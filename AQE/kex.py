import time
import base64
import asyncio
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .errors import AuthenticationError, HandshakeTimeoutError, RateLimitExceededError, ReplayAttackError, SignatureVerificationError
from .logger import SecurityEvent, EnhancedSecurityLogger, SecurityMetrics, setup_logging
from .configuration import ConfigurationManager
from oqs import KeyEncapsulation, Signature

class QuantumSafeKEX:
    def __init__(
        self,
        identity_key=None,
        kyber_keypair=None,
        ec_priv_public_raw=None,
        awa=None,
        sig_keypair=None,
        config_manager: ConfigurationManager = None,
        logger: EnhancedSecurityLogger = None,
        is_initiator: bool = True
    ):
        """
        量子耐性のある鍵交換プロトコルの実装クラスを初期化します。
        ハイブリッド方式（古典的な楕円曲線と格子ベースの暗号）を使用します。
        AWAのローテーション機能は削除されています。

        Args:
            identity_key: 既存のX25519秘密鍵。指定されていない場合は新しく生成されます。
            kyber_keypair: 既存のKyber鍵ペア。指定されていない場合は新しく生成されます。
            ec_priv_public_raw: 楕円曲線公開鍵のRaw形式のバイト列。指定されていない場合は計算されます。
            awa: 既存の認証データ（Authentication and Whitelisting Assertion）。指定されていない場合は生成されます。
            sig_keypair: 署名鍵ペア。指定されていない場合は新しく生成されます。
            config_manager: 設定を管理するConfigurationManagerのインスタンス。指定されていない場合は新しく生成されます。
            logger: 拡張されたセキュリティロガーのインスタンス。指定されていない場合は新しく生成されます。
            is_initiator: 鍵交換の初期化者かどうかを示す値。

        Returns:
            なし
        """
        self.config_manager = config_manager or ConfigurationManager()
        self.metrics = SecurityMetrics()
        self.enhanced_logger = logger or EnhancedSecurityLogger(setup_logging(), self.metrics)
        self.logger = self.enhanced_logger.logger
        self.max_failed_attempts = self.config_manager.getint("security", "MAX_FAILED_ATTEMPTS", fallback=5)
        self.rate_limit_window = self.config_manager.getint("security", "RATE_LIMIT_WINDOW", fallback=300)
        self.is_initiator = is_initiator
        self.failed_attempts = 0
        self.last_failed_time = 0

        self.ec_priv = identity_key or x25519.X25519PrivateKey.generate()
        self.kyber = KeyEncapsulation(self.config_manager.get("kex", "KEX_ALG", fallback="Kyber768"), None)
        self.signer = Signature(self.config_manager.get("signature", "SIG_ALG", fallback="Dilithium3"), None)
        self.public_key = kyber_keypair or self.kyber.generate_keypair()
        self.sig_keypair = sig_keypair or self.signer.generate_keypair()
        self.ec_priv_public_raw = ec_priv_public_raw or self.ec_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.awa = awa or self._generate_awa()

        self.logger.info(f"QuantumSafeKEX initialized. KEX Alg: {self.kyber.details['name']}, SIG Alg: {self.signer.details['name']}, Initiator: {self.is_initiator}")

    def _generate_awa(self) -> bytes:
        """
        AWA (Authentication and Whitelisting Assertion) を生成します。
        AWAは認証と許可リストに基づいたアサーションであり、以下の要素を含みます：
        - タイムスタンプ：AWAの生成時刻（Unixタイムスタンプ形式）
        - EC公開鍵：X25519公開鍵 (Raw)
        - PQ公開鍵：Kyber公開鍵
        - 署名公開鍵: 署名アルゴリズムの公開鍵
        - 署名：署名秘密鍵で生成された署名（タイムスタンプ + EC公開鍵 + PQ公開鍵 + 署名公開鍵 を署名対象とする）
        Returns:
            bytes: 生成されたAWAバイト列
        """
        timestamp = int(time.time()).to_bytes(8, 'big')
        ec_pub = self.ec_priv_public_raw
        pq_pub = self.public_key
        sig_pub = self.sig_keypair

        sig_data_payload = timestamp + ec_pub + pq_pub + sig_pub
        signature = self.signer.sign(sig_data_payload)

        self.logger.info("AWA generated successfully.")
        return sig_data_payload + signature

    async def verify_peer_awa(self, peer_awa: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        ピアから受け取ったAWAを検証します。
        タイムスタンプの妥当性（リプレイ攻撃対策）と署名を検証します。

        Args:
            peer_awa: ピアから受け取ったAWAバイト列

        Returns:
            Tuple[bytes, bytes, bytes, bytes]: 検証が成功した場合、(ピアのEC公開鍵, ピアのPQ公開鍵, ピアの署名公開鍵, ピアのAWAタイムスタンプ) のタプル

        Raises:
            AuthenticationError: 認証エラー（データ不完全、フォーマット不正など）が発生した場合
            ReplayAttackError: リプレイ攻撃（古いタイムスタンプ）が検出された場合
            SignatureVerificationError: 署名検証に失敗した場合
            RateLimitExceededError: レート制限を超えた場合
        """
        current_time = time.time()
        if self.failed_attempts >= self.max_failed_attempts:
            if current_time - self.last_failed_time < self.rate_limit_window:
                await self._log_security_event("CRITICAL", "RATE_LIMIT_EXCEEDED",
                    f"Maximum failed attempts ({self.max_failed_attempts}) reached. Blocking for {self.rate_limit_window} seconds.")
                raise RateLimitExceededError("Too many failed authentication attempts")
            else:
                self.failed_attempts = 0
                self.last_failed_time = 0

        try:
            ec_pub_len = 32
            pq_pub_len = self.kyber.details.get("length_public_key")
            sig_pub_len = self.signer.details.get("length_public_key")
            sig_len = self.signer.details.get("length_signature")

            if not all([pq_pub_len, sig_pub_len, sig_len]):
                 raise ConfigurationError("Could not determine key/signature lengths from OQS details.")

            min_len = 8 + ec_pub_len + pq_pub_len + sig_pub_len + sig_len
            if len(peer_awa) < min_len:
                await self._log_security_event("MEDIUM", "VERIFICATION_FAILED", f"Peer AWA data is incomplete. Expected min {min_len} bytes, got {len(peer_awa)}")
                raise AuthenticationError(f"Peer AWA data is incomplete. Expected min {min_len} bytes.")

            offset = 0
            timestamp_bytes = peer_awa[offset:offset+8]
            offset += 8
            peer_ec_pub = peer_awa[offset:offset+ec_pub_len]
            offset += ec_pub_len
            peer_pq_pub = peer_awa[offset:offset+pq_pub_len]
            offset += pq_pub_len
            peer_sig_pub = peer_awa[offset:offset+sig_pub_len]
            offset += sig_pub_len
            signature = peer_awa[offset:]

            if len(signature) != sig_len:
                 raise AuthenticationError(f"Incorrect signature length in peer AWA. Expected {sig_len}, got {len(signature)}")

            timestamp = int.from_bytes(timestamp_bytes, 'big')
            timestamp_window = self.config_manager.getint("security", "TIMESTAMP_WINDOW", fallback=60)
            if abs(current_time - timestamp) > timestamp_window:
                await self._log_security_event("MEDIUM", "REPLAY_ATTEMPT", f"AWA Timestamp {timestamp} outside allowed window (±{timestamp_window}s from {current_time:.0f})")
                raise ReplayAttackError(f"Timestamp outside allowed window (±{timestamp_window}s).")

            signed_data = timestamp_bytes + peer_ec_pub + peer_pq_pub + peer_sig_pub
            try:
                is_valid = self.signer.verify(signed_data, signature, peer_sig_pub)
            except Exception as e:
                await self._log_security_event("HIGH", "SIGNATURE_VERIFICATION_ERROR", f"Error during signature verification: {str(e)}")
                raise SignatureVerificationError(f"Error during signature verification: {str(e)}") from e

            if not is_valid:
                await self._log_security_event("HIGH", "SIGNATURE_VERIFICATION_FAILED", "Peer AWA signature verification failed.")
                raise SignatureVerificationError("Peer AWA signature verification failed.")

            if len(peer_ec_pub) != ec_pub_len:
                 raise AuthenticationError("Invalid peer EC public key length.")
            if len(peer_pq_pub) != pq_pub_len:
                 raise AuthenticationError("Invalid peer PQ public key length.")
            if len(peer_sig_pub) != sig_pub_len:
                 raise AuthenticationError("Invalid peer Signature public key length.")

            self.logger.info("Peer AWA verification successful.")
            self.failed_attempts = 0
            self.last_failed_time = 0
            return peer_ec_pub, peer_pq_pub, peer_sig_pub, timestamp_bytes

        except Exception as e:
            self.failed_attempts += 1
            self.last_failed_time = time.time()
            if not isinstance(e, (AuthenticationError, ReplayAttackError, SignatureVerificationError, RateLimitExceededError)):
                await self._log_security_event("HIGH", "VERIFICATION_ERROR", f"Unexpected error during AWA verification: {str(e)}")
            self.logger.error(f"Peer AWA verification failed: {str(e)}")
            if isinstance(e, (ReplayAttackError, SignatureVerificationError, RateLimitExceededError)):
                raise
            raise AuthenticationError(f"Peer AWA verification failed: {str(e)}") from e

    async def exchange(self, peer_awa: bytes) -> Tuple[bytes, bytes]:
        """
        ピアとの鍵交換を実行します。 AWAを受け取り、検証してから交換処理に進みます。

        このメソッドは以下の処理を行います：
        1. ピアのAWAを検証 (verify_peer_awa を使用)
        2. 楕円曲線Diffie-Hellman (ECDH) による共有秘密の計算
        3. 格子ベース暗号による共有秘密のカプセル化/デカプセル化 (役割による)
        4. 両方の共有秘密を組み合わせた最終的な共有秘密の導出 (HKDF)

        Args:
            peer_awa: ピアから受け取ったAWAデータ

        Returns:
            Tuple[bytes, bytes]: (共有秘密鍵, 送信する暗号文または空バイト)のタプル
                                Initiatorの場合: (shared_secret, ciphertext)
                                Responderの場合: (shared_secret, b'') ※交換完了のため

        Raises:
            AuthenticationError: ピアAWA検証に失敗した場合
            HandshakeTimeoutError: ハンドシェイクがタイムアウトした場合
            ConfigurationError: 設定に問題がある場合
            その他の例外: 暗号操作中にエラーが発生した場合
        """
        try:
            async with asyncio.timeout(self.config_manager.getint("timeouts", "HANDSHAKE_TIMEOUT", fallback=30)):
                try:
                    peer_ec_pub, peer_pq_pub, peer_sig_pub, _ = await self.verify_peer_awa(peer_awa)
                except AuthenticationError as e:
                    self.logger.warning(f"Peer AWA verification failed during exchange: {e}")
                    raise

                try:
                    ec_peer_key = x25519.X25519PublicKey.from_public_bytes(peer_ec_pub)
                    ec_shared = await asyncio.get_event_loop().run_in_executor(None, self.ec_priv.exchange, ec_peer_key)
                except Exception as e:
                    await self._log_security_event("HIGH", "KEX_ERROR", f"ECDH key exchange failed: {str(e)}")
                    raise ConnectionAbortedError(f"ECDH key exchange failed: {str(e)}") from e

                pq_shared = None
                ciphertext_to_send = b''

                if self.is_initiator:
                    try:
                        ciphertext, pq_shared = self.kyber.encap_secret(peer_pq_pub)
                        ciphertext_to_send = ciphertext
                    except Exception as e:
                         await self._log_security_event("HIGH", "KEX_ERROR", f"Kyber encapsulation failed: {str(e)}")
                         raise ConnectionAbortedError(f"Kyber encapsulation failed: {str(e)}") from e
                else:
                    if not self.is_initiator:
                         await self._log_security_event("CRITICAL", "KEX_LOGIC_ERROR", "Exchange method called by Responder. Should use decap.")
                         raise ValueError("Responder should call decap, not exchange.")

                transcript = self._build_transcript(peer_ec_pub, peer_pq_pub, peer_sig_pub)
                salt = self._generate_salt(transcript)

                try:
                    key_size = self.config_manager.getint("kex", "DERIVED_KEY_SIZE", fallback=32)
                    hkdf = HKDF(algorithm=hashes.SHA512(), length=key_size, salt=salt, info=b'hybrid-kex-v5')
                    shared_secret = hkdf.derive(ec_shared + pq_shared)
                except Exception as e:
                    await self._log_security_event("HIGH", "KEX_ERROR", f"Final key derivation (HKDF) failed: {str(e)}")
                    raise ConnectionAbortedError(f"Final key derivation (HKDF) failed: {str(e)}") from e

                await self._log_security_event("LOW", "KEX_SUCCESS", "Key exchange successful")
                self.logger.info("Key exchange successful.")
                return shared_secret, ciphertext_to_send

        except asyncio.TimeoutError as e:
            await self._log_security_event("HIGH", "HANDSHAKE_TIMEOUT",
                f"Handshake timed out after {self.config_manager.getint('timeouts', 'HANDSHAKE_TIMEOUT', fallback=30)} seconds")
            raise HandshakeTimeoutError("Handshake process timed out") from e
        except AuthenticationError as e:
             self.logger.error(f"Authentication failed during key exchange: {e}")
             raise
        except Exception as e:
            await self._log_security_event("CRITICAL", "KEX_UNEXPECTED_ERROR", f"Unexpected error during key exchange: {str(e)}")
            self.logger.exception(f"Unexpected error during key exchange: {e}")
            raise ConnectionAbortedError(f"Unexpected error during key exchange: {str(e)}") from e

    async def decap(self, ciphertext: bytes, peer_awa: bytes) -> bytes:
        """
        (Responder Role) 受け取った暗号文とピアのAWAを使用して共有秘密鍵を復元します。
        このメソッドは鍵交換のResponder側で呼び出されることを想定しています。

        Args:
            ciphertext: Initiatorから受け取ったKyber暗号文
            peer_awa: Initiatorから受け取ったAWAデータ

        Returns:
            bytes: 復元された共有秘密鍵

        Raises:
            AuthenticationError: ピアAWA検証に失敗した場合
            HandshakeTimeoutError: 処理がタイムアウトした場合 (追加検討)
            ConfigurationError: 設定に問題がある場合
            ValueError: 暗号文の形式が不正な場合
            その他の例外: 暗号操作中にエラーが発生した場合
        """
        if self.is_initiator:
            await self._log_security_event("CRITICAL", "KEX_LOGIC_ERROR", "Decap method called by Initiator. Should use exchange.")
            raise  ValueError("Initiator should call exchange, not decap.")

        try:
            try:
                 peer_ec_pub, peer_pq_pub, peer_sig_pub, _ = await self.verify_peer_awa(peer_awa)
            except AuthenticationError as e:
                 self.logger.warning(f"Peer AWA verification failed during decap: {e}")
                 raise

            try:
                pq_shared = self.kyber.decap_secret(ciphertext)
            except Exception as e:
                await self._log_security_event("HIGH", "DECAP_ERROR", f"Kyber decapsulation failed: {str(e)}")
                raise ValueError(f"Kyber decapsulation failed: {str(e)}") from e

            try:
                ec_peer_key = x25519.X25519PublicKey.from_public_bytes(peer_ec_pub)
                ec_shared = await asyncio.get_event_loop().run_in_executor(None, self.ec_priv.exchange, ec_peer_key)
            except Exception as e:
                 await self._log_security_event("HIGH", "KEX_ERROR", f"ECDH key exchange failed during decap: {str(e)}")
                 raise ConnectionAbortedError(f"ECDH key exchange failed during decap: {str(e)}") from e

            transcript = self._build_transcript(peer_ec_pub, peer_pq_pub, peer_sig_pub)
            salt = self._generate_salt(transcript)

            try:
                key_size = self.config_manager.getint("kex", "DERIVED_KEY_SIZE", fallback=32)
                hkdf = HKDF(algorithm=hashes.SHA512(), length=key_size, salt=salt, info=b'hybrid-kex-v5')
                shared_secret = hkdf.derive(ec_shared + pq_shared)
            except Exception as e:
                await self._log_security_event("HIGH", "KEX_ERROR", f"Final key derivation (HKDF) failed during decap: {str(e)}")
                raise ConnectionAbortedError(f"Final key derivation (HKDF) failed during decap: {str(e)}") from e

            await self._log_security_event("LOW", "DECAP_SUCCESS", "Key decapsulation successful")
            self.logger.info("Key decapsulation successful.")

            return shared_secret

        except AuthenticationError as e:
             self.logger.error(f"Authentication failed during key decapsulation: {e}")
             raise
        except ValueError as e:
             self.logger.error(f"Decapsulation failed: {e}")
             raise
        except Exception as e:
            await self._log_security_event("CRITICAL", "DECAP_UNEXPECTED_ERROR", f"Unexpected error during key decapsulation: {str(e)}")
            self.logger.exception(f"Unexpected error during key decapsulation: {e}")
            raise ConnectionAbortedError(f"Unexpected error during key decapsulation: {str(e)}") from e

    async def _log_security_event(self, severity: str, event_type: str, details: str):
        """
        セキュリティイベントをログに記録するヘルパーメソッドです。

        Args:
            severity: イベントの重大度 ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            event_type: イベントの種類を示す識別子
            details: イベントの詳細説明

        Returns:
            なし
        """
        event = SecurityEvent(
            severity,
            event_type,
            details,
            time.time(),
            {}
        )
        await self.enhanced_logger.log_security_event(event)

    def export_keys(self) -> Dict[str, str]:
        """
        現在の鍵の状態をエクスポートします。
        秘密鍵（EC、Kyber、署名）と公開鍵、AWAが含まれます。
        AWAローテーションが削除されたため、関連する状態変数はエクスポートされません。

        エクスポートされる情報:
        - EC秘密鍵 (Raw)
        - EC公開鍵 (Raw)
        - Kyber公開鍵
        - Kyber秘密鍵
        - 署名公開鍵
        - 署名秘密鍵
        - AWA

        Returns:
            Dict[str, str]: エクスポートされた鍵データの辞書（Base64エンコード）
        """
        try:
            ec_private_bytes = self.ec_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )

            kyber_secret_bytes = self.kyber.export_secret_key() if hasattr(self.kyber, 'export_secret_key') else None
            signer_secret_bytes = self.signer.export_secret_key() if hasattr(self.signer, 'export_secret_key') else None

            if kyber_secret_bytes is None or signer_secret_bytes is None:
                 raise RuntimeError("Failed to export OQS secret keys.")

            return {
                'ec_private': base64.b64encode(ec_private_bytes).decode('utf-8'),
                'ec_public': base64.b64encode(self.ec_priv_public_raw).decode('utf-8'),
                'kyber_public': base64.b64encode(self.public_key).decode('utf-8'),
                'kyber_secret': base64.b64encode(kyber_secret_bytes).decode('utf-8'),
                'sig_public': base64.b64encode(self.sig_keypair).decode('utf-8'),
                'sig_secret': base64.b64encode(signer_secret_bytes).decode('utf-8'),
                'awa': base64.b64encode(self.awa).decode('utf-8'),
                'is_initiator': self.is_initiator
            }
        except Exception as e:
             self.logger.error(f"Failed to export keys: {e}")
             raise RuntimeError(f"Failed to export keys: {e}") from e

    @classmethod
    def load_from_keys(cls, data: Dict[str, Any], config_manager: ConfigurationManager = None, logger: EnhancedSecurityLogger = None) -> 'QuantumSafeKEX':
        """
        エクスポートされた鍵データから新しいQuantumSafeKEXインスタンスを作成します。

        Args:
            data: export_keys()メソッドでエクスポートされた鍵データの辞書
            config_manager: 設定を管理するConfigurationManagerのインスタンス（オプション）
            logger: 拡張ロガーインスタンス（オプション）

        Returns:
            QuantumSafeKEX: 復元されたインスタンス

        Raises:
            ValueError: 必要なキーがデータ辞書に存在しない場合、またはデコード/復元に失敗した場合
            ConfigurationError: 設定ファイルからアルゴリズム名を取得できない場合
        """
        required_keys = ['ec_private', 'ec_public', 'kyber_public', 'kyber_secret', 'sig_public', 'sig_secret', 'awa', 'is_initiator']
        for key in required_keys:
            if key not in data:
                raise ValueError(f"Missing required key in data for loading: {key}")

        try:
            config = config_manager or ConfigurationManager()
            log_enh = logger

            kex_alg = config.get("kex", "KEX_ALG", fallback="Kyber768")
            sig_alg = config.get("signature", "SIG_ALG", fallback="Dilithium3")
            if not kex_alg or not sig_alg:
                 raise ConfigurationError("KEX or Signature algorithm name not found in configuration.")

            ec_priv_bytes = base64.b64decode(data['ec_private'])
            ec_pub_raw = base64.b64decode(data['ec_public'])
            kyber_pub = base64.b64decode(data['kyber_public'])
            kyber_sec = base64.b64decode(data['kyber_secret'])
            sig_pub = base64.b64decode(data['sig_public'])
            sig_sec = base64.b64decode(data['sig_secret'])
            awa_bytes = base64.b64decode(data['awa'])
            is_initiator_flag = data['is_initiator']

            ec_priv = x25519.X25519PrivateKey.from_private_bytes(ec_priv_bytes)

            kyber = KeyEncapsulation(kex_alg, kyber_sec)
            signer = Signature(sig_alg, sig_sec)

            instance = cls(
                identity_key=ec_priv,
                kyber_keypair=kyber_pub,
                ec_priv_public_raw=ec_pub_raw,
                awa=awa_bytes,
                sig_keypair=sig_pub,
                config_manager=config,
                logger=log_enh,
                is_initiator=is_initiator_flag
            )

            instance.kyber = kyber
            instance.signer = signer

            instance.logger.info("QuantumSafeKEX instance successfully loaded from keys.")
            return instance

        except (TypeError, ValueError, base64.binascii.Error) as e:
             temp_logger = logger.logger if logger else setup_logging()
             temp_logger.error(f"Failed to decode or restore keys from data: {e}")
             raise ValueError(f"Failed to decode or restore keys from data: {e}") from e
        except Exception as e:
             temp_logger = logger.logger if logger else setup_logging()
             temp_logger.error(f"An unexpected error occurred during loading from keys: {e}")
             raise RuntimeError(f"An unexpected error occurred during loading from keys: {e}") from e

    def _build_transcript(self, peer_ec_pub, peer_pq_pub, peer_sig_pub):
        """KDFで使用するトランスクリプトを構築"""
        if self.is_initiator:
            ec_a, ec_b = self.ec_priv_public_raw, peer_ec_pub
            pq_a, pq_b = self.public_key, peer_pq_pub
            sig_a, sig_b = self.sig_keypair, peer_sig_pub
        else:
            ec_a, ec_b = peer_ec_pub, self.ec_priv_public_raw
            pq_a, pq_b = peer_pq_pub, self.public_key
            sig_a, sig_b = peer_sig_pub, self.sig_keypair

        return (
            b"hybrid-kex-v5" +
            b"|initiator_ec:" + ec_a +
            b"|responder_ec:" + ec_b +
            b"|initiator_pq:" + pq_a +
            b"|responder_pq:" + pq_b +
            b"|initiator_sig:" + sig_a +
            b"|responder_sig:" + sig_b
        )

    def _generate_salt(self, transcript):
        """トランスクリプトからHKDF用のソルトを生成"""
        hasher = hashes.Hash(hashes.SHA512())
        hasher.update(transcript)
        return hasher.finalize()