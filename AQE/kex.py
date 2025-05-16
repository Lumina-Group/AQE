import time
import base64
import asyncio
import os
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .errors import AuthenticationError, HandshakeTimeoutError, RateLimitExceededError, ReplayAttackError,ConfigurationError, SignatureVerificationError,CryptoOperationError
from .logger import SecurityEvent, EnhancedSecurityLogger, SecurityMetrics, setup_logging
from .configuration import ConfigurationManager
from oqs import KeyEncapsulation, Signature # Assuming oqs-python is installed

class QuantumSafeKEX:

    def __init__(
        self,
        config_manager: Optional[ConfigurationManager] = None,
        identity_key: Optional[x25519.X25519PrivateKey] = None,
        kyber_keypair: Optional[Tuple[bytes, bytes]] = None,
        sig_keypair: Optional[Tuple[bytes, bytes]] = None,
        logger: Optional[EnhancedSecurityLogger] = None,
        is_initiator: bool = True
    ):
        """
        量子耐性のある鍵交換プロトコルの実装クラスを初期化します。
        ハイブリッド方式（古典的な楕円曲線と格子ベースの暗号）を使用します。

        Args:
            config_manager: 設定を管理するConfigurationManagerのインスタンス。指定されていない場合は新しく生成されます。
            identity_key: 既存のX25519秘密鍵。指定されていない場合は新しく生成されます。
            kyber_keypair: 既存のKyber鍵ペア (public_key_bytes, secret_key_bytes)。
                           指定された場合、この鍵ペアの正当性（公開鍵と秘密鍵が対応していること）は呼び出し元の責任となります。
            sig_keypair: 既存の署名鍵ペア (public_key_bytes, secret_key_bytes)。
                         指定された場合、この鍵ペアの正当性は呼び出し元の責任となります。
            logger: 拡張されたセキュリティロガーのインスタンス。指定されていない場合は新しく生成されます。
            is_initiator: 鍵交換の初期化者かどうかを示す値。
        """
        self.PROTOCOl_VER = b"HybridKEXv1.0" # HKDF情報用のプロトコルバージョン
        self.config_manager = config_manager or ConfigurationManager()
        self.metrics = SecurityMetrics() # SecurityMetricsが定義されていると仮定
        self.enhanced_logger = logger or EnhancedSecurityLogger(setup_logging(), self.metrics)
        self.logger = self.enhanced_logger.logger

        self.max_failed_attempts = self.config_manager.getint("security", "MAX_FAILED_ATTEMPTS", fallback=5)
        self.rate_limit_window = self.config_manager.getint("security", "RATE_LIMIT_WINDOW", fallback=300)
        self.is_initiator = is_initiator
        self.failed_attempts = 0
        self.last_failed_time = 0.0 # float型で初期化

        # 古典的なKEX部分 (X25519)
        self.ec_priv = identity_key or x25519.X25519PrivateKey.generate()
        self.ec_public_raw = self.ec_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # ポスト量子KEM (例: Kyber)
        self.kex_alg_name = self.config_manager.get("kex", "KEX_ALG", fallback="Kyber768")
        if kyber_keypair and len(kyber_keypair) == 2:
            provided_pk, provided_sk = kyber_keypair
            self.kyber_public_key = provided_pk
            # 提供された秘密鍵でKEMオブジェクトを初期化 (デカプセル化用)
            try:
                self.kem = KeyEncapsulation(self.kex_alg_name, secret_key=provided_sk)
            except Exception as e: # oqs-python could raise various errors for invalid SK or alg
                self.logger.error(f"Failed to initialize KEM {self.kex_alg_name} with provided secret key: {e}", exc_info=True)
                raise ConfigurationError(f"Invalid KEM algorithm or secret key provided for {self.kex_alg_name}: {e}") from e

            # 重要: 提供された公開鍵が秘密鍵に対応していることを信頼しています。
            # oqs-pythonライブラリは、このようにKEMオブジェクトを初期化した後に、
            # 指定された秘密鍵から公開鍵を再導出して検証する簡単な方法を提供していません。
            # 提供された鍵ペアの完全性を保証するのは、このクラスの利用者の責任です。
            self.logger.info(f"Initialized KEM {self.kex_alg_name} with a provided keypair. "
                             "The provided public key will be used for AWA. "
                             "The provided secret key is configured for decapsulation operations.")
            if not self.kem.secret_key: # 秘密鍵が正しく設定されたか確認 (oqs-pythonの振る舞いに依存)
                 self.logger.error(f"Failed to set secret key for KEM {self.kex_alg_name} from provided keypair. This is unexpected.")
                 raise ConfigurationError(f"Failed to initialize KEM {self.kex_alg_name} with the provided secret key.")
        else:
            # 新しい鍵ペアを生成
            try:
                self.kem = KeyEncapsulation(self.kex_alg_name)
                self.kyber_public_key = self.kem.generate_keypair()
            except Exception as e: # e.g., oqs.MechanismNotSupportedError
                self.logger.error(f"Failed to generate KEM keypair for {self.kex_alg_name}: {e}", exc_info=True)
                raise ConfigurationError(f"Failed to generate KEM keypair for {self.kex_alg_name}: {e}") from e
            # generate_keypair()後、self.kem.public_key と self.kem.secret_key が設定されます。
            # self.kyber_public_key は通知する公開鍵です。
            # self.kem (その中の self.kem.secret_key) はデカプセル化に使用されます。
            #self.logger.info(f"Generated new KEM keypair for {self.kex_alg_name}.")

        # ポスト量子署名 (例: Dilithium)
        self.sig_alg_name = self.config_manager.get("signature", "SIG_ALG", fallback="Dilithium3")
        if sig_keypair and len(sig_keypair) == 2:
            provided_pk, provided_sk = sig_keypair
            self.sig_public_key = provided_pk
            # 提供された秘密鍵で署名オブジェクトを初期化 (署名用)
            try:
                self.signer = Signature(self.sig_alg_name, secret_key=provided_sk)
            except Exception as e:
                self.logger.error(f"Failed to initialize Signature {self.sig_alg_name} with provided secret key: {e}", exc_info=True)
                raise ConfigurationError(f"Invalid Signature algorithm or secret key provided for {self.sig_alg_name}: {e}") from e
            
            # 重要: 提供された公開鍵が秘密鍵に対応していることを信頼しています。
            self.logger.info(f"Initialized Signature {self.sig_alg_name} with a provided keypair. "
                             "The provided public key will be used for AWA. "
                             "The provided secret key is configured for signing operations.")
            if not self.signer.secret_key:
                 self.logger.error(f"Failed to set secret key for Signature {self.sig_alg_name} from provided keypair.")
                 raise ConfigurationError(f"Failed to initialize Signature {self.sig_alg_name} with the provided secret key.")
        else:
            # 新しい鍵ペアを生成
            try:
                self.signer = Signature(self.sig_alg_name)
                self.sig_public_key = self.signer.generate_keypair()
            except Exception as e: # e.g., oqs.MechanismNotSupportedError
                self.logger.error(f"Failed to generate Signature keypair for {self.sig_alg_name}: {e}", exc_info=True)
                raise ConfigurationError(f"Failed to generate Signature keypair for {self.sig_alg_name}: {e}") from e
            # generate_keypair()後、self.signer.public_key と self.signer.secret_key が設定されます。
            #self.logger.info(f"Generated new Signature keypair for {self.sig_alg_name}.")

        self.awa = self._generate_awa() # 認証とホワイトリストアサーション

        #self.logger.info(f"QuantumSafeKEX initialized. KEX Alg: {self.kem.details['name']}, SIG Alg: {self.signer.details['name']}, Initiator: {self.is_initiator}")

    def _generate_awa(self) -> bytes:
        """
        AWA (Authentication and Whitelisting Assertion) を生成します。
        AWAは認証と許可リストに基づいたアサーションであり、以下の要素を含みます：
        - タイムスタンプ：AWAの生成時刻（Unixタイムスタンプ形式）
        - EC公開鍵：X25519公開鍵 (Raw)
        - PQ公開鍵：Kyber公開鍵 (KEM public key)
        - 署名公開鍵: 署名アルゴリズムの公開鍵
        - Nonce: 乱数
        - 署名：署名秘密鍵で生成された署名（タイムスタンプ + Nonce + EC公開鍵 + PQ公開鍵 + 署名公開鍵 を署名対象とする）
        Returns:
            bytes: 生成されたAWAバイト列
        Raises:
            ConfigurationError: AWAペイロードの署名に失敗した場合 (通常は設定や鍵の問題)
        """
        timestamp = int(time.time()).to_bytes(8, 'big')
        nonce = os.urandom(16) # AWAの鮮度のための暗号学的ノンス

        # 署名用ペイロード
        sig_data_payload = timestamp + nonce + self.ec_public_raw + self.kyber_public_key + self.sig_public_key

        try:
            signature = self.signer.sign(sig_data_payload)
        except Exception as e:
            self.logger.critical(f"Failed to sign AWA payload with {self.sig_alg_name}: {e}", exc_info=True)
            # これは初期化または鍵生成中の致命的な失敗です。
            raise ConfigurationError(f"Failed to sign AWA payload using {self.sig_alg_name}: {e}") from e

        self.logger.debug(f"AWA generated successfully. Payload length: {len(sig_data_payload)}, Signature length: {len(signature)}")
        return sig_data_payload + signature # ペイロードと署名を連結

    async def verify_peer_awa(self, peer_awa: bytes) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
        """
        ピアから受け取ったAWAを検証します。
        タイムスタンプの妥当性（リプレイ攻撃対策）と署名を検証します。

        Args:
            peer_awa: ピアから受け取ったAWAバイト列

        Returns:
            Tuple[bytes, bytes, bytes, bytes, bytes]: 検証が成功した場合、(ピアのEC公開鍵, ピアのPQ公開鍵, ピアの署名公開鍵, ピアのAWAタイムスタンプ, ピアのAWA乱数) のタプル

        Raises:
            AuthenticationError: 認証エラー（データ不完全、フォーマット不正など）が発生した場合
            ReplayAttackError: リプレイ攻撃（古いタイムスタンプ）が検出された場合
            SignatureVerificationError: 署名検証に失敗した場合
            RateLimitExceededError: レート制限を超えた場合
            ConfigurationError: 鍵長などの設定情報取得に失敗した場合
        """
        current_time_float = time.time()
        current_time_int = int(current_time_float)

        if self.failed_attempts >= self.max_failed_attempts:
            if current_time_float - self.last_failed_time < self.rate_limit_window:
                await self._log_security_event(SecurityEvent(
                    "CRITICAL", "RATE_LIMIT_EXCEEDED",
                    f"Max failed AWA verification attempts ({self.max_failed_attempts}) reached. Blocking for {self.rate_limit_window}s.",
                    current_time_float, {}))
                raise RateLimitExceededError(f"Too many failed authentication attempts. Try again in {self.rate_limit_window - (current_time_float - self.last_failed_time):.0f} seconds.")
            else: # ウィンドウが経過していればカウンターをリセット
                self.failed_attempts = 0
                # self.last_failed_time は失敗時に更新されるので、ここではリセット不要

        try:
            # KEM公開鍵の長さはピアのKEMアルゴリズムに依存します。ここでは、ピアが同じKEMアルゴリズムを使用すると仮定します。
            # これは通常、プロトコルレベルで合意されるか、固定されます。
            # ここではローカルのkemインスタンスから長さを取得します。
            pq_pub_len_details = KeyEncapsulation(self.kex_alg_name).details # 一時的なインスタンスで詳細取得
            pq_pub_len = pq_pub_len_details.get("length_public_key")


            # 署名公開鍵と署名の長さはピアの署名アルゴリズムに依存します。
            # 重要: ここでは、ピアがこのインスタンスと同じ署名アルゴリズム(self.sig_alg_name)を使用すると仮定しています。
            # より堅牢なプロトコルでは、AWAに署名アルゴリズム識別子を含めることがあります。
            sig_details_for_peer = Signature(self.sig_alg_name).details # 一時的なインスタンスで詳細取得
            sig_pub_len = sig_details_for_peer.get("length_public_key")
            sig_len = sig_details_for_peer.get("length_signature")

            ec_pub_len = 32 # X25519公開鍵サイズ (固定)

            if not all([pq_pub_len, sig_pub_len, sig_len]):
                self.logger.error(f"Could not determine key/signature lengths from OQS details for KEM {self.kex_alg_name} or SIG {self.sig_alg_name}. Check algorithm configuration.")
                raise ConfigurationError("Could not determine key/signature lengths from OQS algorithm details.")

            # AWA構造: timestamp(8) + nonce(16) + ec_pub(32) + pq_pub(var) + sig_pub(var) + signature(var)
            header_len = 8 + 16 + ec_pub_len
            payload_len = header_len + pq_pub_len + sig_pub_len
            expected_total_len = payload_len + sig_len

            if len(peer_awa) != expected_total_len:
                msg = f"Peer AWA length mismatch. Expected {expected_total_len} (based on KEM: {self.kex_alg_name}, SIG: {self.sig_alg_name}), got {len(peer_awa)}."
                await self._log_security_event(SecurityEvent("MEDIUM", "VERIFICATION_FAILED", msg, current_time_float, {}))
                raise AuthenticationError(msg)

            offset = 0
            timestamp_bytes = peer_awa[offset:offset+8]; offset += 8
            nonce_bytes = peer_awa[offset:offset+16]; offset += 16
            peer_ec_pub = peer_awa[offset:offset+ec_pub_len]; offset += ec_pub_len
            peer_pq_pub = peer_awa[offset:offset+pq_pub_len]; offset += pq_pub_len
            peer_sig_pub = peer_awa[offset:offset+sig_pub_len]; offset += sig_pub_len
            signature = peer_awa[offset:]

            if len(signature) != sig_len: # 追加の整合性チェック
                msg = f"Peer AWA signature length component mismatch. Expected {sig_len}, got {len(signature)}."
                await self._log_security_event(SecurityEvent("MEDIUM", "VERIFICATION_FAILED", msg, current_time_float, {}))
                raise AuthenticationError(msg)


            # 1. タイムスタンプ検証 (リプレイ防止)
            timestamp_val = int.from_bytes(timestamp_bytes, 'big')
            timestamp_window = self.config_manager.getint("security", "TIMESTAMP_WINDOW", fallback=60) # 秒

            if abs(current_time_int - timestamp_val) > timestamp_window:
                msg = f"AWA Timestamp {timestamp_val} outside allowed window (current: {current_time_int}, window: ±{timestamp_window}s)."
                await self._log_security_event(SecurityEvent("MEDIUM", "REPLAY_ATTEMPT", msg, current_time_float, {}))
                raise ReplayAttackError(msg)

            # 2. 署名検証
            signed_data = timestamp_bytes + nonce_bytes + peer_ec_pub + peer_pq_pub + peer_sig_pub

            # ピアの署名アルゴリズムがローカル設定と同じ(self.sig_alg_name)であると仮定して検証用オブジェクトを作成します。
            # この仮定が正しくない場合、検証は失敗します。
            self.logger.debug(f"Attempting to verify peer AWA signature using algorithm {self.sig_alg_name} "
                              f"(derived from local configuration, assuming peer uses the same). "
                              f"Peer's KEM algorithm for key length parsing is assumed to be {self.kex_alg_name}.")
            try:
                # 検証用に一時的な署名オブジェクトを作成。秘密鍵は不要。
                peer_verifier = Signature(self.sig_alg_name)
                is_valid = peer_verifier.verify(signed_data, signature, peer_sig_pub)
            except Exception as e: # 基盤となる暗号ライブラリからのエラーをキャッチ (例: oqs.Error, ValueError)
                msg = f"Error during AWA signature verification with {self.sig_alg_name}: {str(e)}"
                await self._log_security_event(SecurityEvent("HIGH", "SIGNATURE_VERIFICATION_ERROR", msg, current_time_float, {}))
                raise SignatureVerificationError(f"Cryptographic error during signature verification using {self.sig_alg_name}: {e}") from e

            if not is_valid:
                msg = f"Peer AWA signature verification failed (algorithm assumed: {self.sig_alg_name})."
                await self._log_security_event(SecurityEvent("HIGH", "SIGNATURE_VERIFICATION_FAILED", msg, current_time_float, {}))
                raise SignatureVerificationError(msg)

            self.logger.info("Peer AWA verification successful.")
            self.failed_attempts = 0 # 成功時にリセット
            return peer_ec_pub, peer_pq_pub, peer_sig_pub, timestamp_bytes, nonce_bytes

        except (AuthenticationError, ReplayAttackError, SignatureVerificationError, ConfigurationError, RateLimitExceededError) as e:
            self.failed_attempts += 1
            self.last_failed_time = current_time_float
            self.logger.warning(f"Peer AWA verification failed: {type(e).__name__} - {str(e)}")
            raise
        except Exception as e:
            self.failed_attempts += 1
            self.last_failed_time = current_time_float
            self.logger.error(f"Unexpected error during AWA verification: {str(e)}", exc_info=True)
            await self._log_security_event(SecurityEvent("HIGH", "VERIFICATION_UNEXPECTED_ERROR", f"Unexpected: {str(e)}", current_time_float, {}))
            raise AuthenticationError(f"Unexpected error during AWA verification: {str(e)}") from e


    async def exchange(self, peer_awa_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        (イニシエータロール) ピアとの鍵交換を実行します。ピアのAWAを受け取り、検証後、自身のKEM暗号文を生成します。

        Args:
            peer_awa_bytes: ピア(レスポンダ)から受け取ったAWAデータ

        Returns:
            Tuple[bytes, bytes]: (共有秘密鍵, 送信するKEM暗号文)のタプル

        Raises:
            verify_peer_awaからの各種エラー, HandshakeTimeoutError, CryptoOperationError (暗号化失敗時)
        """
        if not self.is_initiator:
            msg = "Exchange method called by Responder. Responder should use 'decap'."
            await self._log_security_event(SecurityEvent("CRITICAL", "KEX_LOGIC_ERROR", msg, time.time(), {}))
            # プログラミングエラーなのでValueErrorが適切
            raise ValueError(msg)

        try:
            async with asyncio.timeout(self.config_manager.getint("timeouts", "HANDSHAKE_TIMEOUT", fallback=30)):
                # 1. ピアのAWAを検証
                peer_ec_pub_raw, peer_pq_pub, peer_sig_pub, _, _ = await self.verify_peer_awa(peer_awa_bytes)

                # 2. ECDH共有秘密
                try:
                    peer_ec_public_key = x25519.X25519PublicKey.from_public_bytes(peer_ec_pub_raw)
                    ec_shared_secret = await asyncio.get_event_loop().run_in_executor(
                        None, self.ec_priv.exchange, peer_ec_public_key
                    )
                except Exception as e: # cryptographyライブラリは様々な例外を出す可能性あり
                    msg = f"ECDH key exchange failed: {str(e)}"
                    await self._log_security_event(SecurityEvent("HIGH", "KEX_ERROR", msg, time.time(), {"detail": "ECDH phase"}))
                    raise CryptoOperationError(msg) from e

                # 3. PQC KEMカプセル化 (イニシエータがレスポンダのPQ公開鍵に対してカプセル化)
                # カプセル化には一時的なKEMオブジェクトを使用 (self.kemは自身の秘密鍵で初期化されている場合があるため)
                try:
                    temp_encapsulator = KeyEncapsulation(self.kex_alg_name) # ピアの公開鍵に対してカプセル化
                    kem_ciphertext, pq_shared_secret = temp_encapsulator.encap_secret(peer_pq_pub)
                except Exception as e: # oqs.Errorなど
                    msg = f"KEM encapsulation ({self.kex_alg_name}) failed: {str(e)}"
                    await self._log_security_event(SecurityEvent("HIGH", "KEX_ERROR", msg, time.time(), {"detail": "KEM encapsulation"}))
                    raise CryptoOperationError(msg) from e

                # 4. HKDFを使用して秘密を結合
                transcript = self._build_transcript(
                    self.ec_public_raw, self.kyber_public_key, self.sig_public_key, # 自身の鍵
                    peer_ec_pub_raw, peer_pq_pub, peer_sig_pub                      # ピアの鍵
                )
                salt = self._generate_salt(transcript)

                try:
                    key_size = self.config_manager.getint("kex", "DERIVED_KEY_SIZE", fallback=32)
                    hkdf = HKDF(
                        algorithm=hashes.SHA512(),
                        length=key_size,
                        salt=salt,
                        info=self.PROTOCOl_VER
                    )
                    final_shared_secret = hkdf.derive(ec_shared_secret + pq_shared_secret)
                except Exception as e:
                    msg = f"Final key derivation (HKDF) failed: {str(e)}"
                    await self._log_security_event(SecurityEvent("HIGH", "KEX_ERROR", msg, time.time(), {"detail": "HKDF derivation"}))
                    raise CryptoOperationError(msg) from e

                await self._log_security_event(SecurityEvent("LOW", "KEX_SUCCESS", "Initiator key exchange successful", time.time(), {}))
                self.logger.info("Initiator key exchange successful.")
                return final_shared_secret, kem_ciphertext

        except asyncio.TimeoutError:
            timeout_val = self.config_manager.getint('timeouts', 'HANDSHAKE_TIMEOUT', fallback=30)
            msg = f"Handshake timed out after {timeout_val} seconds during initiator exchange."
            await self._log_security_event(SecurityEvent("HIGH", "HANDSHAKE_TIMEOUT", msg, time.time(), {}))
            raise HandshakeTimeoutError(msg) from None
        except (AuthenticationError, SignatureVerificationError, ReplayAttackError, RateLimitExceededError, CryptoOperationError) as e:
            # これらはverify_peer_awaまたはこのメソッド内の暗号操作によってログ記録済みの可能性あり
            self.logger.warning(f"Key exchange failed for initiator: {type(e).__name__} - {str(e)}")
            raise
        except Exception as e:
            msg = f"Unexpected error during initiator key exchange: {str(e)}"
            await self._log_security_event(SecurityEvent("CRITICAL", "KEX_UNEXPECTED_ERROR", msg, time.time(), {}))
            self.logger.exception(msg)
            raise CryptoOperationError(f"Unexpected critical error in KEX: {e}") from e


    async def decap(self, kem_ciphertext: bytes, peer_awa_bytes: bytes) -> bytes:
        """
        (レスポンダロール) 受け取ったKEM暗号文とピアのAWAを使用して共有秘密鍵を復元します。

        Args:
            kem_ciphertext: イニシエータから受け取ったKEM暗号文
            peer_awa_bytes: イニシエータから受け取ったAWAデータ

        Returns:
            bytes: 復元された最終共有秘密鍵

        Raises:
            verify_peer_awaからの各種エラー, HandshakeTimeoutError, CryptoOperationError (KEMの問題時など)
        """
        if self.is_initiator:
            msg = "Decap method called by Initiator. Initiator should use 'exchange'."
            await self._log_security_event(SecurityEvent("CRITICAL", "KEX_LOGIC_ERROR", msg, time.time(), {}))
            raise ValueError(msg)

        try:
            async with asyncio.timeout(self.config_manager.getint("timeouts", "HANDSHAKE_TIMEOUT", fallback=30)):
                # 1. ピアのAWAを検証
                peer_ec_pub_raw, peer_pq_pub, peer_sig_pub, _, _ = await self.verify_peer_awa(peer_awa_bytes)

                # 2. ECDH共有秘密
                try:
                    peer_ec_public_key = x25519.X25519PublicKey.from_public_bytes(peer_ec_pub_raw)
                    ec_shared_secret = await asyncio.get_event_loop().run_in_executor(
                        None, self.ec_priv.exchange, peer_ec_public_key
                    )
                except Exception as e:
                    msg = f"ECDH key exchange failed during decap: {str(e)}"
                    await self._log_security_event(SecurityEvent("HIGH", "KEX_ERROR", msg, time.time(), {"detail": "ECDH phase decap"}))
                    raise CryptoOperationError(msg) from e

                # 3. PQC KEMデカプセル化 (レスポンダが自身のPQ秘密鍵を使用してデカプセル化)
                # self.kem は自身の秘密鍵で初期化されているはずです。
                if not self.kem.secret_key:
                    # これは設定ミスを示します。__init__で秘密鍵が設定されるべきでした。
                    self.logger.critical(f"KEM object for {self.kex_alg_name} not initialized with a secret key for decapsulation.")
                    raise ConfigurationError(f"KEM {self.kex_alg_name} not ready for decapsulation (no secret key).")
                try:
                    pq_shared_secret = self.kem.decap_secret(kem_ciphertext)
                except Exception as e: # oqs.Errorなど、不正な暗号文や内部エラー
                    msg = f"KEM decapsulation ({self.kem.details['name']}) failed: {str(e)}"
                    await self._log_security_event(SecurityEvent("HIGH", "DECAP_ERROR", msg, time.time(), {}))
                    raise CryptoOperationError(msg) from e

                # 4. HKDFを使用して秘密を結合
                transcript = self._build_transcript(
                    peer_ec_pub_raw, peer_pq_pub, peer_sig_pub,                      # ピアの (イニシエータの) 鍵
                    self.ec_public_raw, self.kyber_public_key, self.sig_public_key   # 自身の (レスポンダの) 鍵
                )
                salt = self._generate_salt(transcript)

                try:
                    key_size = self.config_manager.getint("kex", "DERIVED_KEY_SIZE", fallback=32)
                    hkdf = HKDF(
                        algorithm=hashes.SHA512(),
                        length=key_size,
                        salt=salt,
                        info=self.PROTOCOl_VER
                    )
                    final_shared_secret = hkdf.derive(ec_shared_secret + pq_shared_secret)
                except Exception as e:
                    msg = f"Final key derivation (HKDF) failed during decap: {str(e)}"
                    await self._log_security_event(SecurityEvent("HIGH", "KEX_ERROR", msg, time.time(), {"detail": "HKDF derivation decap"}))
                    raise CryptoOperationError(msg) from e

                await self._log_security_event(SecurityEvent("LOW", "DECAP_SUCCESS", "Responder key decapsulation and derivation successful", time.time(), {}))
                self.logger.info("Responder key decapsulation and derivation successful.")
                return final_shared_secret

        except asyncio.TimeoutError:
            timeout_val = self.config_manager.getint('timeouts', 'HANDSHAKE_TIMEOUT', fallback=30)
            msg = f"Handshake timed out after {timeout_val} seconds during responder decap."
            await self._log_security_event(SecurityEvent("HIGH", "HANDSHAKE_TIMEOUT", msg, time.time(), {}))
            raise HandshakeTimeoutError(msg) from None
        except (AuthenticationError, SignatureVerificationError, ReplayAttackError, RateLimitExceededError, CryptoOperationError, ConfigurationError) as e:
            self.logger.warning(f"Key decapsulation failed for responder: {type(e).__name__} - {str(e)}")
            raise
        except Exception as e:
            msg = f"Unexpected error during responder key decapsulation: {str(e)}"
            await self._log_security_event(SecurityEvent("CRITICAL", "DECAP_UNEXPECTED_ERROR", msg, time.time(), {}))
            self.logger.exception(msg)
            raise CryptoOperationError(f"Unexpected critical error in KEX decap: {e}") from e

    async def _log_security_event(self, event: SecurityEvent):
        """
        セキュリティイベントをログに記録するヘルパーメソッドです。
        EnhancedSecurityLoggerのメソッドを呼び出します。
        """
        await self.enhanced_logger.log_security_event(event)


    def _build_transcript(self, initiator_ec_pub: bytes, initiator_pq_pub: bytes, initiator_sig_pub: bytes,
                          responder_ec_pub: bytes, responder_pq_pub: bytes, responder_sig_pub: bytes) -> bytes:
        """
        KDFで使用するトランスクリプトを構築します。
        鍵交換に関与したすべての公開鍵情報を含み、役割（イニシエータ/レスポンダ）に基づいて順序付けられます。
        これにより、両当事者が同じトランスクリプトを計算できるようになります。
        """
        # 鍵が何らかの形で同一であるか、互いの部分文字列である場合の曖昧さを防ぐためのラベル
        return (
            b"hybrid-kex-transcript-v1.0" + # トランスクリプト用のプロトコルバージョン
            b"|initiator_ec_pub:" + initiator_ec_pub +
            b"|initiator_pq_pub:" + initiator_pq_pub +
            b"|initiator_sig_pub:" + initiator_sig_pub +
            b"|responder_ec_pub:" + responder_ec_pub +
            b"|responder_pq_pub:" + responder_pq_pub +
            b"|responder_sig_pub:" + responder_sig_pub
        )

    def _generate_salt(self, transcript: bytes) -> bytes:
        """トランスクリプトからHKDF用のソルトを生成"""
        # HKDFのハッシュと一致するSHA512をソルト導出に使用
        hasher = hashes.Hash(hashes.SHA512())
        hasher.update(transcript)
        return hasher.finalize()
        


    def export_keys(self) -> Dict[str, Optional[str]]:
        """
        現在の鍵の状態をエクスポートします。秘密鍵と公開鍵、AWAが含まれます。
        秘密鍵はBase64エンコードされた文字列としてエクスポートされます。

        エクスポートされる情報:
        - EC秘密鍵 (Raw)
        - EC公開鍵 (Raw)
        - KEM公開鍵 (例: Kyber)
        - KEM秘密鍵 (例: Kyber)
        - 署名公開鍵 (例: Dilithium)
        - 署名秘密鍵 (例: Dilithium)
        - AWA (生成された認証アサーション)

        Returns:
            Dict[str, Optional[str]]: エクスポートされた鍵データの辞書（Base64エンコード文字列、秘密鍵がない場合はNone）
        """
        exported_data: Dict[str, Optional[str]] = {}
        try:
            # EC Keys
            ec_private_bytes = self.ec_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption() # Should be NoEncryption for raw bytes
            )
            exported_data['ec_private_key_raw'] = base64.b64encode(ec_private_bytes).decode('utf-8')
            exported_data['ec_public_key_raw'] = base64.b64encode(self.ec_public_raw).decode('utf-8')

            # KEM Keys (e.g., Kyber)
            exported_data['kem_public_key'] = base64.b64encode(self.kyber_public_key).decode('utf-8')
            kem_secret_bytes = self.kem.export_secret_key()
            if kem_secret_bytes:
                exported_data['kem_secret_key'] = base64.b64encode(kem_secret_bytes).decode('utf-8')
            else:
                exported_data['kem_secret_key'] = None
                self.logger.warning("KEM secret key could not be exported (it might not be available in the KEM object).")
            
            # Signature Keys (e.g., Dilithium)
            exported_data['sig_public_key'] = base64.b64encode(self.sig_public_key).decode('utf-8')
            signer_secret_bytes = self.signer.export_secret_key()
            if signer_secret_bytes:
                exported_data['sig_secret_key'] = base64.b64encode(signer_secret_bytes).decode('utf-8')
            else:
                exported_data['sig_secret_key'] = None
                self.logger.warning("Signer secret key could not be exported (it might not be available in the Signer object).")

            # AWA
            exported_data['awa'] = base64.b64encode(self.awa).decode('utf-8')
            
            exported_data['kex_algorithm'] = self.kem.details['name']
            exported_data['sig_algorithm'] = self.signer.details['name']
            exported_data['is_initiator'] = str(self.is_initiator) # Store as string for simple dict

            self.logger.info(f"Keys exported successfully for KEX Alg: {exported_data['kex_algorithm']}, SIG Alg: {exported_data['sig_algorithm']}")
            return exported_data

        except Exception as e:
            self.logger.error(f"Failed to export keys: {str(e)}", exc_info=True)
            # 部分的に入力された辞書を返すか、エラーを発生させます
            # # 収集された内容を返しますが、ログには失敗が記録されます。
            raise ConfigurationError(f"Key export failed: {e}") from e

