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

        # 鍵ローテーションチェック間隔
        self.key_rotation_check_interval = self.config_manager.getint("keys", "KEY_ROTATION_CHECK_INTERVAL", fallback=60)
        self.last_rotation_check = 0
        self.ec_priv = identity_key or x25519.X25519PrivateKey.generate()
        self.kyber = KeyEncapsulation(self.config_manager.get("kex", "KEX_ALG"), None)
        self.signer = Signature(self.config_manager.get("signature", "SIG_ALG"),None )
        self.public_key = kyber_keypair or self.kyber.generate_keypair()
        self.sig_keypair = sig_keypair or self.signer.generate_keypair()
        self.ec_priv_public_raw = ec_priv_public_raw or self.ec_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.awa = awa or self._generate_awa()
        self.awa_timestamp = int(time.time())
        
        # 鍵使用回数の追跡
        self.key_usage_count = 0
        self.max_key_usage = self.config_manager.getint("security", "KEY_ROTATION_INTERVAL", fallback=1000)

    def _generate_awa(self) -> bytes:
        """
        AWA (Authentication and Whitelisting Assertion) を生成します。
        AWAは認証と許可リストに基づいたアサーションであり、以下の要素を含みます：
        - タイムスタンプ：AWAの生成時刻（Unixタイムスタンプ形式）
        - EC公開鍵：ECDSA（Elliptic Curve Digital Signature Algorithm）の公開鍵
        - PQ公開鍵：Kyber（Post-Quantum Key Encapsulation Mechanism）の公開鍵
        - 署名：ECDSAで生成された署名（タイムスタンプ + EC公開鍵 + PQ公開鍵を署名対象とする）
        Returns:
            bytes: 生成されたAWAバイト列
        """
        timestamp = int(time.time()).to_bytes(8, 'big')
        ec_pub = self.ec_priv_public_raw
        pq_pub = self.public_key
        sig_data = timestamp + ec_pub + pq_pub
        signature = self.signer.sign(sig_data)
        self.logger.info("AWA generated successfully.")
        return sig_data + signature

    async def rotate_awa_if_needed(self):
        """
        AWA (Authentication and Whitelisting Assertion) を必要に応じてローテーションします。
        設定された有効期間を超えた場合に新しいAWAを生成します。
        
        セキュリティイベントとしてローテーションをロギングし、鍵使用回数もリセットします。
        
        Returns:
            なし
        """
        current_time = time.time()
        if current_time - self.last_rotation_check < self.key_rotation_check_interval:
            return
        self.last_rotation_check = current_time
        elapsed_time = time.time() - self.awa_timestamp
        if elapsed_time > self.config_manager.getint("kex", "EPHEMERAL_KEY_LIFETIME"):
            self.awa = self._generate_awa()
            self.awa_timestamp = int(time.time())

            event = SecurityEvent(
                "LOW",
                "AWA_ROTATION",
                f"AWA rotated after {elapsed_time:.2f} seconds.",
                time.time(),
                {"elapsed_time": elapsed_time}
            )
            await self.enhanced_logger.log_security_event(event)
            
            # 鍵使用回数をリセット
            self.key_usage_count = 0

    async def verify_peer(self, peer_pub: bytes) -> bool:
        """
        ピアの公開鍵データを検証します。
        
        検証内容:
        1. 公開鍵データの完全性チェック
        2. タイムスタンプの有効性検証（リプレイ攻撃対策）
        3. 公開鍵フォーマットの検証
        Args:
            peer_pub: ピアの公開鍵データ（タイムスタンプ、公開鍵、署名を含む）
            
        Returns:
            bool: 検証が成功した場合はTrue、それ以外はFalse
            
        Raises:
            AuthenticationError: 認証エラーが発生した場合
            ReplayAttackError: リプレイ攻撃が検出された場合
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
                # ウィンドウ時間経過後はリセット
                self.failed_attempts = 0
                self.last_failed_time = 0

        try:
               
            sig_length = self.signer.details.get("length_signature", 64)
            min_len = 8 + 32 + sig_length
            if len(peer_pub) < min_len:
                await self._log_security_event("MEDIUM", "VERIFICATION_FAILED", "Peer public key data is incomplete")
                raise AuthenticationError("Peer public key data is incomplete.")

            timestamp = int.from_bytes(peer_pub[:8], 'big')
            timestamp_window = self.config_manager.getint("security", "TIMESTAMP_WINDOW")
            if abs(time.time() - timestamp) > timestamp_window:
                await self._log_security_event("MEDIUM", "REPLAY_ATTEMPT", "Timestamp outside allowed window")
                raise ReplayAttackError(f"Timestamp outside allowed window (±{timestamp_window}s).")

            if not self._is_valid_public_key_format(peer_pub):
                await self._log_security_event("MEDIUM", "INVALID_KEY_FORMAT", "Invalid peer public key format")
                raise AuthenticationError("Invalid peer public key format.")
            self.logger.info(f"Peer verification successful")
            return True

        except Exception as e:
            self.failed_attempts += 1
            self.last_failed_time = time.time()
            if not isinstance(e, (AuthenticationError, ReplayAttackError, SignatureVerificationError)):
                await self._log_security_event("HIGH", "VERIFICATION_ERROR", f"Unexpected error during verification: {str(e)}")
            self.logger.error(f"Peer verification failed: {str(e)}")
            return False

    def _is_valid_public_key_format(self, public_key_data: bytes) -> bool:
        """
        公開鍵データの形式が有効かどうかを検証します。
        
        検証内容:
        - データの最小長チェック
        - 楕円曲線公開鍵部分のサイズチェック
        
        Args:
            public_key_data: 検証する公開鍵データ
            
        Returns:
            bool: 形式が有効な場合はTrue、それ以外はFalse
        """
        sig_length = self.signer.details.get("length_signature", 64)
        min_len = 8 + 32 + sig_length
        if len(public_key_data) < min_len:
            return False
            
        # 追加の形式検証をここに実装可能
        ec_pub_portion = public_key_data[8:40]
        if len(ec_pub_portion) != 32:
            return False
        
        return True

    async def exchange(self, peer_pub: bytes) -> Tuple[bytes, bytes]:
     """
        ピアとの鍵交換を実行します。
        
        このメソッドは以下の処理を行います：
        1. ピアの公開鍵データを検証
        2. 楕円曲線Diffie-Hellman (ECDH) による共有秘密の計算
        3. 格子ベース暗号による共有秘密のカプセル化
        4. 両方の共有秘密を組み合わせた最終的な共有秘密の導出
        
        Args:
            peer_pub: ピアの公開鍵データ
            
        Returns:
            Tuple[bytes, bytes]: (共有秘密鍵, 暗号文)のタプル
            
        Raises:
            AuthenticationError: ピア検証に失敗した場合
            HandshakeTimeoutError: ハンドシェイクがタイムアウトした場合
            その他の例外: 暗号操作中にエラーが発生した場合
        """
     try:

      async with asyncio.timeout(self.config_manager.getint("timeouts", "HANDSHAKE_TIMEOUT", fallback=30)):
        #await asyncio.sleep(self.config_manager.getint("timeouts", "HANDSHAKE_TIMEOUT", fallback=30))
        if not await self.verify_peer(peer_pub):
             await self._log_security_event("HIGH", "KEX_FAILURE", "Peer verification failed during exchange")
             self.logger.warning("Peer verification failed during exchange.")
             raise AuthenticationError("Peer verification failed during exchange.")

        # 鍵使用回数を増やす
        self.key_usage_count += 1
        
        # 必要に応じてAWAをローテーション
        if self.key_usage_count >= self.max_key_usage:
            await self.rotate_awa_if_needed()

        try:
            # 楕円曲線Diffie-Hellman (ECDH) 部分
            ec_peer = peer_pub[8:40]
            sig_length = self.signer.details.get("length_signature", 64)
            pq_peer = peer_pub[40:-sig_length]
            
            # EC部分の共有秘密を計算
            ec_peer_key = x25519.X25519PublicKey.from_public_bytes(ec_peer)
            ec_shared = await asyncio.get_event_loop().run_in_executor(None, self.ec_priv.exchange, ec_peer_key)
            
            # 格子ベースの暗号を使用したカプセル化
            ciphertext, pq_shared = self.kyber.encap_secret(pq_peer)
            # ロール情報を明示的に示す
            # role_label = b"initiator" if self.is_initiator else b"responder"
            # ec_parts = sorted([self.ec_priv_public_raw, ec_peer])
            # pq_parts = sorted([self.public_key, pq_peer])
            # トランスクリプトの構築
            transcript = self._build_transcript(ec_peer, pq_peer)
            salt = self._generate_salt(transcript)
            
            # 最終的な共有秘密の導出
            hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=salt, info=b'hybrid-kex-v5')
            shared_secret = hkdf.derive(ec_shared + pq_shared)
            #print(len(shared_secret))

            # 成功ログ
            await self._log_security_event("LOW", "KEX_SUCCESS", "Key exchange successful")
            self.logger.info("Key exchange successful.")
            return shared_secret, ciphertext
            
        except Exception as e:
            await self._log_security_event("HIGH", "KEX_ERROR", f"Key exchange error: {str(e)}")
            self.logger.error(f"Key exchange failed: {str(e)}")
            raise
     except asyncio.TimeoutError as e:
            await self._log_security_event("HIGH", "HANDSHAKE_TIMEOUT", 
                f"Handshake timed out after {self.config_manager.getint('timeouts', 'HANDSHAKE_TIMEOUT')} seconds")
            raise HandshakeTimeoutError("Handshake process timed out") from e
    async def decap(self, ciphertext: bytes, peer_pub: bytes) -> bytes:
        """
        受け取った暗号文とピアの公開鍵を使用して共有秘密鍵を復元します。
        
        Args:
            ciphertext: 暗号化されたデータ
            peer_pub: ピアの公開鍵データ
            
        Returns:
            bytes: 復元された共有秘密鍵
            
        Raises:
            その他の例外: 暗号操作中にエラーが発生した場合
        """
        try:
            # 格子ベースの暗号を使用した復号化
            pq_shared = self.kyber.decap_secret(ciphertext)

            # EC部分の共有秘密を計算
            ec_peer = peer_pub[8:40]
            sig_length = self.signer.details.get("length_signature", 64)
            pq_peer = peer_pub[40:-sig_length]

            ec_peer_key = x25519.X25519PublicKey.from_public_bytes(ec_peer)
            ec_shared = await asyncio.get_event_loop().run_in_executor(None, self.ec_priv.exchange, ec_peer_key)
            #role_label = b"initiator" if self.is_initiator else b"responder"
            # ec_parts = sorted([self.ec_priv_public_raw, ec_peer])
            # pq_parts = sorted([self.public_key, pq_peer])
            # トランスクリプトの構築
            transcript = self._build_transcript(ec_peer, pq_peer)
            salt = self._generate_salt(transcript)

            # 最終的な共有秘密の導出
            hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=salt, info=b'hybrid-kex-v5')
            shared_secret = hkdf.derive(ec_shared + pq_shared)

            # 成功ログ
            await self._log_security_event("LOW", "DECAP_SUCCESS", "Key decapsulation successful")
            self.logger.info("Key decapsulation successful.")

            return shared_secret
        except Exception as e:
            await self._log_security_event("HIGH", "DECAP_ERROR", f"Key decapsulation error: {str(e)}")
            self.logger.error(f"Key decapsulation failed: {str(e)}")
            raise
    async def _log_security_event(self, severity: str, event_type: str, details: str,):
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
        これにより、後で同じ状態を復元することが可能になります。
        
        エクスポートされる情報:
        - EC秘密鍵
        - Kyber公開鍵と秘密鍵
        - 署名鍵ペア
        - AWA
        - 楕円曲線公開鍵（Raw形式）
        - クライアントID
        
        Returns:
            Dict[str, str]: エクスポートされた鍵データの辞書（Base64エンコード）
        """
        # 秘密鍵は必ずシリアライズする
        ec_private_bytes = self.ec_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # クライアントIDも含める
        return {
            'ec_private': base64.b64encode(ec_private_bytes).decode('utf-8'),
            'ec_public': base64.b64encode(self.ec_priv_public_raw).decode('utf-8'),
            'kyber_public': base64.b64encode(self.public_key).decode('utf-8'),
            'kyber_secret': base64.b64encode(self.kyber.export_secret_key()).decode('utf-8'),
            'sig_public': base64.b64encode(self.sig_keypair).decode('utf-8'),
            'sig_secret': base64.b64encode(self.signer.export_secret_key()).decode('utf-8'),
            'awa': base64.b64encode(self.awa).decode('utf-8')
        }

    @classmethod
    async def load_from_keys(cls, data: Dict[str, Any], config_manager: ConfigurationManager = None) -> 'QuantumSafeKEX':
        """
        エクスポートされた鍵データから新しいQuantumSafeKEXインスタンスを作成します。
        
        Args:
            data: export_keys()メソッドでエクスポートされた鍵データの辞書
            config_manager: 設定を管理するConfigurationManagerのインスタンス（オプション）
            
        Returns:
            QuantumSafeKEX: 復元されたインスタンス
            
        Raises:
            ValueError: 必要なキーがデータ辞書に存在しない場合
        """
        required_keys = ['ec_private', 'ec_public', 'kyber_public', 'kyber_secret', 'sig_public', 'sig_secret', 'awa']
        for key in required_keys:
            if key not in data:
                raise ValueError(f"Missing required key in data: {key}")
                
        # 設定マネージャーの準備
        config = config_manager or ConfigurationManager()
        
        # EC鍵の復元
        ec_priv_bytes = base64.b64decode(data['ec_private'])
        ec_priv = x25519.X25519PrivateKey.from_private_bytes(ec_priv_bytes)
        
        # Kyber鍵の復元
        kyber = KeyEncapsulation(config.get("kex", "KEX_ALG"), base64.b64decode(data['kyber_secret']))
        
        # 署名鍵の復元
        signer = Signature(config.get("signature", "SIG_ALG"), base64.b64decode(data['sig_secret']))
        
        # インスタンス作成
        instance = cls(
            identity_key=ec_priv,
            kyber_keypair=base64.b64decode(data['kyber_public']),
            ec_priv_public_raw=base64.b64decode(data['ec_public']),
            awa=base64.b64decode(data['awa']),
            sig_keypair=base64.b64decode(data['sig_public']),
      ec_pub_rawer=config
        )
        
        # 鍵の内部状態を調整
        instance.kyber = kyber
        instance.signer = signer
        
        return instance

    def _build_transcript(self, ec_peer, pq_peer):
        ec_parts = sorted([self.ec_priv_public_raw, ec_peer])
        pq_parts = sorted([self.public_key, pq_peer])
        return (
            b"hybrid-kex-v5" +
            b"|ec_a:" + ec_parts[0] +
            b"|ec_b:" + ec_parts[1] +
            b"|pq_a:" + pq_parts[0] +
            b"|pq_b:" + pq_parts[1]
        )

    def _generate_salt(self, transcript):
        hasher = hashes.Hash(hashes.SHA512())
        hasher.update(transcript)
        return hasher.finalize()[:32]