import os
import time
import base64
import json
import hashlib
from Crypto.Cipher import ChaCha20_Poly1305
from .errors import (
    ReplayAttackError,
    DecryptionError,
    InvalidNonceError,
    AuthenticationTagMismatchError
)
from .logger import EnhancedSecurityLogger, SecurityMetrics, setup_logging
from .configuration import ConfigurationManager

class SecureTransport:
    def __init__(self, initial_key: bytes, config_manager: ConfigurationManager = None, logger: EnhancedSecurityLogger = None):
        """
        安全な通信トランスポート層を初期化します。
        このクラスは暗号化、復号化などを担当します。

        機能:
        - ChaCha20-Poly1305による暗号化/復号化
        - リプレイ攻撃に対する保護
        - シーケンス番号の検証

        Args:
            initial_key: 初期共有秘密鍵
            config_manager: 設定を管理するConfigurationManagerのインスタンス。指定されていない場合は新しく生成されます。
            logger: 拡張されたセキュリティロガーのインスタンス。指定されていない場合は新しく生成されます。

        Returns:
            なし
        """
        self.config_manager = config_manager or ConfigurationManager()
        self.connection_timeout = self.config_manager.getint("timeouts", "CONNECTION_TIMEOUT", fallback=300)
        self.cleanup_interval = self.config_manager.getint("timeouts", "CLEANUP_INTERVAL", fallback=300)
        self.last_activity_time = time.time()
        logger = logger or setup_logging()
        self.security_metrics = SecurityMetrics()
        self.logger = EnhancedSecurityLogger(logger, self.security_metrics).logger

        self.current_key, self.current_salt = initial_key, None
        self.key_id = hashlib.sha256(self.current_key).hexdigest()[:8]

        self.sequence = 0
        self.last_valid_seq = -1
        self.window_size = self.config_manager.getint("security", "SEQUENCE_WINDOW_SIZE", fallback=1024)
        self.sequence_window = set()

        self._nonce_cache = set()
        self._nonce_cache_size = self.config_manager.getint("security", "NONCE_CACHE_SIZE", fallback=10000)

        self.last_timestamp = time.time()

        self.logger.info(f"SecureTransport initialized with key ID {self.key_id}")

    async def encrypt(self, plaintext: bytes, context: bytes = None) -> bytes:
        """
        平文を暗号化します。

        ChaCha20-Poly1305アルゴリズムを使用し、以下の特徴を持ちます：
        - メッセージサイズの上限を設定可能
        - ノンスをランダムに生成し、一意性を保証
        - 追加認証データ (AAD) にシーケンス番号、タイムスタンプを含める

        Args:
            plaintext: 暗号化する平文データ
            context: 追加の認証データに含めるコンテキスト情報（オプション）

        Returns:
            bytes: 暗号化されたメッセージ（JSON形式）

        Raises:
            ValueError: メッセージサイズが上限を超えた場合
            その他の例外: 暗号化処理中にエラーが発生した場合
        """
        self.last_activity_time = time.time()
        max_size = self.config_manager.getint("security", "MAX_MESSAGE_SIZE", fallback=65536)
        if len(plaintext) > max_size:
            raise ValueError(f"Message too large. Maximum size is {max_size} bytes.")

        self.sequence += 1
        seq_bytes = self.sequence.to_bytes(8, 'big')

        key = self.current_key

        random_bytes = os.urandom(4)
        nonce = seq_bytes[-8:] + random_bytes

        timestamp = int(time.time()).to_bytes(8, 'big')
        context_data = context or b''
        aad = seq_bytes + timestamp
        if context_data:
            context_hash = hashlib.sha256(context_data).digest()[:8]
            aad += context_hash

        try:
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

            message = {
                'nonce': base64.b64encode(nonce).decode(),
                'aad': base64.b64encode(aad).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'tag': base64.b64encode(tag).decode(),
                'timestamp': int(time.time())
            }

            return json.dumps(message).encode()
        except Exception as e:
            self.logger.error(f"Encryption error: {str(e)}")
            await self.security_metrics.increment_encryption_failures()

    async def decrypt(self, encrypted: bytes) -> bytes:
        """
        暗号文を復号します。

        Args:
            encrypted: 復号する暗号文（JSON形式）

        Returns:
            bytes: 復号された平文

        Raises:
            DecryptionError: 復号に失敗した場合
            InvalidNonceError: 無効なノンスが検出された場合
            AuthenticationTagMismatchError: 認証タグの不一致が検出された場合
            ReplayAttackError: リプレイ攻撃が検出された場合
            その他の例外: 復号処理中にエラーが発生した場合
        """
        try:
            self.last_activity_time = time.time()
            data = json.loads(encrypted.decode())

            required_fields = ['nonce', 'aad', 'ciphertext', 'tag', 'timestamp']
            for field in required_fields:
                if field not in data:
                    raise DecryptionError(f"Missing required field: {field}")

            message_time = data['timestamp']
            current_time = int(time.time())
            max_age = self.config_manager.getint("security", "MESSAGE_MAX_AGE", fallback=300)
            if current_time - message_time > max_age:
                await self.security_metrics.increment_expired_messages()
                raise DecryptionError(f"Message expired. Arrived {current_time - message_time}s late. Maximum age is {max_age} seconds.")

            key = self.current_key

            try:
                nonce = base64.b64decode(data['nonce'])
                aad = base64.b64decode(data['aad'])
                ciphertext = base64.b64decode(data['ciphertext'])
                tag = base64.b64decode(data['tag'])
            except (TypeError, ValueError) as e:
                raise DecryptionError(f"Invalid base64 encoding: {e}")

            if len(nonce) != 12:
                raise InvalidNonceError(f"Invalid nonce length: {len(nonce)}")

            if len(aad) < 8:
                raise DecryptionError("AAD too short to extract sequence number")
            seq = int.from_bytes(aad[:8], 'big')

            if seq in self.sequence_window:
                await self.security_metrics.increment_replay_attacks()
                raise ReplayAttackError(f"Duplicate sequence number detected: {seq}")

            if seq > self.last_valid_seq:
                if seq - self.last_valid_seq > self.window_size:
                    to_remove = {s for s in self.sequence_window if s <= seq - self.window_size}
                    self.sequence_window -= to_remove
                self.sequence_window.add(seq)
                self.last_valid_seq = max(self.last_valid_seq, seq)
            elif seq > self.last_valid_seq - self.window_size:
                if seq not in self.sequence_window:
                    self.sequence_window.add(seq)
                else:
                    await self.security_metrics.increment_replay_attacks()
                    raise ReplayAttackError(f"Duplicate sequence number {seq} within window (should have been caught earlier)")
            else:
                await self.security_metrics.increment_replay_attacks()
                raise ReplayAttackError(f"Sequence number {seq} is too old (older than window)")

            if len(self.sequence_window) > self.window_size * 1.5:
                cutoff = self.last_valid_seq - self.window_size
                self.sequence_window = {s for s in self.sequence_window if s > cutoff}

            if nonce in self._nonce_cache:
                await self.security_metrics.increment_replay_attacks()
                raise ReplayAttackError(f"Nonce reuse detected: {base64.b64encode(nonce).decode()}")

            self._nonce_cache.add(nonce)
            if len(self._nonce_cache) > self._nonce_cache_size:
                self._nonce_cache.clear()
                self.logger.debug("Nonce cache cleared due to size limit")

            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cipher.update(aad)

            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                await self.security_metrics.increment_successful_decryptions()
                return plaintext
            except ValueError as e:
                await self.security_metrics.increment_decryption_failures()
                self.logger.warning(f"Authentication failed for seq {seq}: {e}")
                raise AuthenticationTagMismatchError("Authentication failed: Data may have been tampered with")

        except json.JSONDecodeError as e:
            await self.security_metrics.increment_decryption_failures()
            raise DecryptionError(f"Invalid message format: {e}")
        except ReplayAttackError as e:
            self.logger.warning(f"Replay attack detected: {e}")
            raise
        except DecryptionError as e:
            await self.security_metrics.increment_decryption_failures()
            self.logger.error(f"Decryption error: {e}")
            raise
        except Exception as e:
            await self.security_metrics.increment_decryption_failures()
            self.logger.exception(f"Unexpected error during decryption: {e}")
            if isinstance(e, (AuthenticationTagMismatchError, InvalidNonceError)):
                raise
            raise DecryptionError(f"Unexpected decryption error: {str(e)}") from e

    async def _check_connection_timeout(self):
        """接続タイムアウトチェック"""
        if time.time() - self.last_activity_time > self.connection_timeout:
            self.logger.warning("Connection timeout, initiating cleanup")
            await self._cleanup_resources()

    async def _cleanup_resources(self):
        """定期的なリソースクリーンアップ"""
        now = time.time()
        self.logger.debug("Performing periodic cleanup...")

        if len(self._nonce_cache) > self._nonce_cache_size:
            self._nonce_cache.clear()
            self.logger.debug(f"Cleared nonce cache (size exceeded {self._nonce_cache_size})")

        cutoff = self.last_valid_seq - self.window_size
        removed_count = len(self.sequence_window)
        self.sequence_window = {s for s in self.sequence_window if s > cutoff}
        removed_count -= len(self.sequence_window)
        if removed_count > 0:
            self.logger.debug(f"Removed {removed_count} old sequence numbers from window")

        self.logger.debug("Cleanup finished.")

    def export_key_state(self) -> dict:
        """
        現在の鍵状態をエクスポートする (バックアップまたは状態保存用)
        """
        return {
            'key': base64.b64encode(self.current_key).decode(),
            'salt': base64.b64encode(self.current_salt).decode() if self.current_salt else None,
            'key_id': self.key_id,
            'sequence': self.sequence,
            'last_valid_seq': self.last_valid_seq,
            'timestamp': time.time()
        }

    @classmethod
    def from_key_state(cls, state: dict, config_manager: ConfigurationManager = None) -> 'SecureTransport':
        """
        エクスポートされた鍵状態から SecureTransport インスタンスを作成する
        """
        instance = cls.__new__(cls)
        instance.config_manager = config_manager or ConfigurationManager()

        logger = setup_logging()
        instance.security_metrics = SecurityMetrics()
        instance.logger = EnhancedSecurityLogger(logger, instance.security_metrics).logger

        try:
            instance.current_key = base64.b64decode(state['key'])
            instance.current_salt = base64.b64decode(state['salt']) if state.get('salt') else None
            instance.key_id = state.get('key_id', hashlib.sha256(instance.current_key).hexdigest()[:8])
        except (KeyError, TypeError, ValueError) as e:
            instance.logger.error(f"Failed to restore key state: {e}")
            raise ValueError("Invalid key state provided for restoration") from e

        instance.sequence = state.get('sequence', 0)
        instance.last_valid_seq = state.get('last_valid_seq', -1)

        instance.window_size = instance.config_manager.getint("security", "SEQUENCE_WINDOW_SIZE", fallback=1024)
        instance.sequence_window = set()

        instance._nonce_cache_size = instance.config_manager.getint("security", "NONCE_CACHE_SIZE", fallback=10000)
        instance._nonce_cache = set()

        instance.connection_timeout = instance.config_manager.getint("timeouts", "CONNECTION_TIMEOUT", fallback=300)
        instance.cleanup_interval = instance.config_manager.getint("timeouts", "CLEANUP_INTERVAL", fallback=300)
        instance.last_activity_time = time.time()
        instance.last_timestamp = time.time()

        instance.logger.info(f"SecureTransport restored from key state with key ID {instance.key_id}")
        return instance