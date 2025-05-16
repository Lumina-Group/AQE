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
from typing import Optional
from collections import deque, OrderedDict

class SecureTransport:
    def __init__(
        self,
        initial_key: bytes,
        config_manager: Optional[ConfigurationManager] = None,
        logger: Optional[EnhancedSecurityLogger] = None
    ):
        """
        SecureTransportクラスのインスタンスを初期化します。

        Args:
            initial_key (bytes): 初期の暗号化キー。
            config_manager (Optional[ConfigurationManager]): 設定マネージャーのインスタンス。指定されない場合は新しく作成されます。
            logger (Optional[EnhancedSecurityLogger]): セキュリティロガーのインスタンス。指定されない場合は新しく作成されます。
        """
        self.config_manager = config_manager or ConfigurationManager()
        # 接続タイムアウト時間を設定ファイルから取得します。デフォルトは300秒です。
        self.connection_timeout = self.config_manager.getint("timeouts", "CONNECTION_TIMEOUT", fallback=300)
        # クリーンアップ間隔を設定ファイルから取得します。デフォルトは300秒です。
        self.cleanup_interval = self.config_manager.getint("timeouts", "CLEANUP_INTERVAL", fallback=300)
        self.last_activity_time = time.time()

    
        self.security_metrics = SecurityMetrics()
        self.enhanced_logger = logger or EnhancedSecurityLogger(setup_logging(), self.security_metrics)
        self.logger = self.enhanced_logger.logger

        self.current_key = initial_key
        # 現在のキーのSHA-256ハッシュの先頭8文字をキーIDとして生成します。
        self.key_id = hashlib.sha256(self.current_key).hexdigest()[:8]

        self.sequence = 0
        self.last_valid_seq = -1
        # シーケンスウィンドウサイズを設定ファイルから取得します。デフォルトは1024です。
        self.window_size = self.config_manager.getint("security", "SEQUENCE_WINDOW_SIZE", fallback=1024)
        # 挿入順序を維持し、高速なpop操作が可能なdequeを使用します。
        self.sequence_window = deque(maxlen=self.window_size)
        self.sequence_set = set()

        # LRUキャッシュとしてOrderedDictを使用します。キーはnonceの16進文字列、値はNoneです。
        self._nonce_cache = OrderedDict()
        # nonceキャッシュの最大サイズを設定ファイルから取得します。デフォルトは10000です。
        self._nonce_cache_max_size = self.config_manager.getint("security", "NONCE_CACHE_SIZE", fallback=10000)

        self.last_timestamp = time.time()
        self.logger.info(f"SecureTransport initialized with key ID {self.key_id}")

    async def encrypt(self, plaintext: bytes, context: Optional[bytes] = None) -> bytes:
        """
        平文を暗号化します。

        Args:
            plaintext (bytes): 暗号化する平文。
            context (Optional[bytes]): 追加認証データとして使用されるコンテキストデータ。デフォルトはNoneです。

        Returns:
            bytes: 暗号化されたJSON形式のメッセージ。

        Raises:
            ValueError: 平文のサイズが最大許容サイズを超える場合。
        """
        self._update_activity()
        # 最大メッセージサイズを設定ファイルから取得します。デフォルトは65536バイトです。
        max_size = self.config_manager.getint("security", "MAX_MESSAGE_SIZE", fallback=65536)
        if len(plaintext) > max_size:
            self.logger.warning(
                f"Plaintext size {len(plaintext)} exceeds maximum allowed size {max_size}."
            )
            raise ValueError(f"Message too large. Maximum size is {max_size} bytes.")

        self.sequence += 1
        seq_bytes = self.sequence.to_bytes(8, 'big')
        key = self.current_key

        nonce = self._make_nonce(seq_bytes)
        timestamp_bytes = int(time.time()).to_bytes(8, 'big')
        context_data = context or b''
        aad = seq_bytes + timestamp_bytes
        if context_data:
            # コンテキストデータのSHA-256ハッシュの先頭8バイトをAADに追加します。
            context_hash = hashlib.sha256(context_data).digest()[:8]
            aad += context_hash

        try:
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            message = {
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'aad': base64.b64encode(aad).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'timestamp': int(time.time())
            }
            return json.dumps(message).encode('utf-8')
        except Exception as e:
            self.logger.error(f"Encryption error: {str(e)}", exc_info=True)
            await self.security_metrics.increment_encryption_failures()
            raise

    async def decrypt(self, encrypted_message_json: bytes) -> bytes:
        """
        暗号化されたJSON形式のメッセージを復号化します。

        Args:
            encrypted_message_json (bytes): 暗号化されたJSON形式のメッセージ。

        Returns:
            bytes: 復号化された平文。

        Raises:
            AuthenticationTagMismatchError: 認証タグが一致しない場合。
            DecryptionError: 復号化中に予期しないエラーが発生した場合。
        """
        self._update_activity()
        current_time_int = int(time.time())

        data = await self._load_json(encrypted_message_json)
        await self._validate_fields(data)
        message_timestamp = data['timestamp']
        await self._validate_timestamp(message_timestamp, current_time_int)

        nonce, aad_received, ciphertext, tag = await self._decode_components(data)
        await self._validate_nonce(nonce)
        self._validate_replay_nonce(nonce)

        received_seq = await self._extract_sequence(aad_received)
        await self._validate_sequence(received_seq)

        self._record_sequence(received_seq)

        try:
            cipher = ChaCha20_Poly1305.new(key=self.current_key, nonce=nonce)
            cipher.update(aad_received)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            self.logger.debug(f"Message decrypted successfully. Sequence: {received_seq}")
            return plaintext
        except ValueError as e:
            await self.security_metrics.increment_decryption_failures()
            self.logger.error(
                f"Decryption failed (tag mismatch or corrupted data): {e} for seq {received_seq}"
            )
            raise AuthenticationTagMismatchError(
                f"Authentication tag mismatch or corrupted data for seq {received_seq}."
            )
        except Exception as e:
            await self.security_metrics.increment_decryption_failures()
            self.logger.error(
                f"Unexpected error during decryption: {str(e)} for seq {received_seq}",
                exc_info=True
            )
            raise DecryptionError(f"Unexpected error during decryption: {e}")

    def _make_nonce(self, seq_bytes: bytes) -> bytes:
        """
        シーケンスバイトからnonceを生成します。

        Args:
            seq_bytes (bytes): シーケンス番号のバイト列。

        Returns:
            bytes: 生成されたnonce。
        """
        random_part = os.urandom(4)
        return seq_bytes[-8:] + random_part

    async def _load_json(self, data: bytes) -> dict:
        """
        バイト列をJSONデータに変換します。

        Args:
            data (bytes): JSON形式のバイト列。

        Returns:
            dict: 変換されたJSONデータ。

        Raises:
            DecryptionError: JSON形式が無効な場合。
        """
        try:
            return json.loads(data.decode('utf-8'))
        except json.JSONDecodeError as e:
            await self.security_metrics.increment_decryption_failures()
            self.logger.error(f"Invalid JSON format: {e}")
            raise DecryptionError(f"Invalid message format: {e}")

    async def _validate_fields(self, data: dict):
        """
        暗号化されたメッセージに必要なフィールドが含まれていることを検証します。

        Args:
            data (dict): 暗号化されたメッセージのJSONデータ。

        Raises:
            DecryptionError: 必要なフィールドが欠落している場合。
        """
        for field in ('nonce', 'aad', 'ciphertext', 'tag', 'timestamp'):
            if field not in data:
                await self.security_metrics.increment_decryption_failures()
                self.logger.error(f"Missing field: {field}")
                raise DecryptionError(f"Missing required field: {field}")

    async def _validate_timestamp(self, msg_ts: int, now: int):
        """
        メッセージのタイムスタンプが有効であることを検証します。

        Args:
            msg_ts (int): メッセージのタイムスタンプ。
            now (int): 現在のタイムスタンプ。

        Raises:
            ReplayAttackError: メッセージが古すぎる場合。
            DecryptionError: メッセージのタイムスタンプが未来の場合。
        """
        # メッセージの最大有効期間を設定ファイルから取得します。デフォルトは300秒です。
        max_age = self.config_manager.getint("security", "MESSAGE_MAX_AGE", fallback=300)
        # クロックスキューの許容範囲を設定ファイルから取得します。デフォルトは5秒です。
        skew = self.config_manager.getint("security", "CLOCK_SKEW_ALLOWANCE", fallback=5)
        if now - msg_ts > max_age:
            await self.security_metrics.increment_expired_messages()
            self.logger.warning(f"Message expired (age {now - msg_ts}s > {max_age}s)")
            raise ReplayAttackError("Message too old.")
        if msg_ts > now + skew:
            await self.security_metrics.increment_decryption_failures()
            self.logger.warning(f"Future timestamp: {msg_ts} > {now} + {skew}")
            raise DecryptionError("Message timestamp from future.")

    async def _decode_components(self, data: dict):
        """
        暗号化されたメッセージの各コンポーネントをBase64デコードします。

        Args:
            data (dict): 暗号化されたメッセージのJSONデータ。

        Returns:
            Tuple[bytes, bytes, bytes, bytes]: デコードされたnonce、AAD、暗号文、タグ。

        Raises:
            ValueError: Base64データが無効な場合。
        """
        try:
            nonce = base64.b64decode(data['nonce'])
            aad = base64.b64decode(data['aad'])
            ciphertext = base64.b64decode(data['ciphertext'])
            tag = base64.b64decode(data['tag'])
            return nonce, aad, ciphertext, tag
        except Exception as e:
            await self.security_metrics.increment_decryption_failures()
            self.logger.error(f"Base64 decode error: {e}")
            raise ValueError(f"Invalid base64 data: {e}")

    async def _validate_nonce(self, nonce: bytes):
        """
        nonceの長さが有効であることを検証します。

        Args:
            nonce (bytes): 検証するnonce。

        Raises:
            InvalidNonceError: nonceの長さが無効な場合。
        """
        if len(nonce) != 12:
            await self.security_metrics.increment_decryption_failures()
            self.logger.error(f"Invalid nonce length {len(nonce)}")
            raise InvalidNonceError(f"Invalid nonce length {len(nonce)}")

    def _validate_replay_nonce(self, nonce: bytes):
        """
        nonceが再利用されていないことを検証します。

        Args:
            nonce (bytes): 検証するnonce。

        Raises:
            InvalidNonceError: nonceが再利用されている場合。
        """
        key = nonce.hex()
        if key in self._nonce_cache:
            self.logger.warning(f"Replayed nonce: {key}")
            raise InvalidNonceError("Replayed nonce detected.")
        self._nonce_cache[key] = None
        if len(self._nonce_cache) > self._nonce_cache_max_size:
            # LRUキャッシュから最も古いエントリを削除します。
            self._nonce_cache.popitem(last=False)

    async def _extract_sequence(self, aad: bytes) -> int:
        """
        AADからシーケンス番号を抽出します。

        Args:
            aad (bytes): 追加認証データ。

        Returns:
            int: 抽出されたシーケンス番号。

        Raises:
            DecryptionError: AADが短すぎる場合。
        """
        if len(aad) < 8:
            await self.security_metrics.increment_decryption_failures()
            self.logger.error(f"AAD too short: {len(aad)}")
            raise DecryptionError("AAD too short.")
        return int.from_bytes(aad[:8], 'big')

    async def _validate_sequence(self, seq: int):
        """
        シーケンス番号が有効であることを検証します。

        Args:
            seq (int): 検証するシーケンス番号。

        Raises:
            ReplayAttackError: シーケンス番号が古すぎるか、再利用されている場合。
        """
        if seq <= self.last_valid_seq and seq not in self.sequence_set:
            self.logger.warning(f"Old sequence {seq}")
            raise ReplayAttackError(f"Old or replayed sequence: {seq}")
        if seq > self.last_valid_seq + self.window_size:
            await self.security_metrics.increment_decryption_failures()
            self.logger.warning(f"Sequence too far ahead: {seq}")
            raise ReplayAttackError(f"Sequence too far in future: {seq}")

    def _record_sequence(self, seq: int):
        """
        有効なシーケンス番号を記録します。

        Args:
            seq (int): 記録するシーケンス番号。
        """
        if seq > self.last_valid_seq:
            self.last_valid_seq = seq
        if seq not in self.sequence_set:
            self.sequence_window.append(seq)
            self.sequence_set.add(seq)
        # 古いシーケンス番号を削除します。
        while len(self.sequence_window) > self.window_size:
            old = self.sequence_window.popleft()
            self.sequence_set.remove(old)

    def _update_activity(self):
        """
        最後のアクティビティ時間を更新します。
        """
        self.last_activity_time = time.time()

    async def _check_connection_timeout(self):
        """
        接続がタイムアウトしていないかチェックします。タイムアウトしている場合はリソースをクリーンアップします。
        """
        if time.time() - self.last_activity_time > self.connection_timeout:
            self.logger.warning("Connection timeout, cleaning up")
            await self._cleanup_resources()

    async def _cleanup_resources(self):
        """
        古いキャッシュデータやシーケンス番号をクリーンアップします。
        """
        self.logger.debug("Performing cleanup...")
        # キャッシュが古い場合はリセットします。
        if len(self._nonce_cache) > self._nonce_cache_max_size:
            self._nonce_cache.clear()
            self.logger.debug("Cleared nonce cache")

        # 古いシーケンス番号を削除します。
        cutoff = self.last_valid_seq - self.window_size
        new_queue = deque()
        new_set = set()
        for s in self.sequence_window:
            if s > cutoff:
                new_queue.append(s)
                new_set.add(s)
        removed = len(self.sequence_window) - len(new_queue)
        self.sequence_window = new_queue
        self.sequence_set = new_set
        if removed:
            self.logger.debug(f"Removed {removed} old sequences")
        self.logger.debug("Cleanup done.")

    def export_key_state(self) -> dict:
        """
        現在の鍵状態をエクスポートする (バックアップまたは状態保存用)
        """
        return {
            'key': base64.b64encode(self.current_key).decode(),
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

        instance.security_metrics = SecurityMetrics()
        instance.logger = EnhancedSecurityLogger(self.logger, instance.security_metrics).logger

        try:
            instance.current_key = base64.b64decode(state['key'])
          #  instance.current_salt = base64.b64decode(state['salt']) if state.get('salt') else None
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