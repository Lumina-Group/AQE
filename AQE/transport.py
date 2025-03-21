
import os
import time
import base64
import json
import hashlib
import struct
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Cryptodome.Cipher import ChaCha20_Poly1305
from .errors import (
    ReplayAttackError,
    DecryptionError,
    InvalidNonceError,
    AuthenticationTagMismatchError
)
from .logger import EnhancedSecurityLogger, SecurityMetrics, setup_logging
from .configuration import ConfigurationManager

class SecureTransport:
    def __init__(self, initial_key: bytes, config_manager: ConfigurationManager = None):
        """
        安全な通信トランスポート層を初期化します。
        このクラスは暗号化、復号化、鍵の管理などを担当します。
        
        機能:
        - ChaCha20-Poly1305による暗号化/復号化
        - 自動的な鍵のローテーション
        - リプレイ攻撃に対する保護
        - シーケンス番号の検証
        
        Args:
            initial_key: 初期共有秘密鍵
            config_manager: 設定を管理するConfigurationManagerのインスタンス。指定されていない場合は新しく生成されます。
            
        Returns:
            なし
        """
        self.config_manager = config_manager or ConfigurationManager()
        
        # ログ設定
        logger = setup_logging()
        self.security_metrics = SecurityMetrics()
        self.logger = EnhancedSecurityLogger(logger, self.security_metrics).logger
        
        # 初期鍵セットの生成
        self.current_key = initial_key
        self.current_salt = None
        self.key_chain = [{
            'key': self.current_key,
            'salt': self.current_salt,
            'created': time.time(),
            'uses': 0,
            'id': hashlib.sha256(self.current_key).hexdigest()[:8] 
        }]
        
        # シーケンス番号の初期化
        self.sequence = 0
        self.last_valid_seq = -1
        self.window_size = self.config_manager.getint("security", "SEQUENCE_WINDOW_SIZE", fallback=1024)
        self.sequence_window = set()
        
        # ノンスキャッシュの初期化
        self._nonce_cache = set()
        self._nonce_cache_size = self.config_manager.getint("security", "NONCE_CACHE_SIZE", fallback=10000)
        
        # タイムスタンプの初期化
        self.last_timestamp = time.time()
        
        # 鍵同期用の状態管理
        self.key_sync_state = {
            'last_sync': time.time(),
            'pending_rotations': set()
        }
        
        # 再送攻撃検出用のウィンドウ
        self.replay_window_size = self.config_manager.getint("security", "REPLAY_WINDOW_SIZE", fallback=64)
        self.replay_window = [False] * self.replay_window_size
        
        # 鍵ローテーション設定
        self.key_rotation_interval = self.config_manager.getint("security", "KEY_ROTATION_INTERVAL", fallback=1000)
        self.key_rotation_time = self.config_manager.getint("security", "KEY_ROTATION_TIME", fallback=3600)
        self.max_key_chain_length = self.config_manager.getint("security", "MAX_KEY_CHAIN_LENGTH", fallback=3)
        
        # パフォーマンス最適化用のキャッシュ
        self._nonce_cache_size = self.config_manager.getint("performance", "NONCE_CACHE_SIZE", fallback=1024)
        self._nonce_cache = set()
        
        self.logger.info(f"SecureTransport initialized with key chain size {self.max_key_chain_length}")

    def _derive_key(self, key_material: bytes) -> Tuple[bytes, bytes]:
        """
        鍵材料から新しい鍵を派生させます。
        HKDF (HMAC-based Key Derivation Function) を使用して、初期鍵材料から
        暗号化に使用する鍵を安全に生成します。
        
        Args:
            key_material: 元となる鍵材料
            
        Returns:
            Tuple[bytes, bytes]: (派生した鍵, 使用したソルト)のタプル
        """
        # バージョン情報を含める
        version_tag = b'chacha-key-v3'
        
        # ソルト生成
        salt = os.urandom(32)
        
        # 時間情報を追加
        timestamp = struct.pack(">Q", int(time.time()))
        info = version_tag + b'|' + timestamp
        
        # HKDF設定
        key_size = self.config_manager.getint("security", "KEY_SIZE", fallback=32)
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=key_size,
            salt=salt,
            info=info
        )
        
        return hkdf.derive(key_material), salt

    async def rotate_key_if_needed(self) -> bool:
        """
        条件に応じて鍵をローテーションします。
        
        以下の条件のいずれかに当てはまる場合、鍵をローテーションします：
        1. 現在の鍵の使用回数が設定された閾値を超えた場合
        2. 現在の鍵が生成されてから設定された時間が経過した場合
        
        Returns:
            bool: ローテーションが行われた場合はTrue、それ以外はFalse
        """
        current_key_data = self.key_chain[-1]
        needs_rotation = False
        
        # 使用回数による判断
        if current_key_data['uses'] >= self.key_rotation_interval:
            needs_rotation = True
            self.logger.info(f"Key rotation triggered by usage count: {current_key_data['uses']}")
        
        # 経過時間による判断
        elapsed_time = time.time() - current_key_data['created']
        if elapsed_time >= self.key_rotation_time:
            needs_rotation = True
            self.logger.info(f"Key rotation triggered by time: {elapsed_time:.2f}s")
            
        if needs_rotation:
            await self.rotate_key()
            return True
        return False    
    async def rotate_key(self):
        """
        鍵をローテーションします。

        このメソッドは以下の処理を行います：
        1. 鍵チェーンの長さが最大値に達している場合、最も古い鍵を削除
        2. 現在の鍵から新しい鍵を派生
        3. 鍵チェーンに新しい鍵を追加
        4. リプレイ保護ウィンドウをリセット

        セキュリティのため、定期的に鍵をローテーションすることで、
        万が一鍵が漏洩した場合のリスクを最小限に抑えます。

        Returns:
            なし
        """
        # 鍵チェーンの長さを制限
        if len(self.key_chain) >= self.max_key_chain_length:
            removed_key = self.key_chain.pop(0)
            self.logger.debug(f"Removed oldest key {removed_key['id']}, chain length: {len(self.key_chain)}")

        # 新しい鍵を生成（現在の鍵から派生）
        new_key, new_salt = self._derive_key(self.current_key)
        new_key_id = hashlib.sha256(new_key).hexdigest()[:8]

        # 鍵チェーンに追加
        new_key_data = {
            'key': new_key,
            'salt': new_salt,
            'created': time.time(),
            'uses': 0,
            'id': new_key_id
        }
        self.key_chain.append(new_key_data)

        self.current_key = new_key
        self.current_salt = new_salt

        # 鍵同期状態を更新
        self.key_sync_state['pending_rotations'].add(new_key_id)

        # セキュリティイベントとしてログに記録
        self.logger.info(f"Key rotated. New key {new_key_id} added. Chain size: {len(self.key_chain)}")

        # リプレイ保護ウィンドウをリセット
        self.sequence_window.clear()
        self.last_valid_seq = self.sequence

    async def encrypt(self, plaintext: bytes, context: bytes = None) -> bytes:
        """
        平文を暗号化します。
        
        ChaCha20-Poly1305アルゴリズムを使用し、以下の特徴を持ちます：
        - 認証付き暗号化（AEAD）によるデータの完全性保護
        - シーケンス番号とランダム値を組み合わせたノンス生成
        - 追加認証データ（AAD）によるメタデータの保護
        - メッセージサイズ制限による異常検知
        
        Args:
            plaintext: 暗号化する平文データ
            context: 追加の認証データに含めるコンテキスト情報（オプション）
            
        Returns:
            bytes: 暗号化されたメッセージ（JSON形式）
            
        Raises:
            ValueError: メッセージサイズが上限を超えた場合
            その他の例外: 暗号化処理中にエラーが発生した場合
        """
        # メッセージサイズチェック
        max_size = self.config_manager.getint("security", "MAX_MESSAGE_SIZE")
        if len(plaintext) > max_size:
            raise ValueError(f"Message too large. Maximum size is {max_size} bytes.")
            
        # シーケンス番号の更新
        self.sequence += 1
        seq_bytes = self.sequence.to_bytes(8, 'big')
        
        # 必要に応じて鍵をローテーション
        await self.rotate_key_if_needed()
        
        # 暗号化に使用する鍵とバージョン
        key_version = len(self.key_chain) - 1
        key_data = self.key_chain[key_version]
        key = key_data['key']
        
        # 鍵使用回数を更新
        self.key_chain[key_version]['uses'] += 1
        
        # ノンス生成 (sequence + random)
        random_bytes = os.urandom(4)  
        nonce = seq_bytes[-8:] + random_bytes
       
        
        # 追加認証データ (AAD) の構築
        # sequence + key_version + timestamp + context
        key_id = key_version.to_bytes(2, 'big')
        timestamp = int(time.time()).to_bytes(8, 'big')
        context_data = context or b''
        aad = seq_bytes + key_id + timestamp
        if context_data:
            context_hash = hashlib.sha256(context_data).digest()[:8]
            aad += context_hash
        #print(len(key))
        
        # 暗号化
        try:
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            
            # メッセージ構造の構築
            message = {
                'nonce': base64.b64encode(nonce).decode(),
                'aad': base64.b64encode(aad).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'tag': base64.b64encode(tag).decode(),
                'key_version': key_version,
                'timestamp': int(time.time())
            }
            
            return json.dumps(message).encode()
        except Exception as e:
            self.logger.error(f"Encryption error: {str(e)}")
            raise

    async def decrypt(self, encrypted: bytes) -> bytes:
        """
        暗号文を復号します。
        
        Args:
            encrypted: 復号する暗号文（JSON形式）
            
        Returns:
            bytes: 復号された平文
            
        Raises:
            DecryptionError: 復号に失敗した場合
            ReplayAttackError: リプレイ攻撃を検出した場合
            その他の例外: 復号処理中にエラーが発生した場合
        """
        try:
            # JSONからデータ構造を解析
            data = json.loads(encrypted.decode())
            
            # タイムスタンプの検証
            if 'timestamp' in data:
                message_time = data['timestamp']
                current_time = int(time.time())
                max_age = self.config_manager.getint("security", "MESSAGE_MAX_AGE", fallback=3600)
                if current_time - message_time > max_age:
                    raise DecryptionError(f"Message expired. Maximum age is {max_age} seconds.")
                self.last_timestamp = message_time
            
            # 鍵バージョンの確認と必要に応じたローテーション
            key_version = data.get('key_version')
            if key_version is None or key_version >= len(self.key_chain):
                raise DecryptionError(f"Invalid key version: {key_version}")
            
            # 鍵の取得と使用回数の更新
            key_data = self.key_chain[key_version]
            key = key_data['key']
            key_id = key_data['id']
            
            # 鍵の同期状態を確認
            if key_id in self.key_sync_state['pending_rotations']:
                self.key_sync_state['pending_rotations'].remove(key_id)
                self.logger.info(f"Key {key_id} synchronized")
            
            key_data['uses'] += 1
            
            # バイナリデータのデコード
            nonce = base64.b64decode(data['nonce'])
            aad = base64.b64decode(data['aad'])
            ciphertext = base64.b64decode(data['ciphertext'])
            tag = base64.b64decode(data['tag'])
            
            # ノンスの検証
            if len(nonce) != 12:
                raise InvalidNonceError(f"Invalid nonce length: {len(nonce)}")
            
            # シーケンス番号とタイムスタンプの抽出
            if len(aad) < 18:  # 8 (seq) + 2 (key_version) + 8 (timestamp)
                raise DecryptionError("AAD too short")
            
            seq = int.from_bytes(aad[:8], 'big')
            timestamp = int.from_bytes(aad[10:18], 'big')
            
            # シーケンス番号の検証
            if seq in self.sequence_window:
                raise ReplayAttackError(f"Duplicate sequence number detected: {seq}")
            
            # シーケンスウィンドウの更新
            if seq > self.last_valid_seq:
                # 新しいシーケンス番号の場合
                if seq - self.last_valid_seq > self.window_size:
                    # ウィンドウサイズを超えた場合、ウィンドウをスライド
                    self.sequence_window.clear()
                    self.last_valid_seq = seq - self.window_size
                self.sequence_window.add(seq)
                self.last_valid_seq = seq
            elif seq > self.last_valid_seq - self.window_size:
                # ウィンドウ内の古いシーケンス番号の場合
                self.sequence_window.add(seq)
            else:
                raise ReplayAttackError(f"Sequence number {seq} is too old")
            
            # ノンスの再利用検出
            if nonce in self._nonce_cache:
                raise ReplayAttackError("Nonce reuse detected")
            
            # ノンスキャッシュの更新
            self._nonce_cache.add(nonce)
            if len(self._nonce_cache) > self._nonce_cache_size:
                self._nonce_cache.clear()
            
            # 復号
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cipher.update(aad)
            
            try:
                return cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError as e:
                raise AuthenticationTagMismatchError("Authentication failed: Data may have been tampered with")
                
        except json.JSONDecodeError:
            raise DecryptionError("Invalid message format")
        except KeyError as e:
            raise DecryptionError(f"Missing required field: {e}")
        except Exception as e:
            if isinstance(e, DecryptionError):
                raise
            raise DecryptionError(f"Decryption error: {str(e)}") from e
            
    def export_key_state(self) -> dict:
        """
        現在の鍵状態をエクスポートする (バックアップまたは状態保存用)
        """
        exported_keys = []
        for key_data in self.key_chain:
            exported_keys.append({
                'key': base64.b64encode(key_data['key']).decode(),
                'salt': base64.b64encode(key_data['salt']).decode(),
                'created': key_data['created'],
                'uses': key_data['uses'],
                'id': key_data['id']
            })
            
        return {
            'keys': exported_keys,
            'sequence': self.sequence,
            'last_valid_seq': self.last_valid_seq,
            'timestamp': time.time()
        }
        
    @classmethod
    def from_key_state(cls, state: dict, config_manager: ConfigurationManager = None) -> 'SecureTransport':
        """
        エクスポートされた鍵状態から SecureTransport インスタンスを作成する
        """
        # 空のインスタンスを作成
        instance = cls.__new__(cls)
        instance.config_manager = config_manager or ConfigurationManager()
        
        # 基本プロパティを初期化
        logger = setup_logging()
        instance.security_metrics = SecurityMetrics()
        instance.logger = EnhancedSecurityLogger(logger, instance.security_metrics).logger
        
        # 鍵状態の復元
        instance.key_chain = []
        for key_data in state['keys']:
            instance.key_chain.append({
                'key': base64.b64decode(key_data['key']),
                'salt': base64.b64decode(key_data['salt']),
                'created': key_data['created'],
                'uses': key_data['uses'],
                'id': key_data['id']
            })
            
        # 最新の鍵を現在の鍵として設定
        instance.current_key = instance.key_chain[-1]['key']
        instance.current_salt = instance.key_chain[-1]['salt']
        
        # シーケンス状態の復元
        instance.sequence = state['sequence']
        instance.last_valid_seq = state['last_valid_seq']
        
        # リプレイウィンドウを初期化
        instance.replay_window_size = instance.config_manager.getint("security", "REPLAY_WINDOW_SIZE", fallback=64)
        instance.replay_window = [False] * instance.replay_window_size
        
        # 鍵ローテーション設定
        instance.key_rotation_interval = instance.config_manager.getint("security", "KEY_ROTATION_INTERVAL", fallback=1000)
        instance.key_rotation_time = instance.config_manager.getint("security", "KEY_ROTATION_TIME", fallback=3600)
        instance.max_key_chain_length = instance.config_manager.getint("security", "MAX_KEY_CHAIN_LENGTH", fallback=3)
        
        # ノンスキャッシュの初期化
        instance._nonce_cache_size = instance.config_manager.getint("security", "NONCE_CACHE_SIZE", fallback=10000)
        instance._nonce_cache = set()
        
        # シーケンスウィンドウの初期化
        instance.window_size = instance.config_manager.getint("security", "SEQUENCE_WINDOW_SIZE", fallback=1024)
        instance.sequence_window = set()
        
        # タイムスタンプの初期化
        instance.last_timestamp = time.time()
        
        # 鍵同期用の状態管理
        instance.key_sync_state = {
            'last_sync': time.time(),
            'pending_rotations': set()
        }
        
        instance.logger.info("SecureTransport restored from key state")
        return instance