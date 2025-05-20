# AQE (Anti-Quantum Encryption) - 対量子ハイブリッド暗号ライブラリ

[![ライセンス](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Pythonバージョン](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![依存関係](https://img.shields.io/badge/dependencies-see%20below-orange)](README.md#-dependencies)

**AQE**は量子コンピュータ時代に対応した次世代暗号ライブラリです。従来の楕円曲線暗号と最先端の格子ベース暗号をハイブリッド方式で組み合わせ、現在および将来にわたるセキュリティを確保します。

## 🌟 主要特徴

- **量子耐性鍵交換** - Kyberアルゴリズムを使用した堅牢な鍵交換
- **強力な暗号化** - ChaCha20-Poly1305による高速かつ安全な暗号化/復号
- **高度な保護機能**
  - リプレイ攻撃防止
  - シーケンス番号検証
  - セキュリティイベントロギング
  - 包括的なメトリクス追跡
- **相互認証** - 通信相手の正当性を確認
- **前方秘匿性** - セッション鍵の安全性を確保

## 🚀 インストール

```bash
pip install AQE
```

### 依存関係

| パッケージ | 必要バージョン |
|------------|----------------|
| cryptography | >=36.0.0 |
| pycryptodome | >=3.14.0 |
| configparser | >=5.3.0 |
| asyncio | >=3.4.3 |
| liboqs-python | >=0.7.0 |

## 📚 基本的な使い方

以下は基本的な実装例です：

```python
import asyncio
from AQE import QuantumSafeKEX, ConfigurationManager
from AQE.transport import SecureTransport

async def main():
    # 設定マネージャーの初期化
    config_manager = ConfigurationManager('config.ini')
    
    # AliceとBobのQuantumSafeKEXインスタンスを初期化
    alice_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=True)
    bob_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=False)
    
    # 公開鍵の交換（相互取得）
    alice_awa = alice_kex.awa
    bob_awa = bob_kex.awa
    
    # --- 鍵交換プロセス ---
    # Aliceが暗号文と共有秘密を生成（encap）
    alice_shared_secret, ciphertext = await alice_kex.exchange(bob_awa)
    
    # Bobが受信した暗号文から共有秘密を復元（decap）
    bob_shared_secret = await bob_kex.decap(ciphertext, alice_awa)
    
    print(f"Bobの共有秘密: {bob_shared_secret.hex()}")
    print(f"Aliceの共有秘密: {alice_shared_secret.hex()}")
    
    # 秘密鍵が一致することを確認
    if alice_shared_secret != bob_shared_secret:
        raise ValueError("共有秘密が一致しません！")
    
    # SecureTransportの初期化
    alice_transport = SecureTransport(initial_key=alice_shared_secret, config_manager=config_manager)
    bob_transport = SecureTransport(initial_key=bob_shared_secret, config_manager=config_manager)
    
    # --- メッセージ暗号化/復号テスト ---
    try:
        message = b"こんにちは！"
        encrypted_msg = await alice_transport.encrypt(message)
        decrypted_by_bob = await bob_transport.decrypt(encrypted_msg)
        
        encrypted_msg2 = await alice_transport.encrypt(message)
        decrypted_by_bob2 = await bob_transport.decrypt(encrypted_msg2)
        
        print(f"復号されたメッセージ1: {decrypted_by_bob.decode()}")
        print(f"復号されたメッセージ2: {decrypted_by_bob2.decode()}")
    except Exception as e:
        print(f"エラーが発生しました: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
```
また、QuantumSafeKEXクラスのみを利用して秘密鍵生成として利用することも可能です。：
```python
import asyncio
from AQE import QuantumSafeKEX, ConfigurationManager
from AQE.transport import SecureTransport

async def main():
    # 設定マネージャーの初期化
    config_manager = ConfigurationManager('config.ini')
    
    # AliceとBobのQuantumSafeKEXインスタンスを初期化
    alice_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=True)
    bob_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=False)
    
    # 公開鍵の交換（相互取得）
    alice_awa = alice_kex.awa
    bob_awa = bob_kex.awa
    
    # --- 鍵交換プロセス ---
    # Aliceが暗号文と共有秘密を生成（encap）
    alice_shared_secret, ciphertext = await alice_kex.exchange(bob_awa)
    
    # Bobが受信した暗号文から共有秘密を復元（decap）
    bob_shared_secret = await bob_kex.decap(ciphertext, alice_awa)
    
    print(f"Bobの共有秘密: {bob_shared_secret.hex()}")
    print(f"Aliceの共有秘密: {alice_shared_secret.hex()}")
    
    # 秘密鍵が一致することを確認
    if alice_shared_secret != bob_shared_secret:
        raise ValueError("共有秘密が一致しません！")
```

## ⚙️ 設定

`config.ini`ファイルで設定をカスタマイズできます：

```ini
[KEX]
kex_alg_name = Kyber1024
sig_alg_name = Dilithium3
timestamp_window = 60
rate_limit_window = 60
rate_limit_max_attempts = 5

[Transport]
chacha_key_size = 32
nonce_size = 12
connection_timeout = 300
sequence_window_size = 100
replay_cache_size = 1000
```

## 🔒 セキュリティアーキテクチャ

AQEは2層のセキュリティアーキテクチャを採用しています：

1. **QuantumSafeKEX (鍵交換層)**
   - 古典暗号(X25519)と量子耐性暗号(Kyber)をハイブリッド方式で組み合わせ
   - Dilithium署名による通信相手の認証
   - HKDFを使用した安全な鍵導出

2. **SecureTransport (トランスポート層)**
   - ChaCha20-Poly1305による認証付き暗号化
   - シーケンス番号とタイムスタンプによるリプレイ攻撃防止
   - Nonce管理による暗号化の安全性確保

## 📊 セキュリティロギングとメトリクス

AQEは包括的なセキュリティイベントロギングとメトリクス追跡機能を提供します。
詳細は`AQE/logger.py`モジュールを参照してください。

## 🤝 貢献

このプロジェクトへの貢献を歓迎します！

- バグを見つけた場合はIssueを作成してください
- 新機能や改善のプルリクエストも歓迎します

## 📜 ライセンス

このプロジェクトは[Apache Software License](LICENSE)の下でライセンスされています。