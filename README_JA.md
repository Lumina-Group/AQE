# AQE (Anti-Quantum Encryption)

[LICENSE](LICENSE)

**AQE** は量子コンピュータ時代に備えた次世代暗号ライブラリです。従来の楕円曲線暗号と最新の格子ベース暗号を組み合わせたハイブリッドアプローチにより、現在から将来にわたるセキュリティを確保します。

## ✨ 主な機能

- **量子耐性のある鍵交換** - Kyberアルゴリズムによる堅牢な鍵交換
- **強力な暗号化** - ChaCha20-Poly1305による高速かつ安全な暗号化/復号化
- **自動鍵ローテーション** - セキュリティを強化する定期的な鍵の更新
- **高度な保護機能**
  - リプレイ攻撃対策
  - シーケンス番号検証
  - セキュリティイベントのロギング
  - 包括的なメトリクス追跡

## 🔧 インストール

```bash
pip install .
```

### 依存パッケージ

| パッケージ | 必要バージョン |
|------------|----------------|
| cryptography | >=36.0.0 |
| pycryptodome | >=3.14.0 |
| configparser | >=5.3.0 |
| asyncio | >=3.4.3 |
| liboqs-python | >=0.7.0 |

## 📘 使用方法

以下は基本的な実装例です：

```python
import asyncio
from AQE import QuantumSafeKEX, ConfigurationManager
from AQE.transport import SecureTransport

async def main():
    # 設定マネージャーの初期化
    config_manager = ConfigurationManager('config.ini')
    
    # Alice と Bob の QuantumSafeKEX インスタンスの初期化
    alice_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=True)
    bob_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=False)
    
    # 公開鍵の交換（相互取得）
    alice_awa = alice_kex.awa
    bob_awa = bob_kex.awa
    
    # --- 鍵交換プロセス ---
    # Alice が暗号文と共有秘密鍵を生成（encap）
    alice_shared_secret, ciphertext = await alice_kex.exchange(bob_awa)
    
    # Bob は受け取った暗号文を使って共有秘密鍵を復元（decap）
    bob_shared_secret = await bob_kex.decap(ciphertext, alice_awa)
    
    print(f"Bob's shared secret: {bob_shared_secret.hex()}")
    print(f"Alice's shared secret: {alice_shared_secret.hex()}")
    
    # 秘密鍵が一致することを確認
    if alice_shared_secret != bob_shared_secret:
        raise ValueError("Shared secrets do not match!")
    
    # SecureTransport を初期化
    alice_transport = SecureTransport(initial_key=alice_shared_secret, config_manager=config_manager)
    bob_transport = SecureTransport(initial_key=bob_shared_secret, config_manager=config_manager)
    
    # --- メッセージ暗号化・復号テスト ---
    try:
        message = b"Hello!"
        encrypted_msg = await alice_transport.encrypt(message)
        decrypted_by_bob = await bob_transport.decrypt(encrypted_msg)
        
        encrypted_msg2 = await alice_transport.encrypt(message)
        decrypted_by_bob2 = await bob_transport.decrypt(encrypted_msg2)
        
        print(f"Decrypted message 1: {decrypted_by_bob.decode()}")
        print(f"Decrypted message 2: {decrypted_by_bob2.decode()}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
```

## ⚙️ 設定

`config.ini` ファイルで設定をカスタマイズできます：

## 📊 セキュリティロギングとメトリクス

AQEは包括的なセキュリティイベントのロギングとメトリクス追跡機能を提供しています。
実装の詳細については `AQE/logger.py` モジュールを参照してください。

## 👥 コントリビューション

このプロジェクトへの貢献を歓迎します！

- バグを発見した場合は Issue を作成してください
- 機能追加や改善のためのプルリクエストをお待ちしています

## 📜 ライセンス

このプロジェクトは [Apache Software License](LICENSE) の下でライセンスされています。