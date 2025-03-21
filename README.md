# AQE: 量子暗号 (Anti-Quantum Encryption)

**AQE** は、ポスト量子時代に向けた次世代の量子耐性暗号ライブラリです。
従来の暗号ライブラリが量子コンピュータによって破られるリスクを抱えているのに対し、AQE は今すぐ実用可能な保護を提供します。

---

## 🚀 AQE の特長

| 機能 | AQE | 従来の暗号ライブラリ | 他のポスト量子暗号ライブラリ |
|------|-----|------------------|------------------|
| **量子耐性** | ✅ 完全なハイブリッド保護 | ❌ 量子攻撃に脆弱 | ⚠️ 部分的な保護 |
| **パフォーマンス** | ✅ 実用向けに最適化 | ✅ 高速 | ❌ 遅く、扱いにくい |
| **使いやすさ** | ✅ シンプルな API | ⚠️ 設定が複雑 | ❌ 実験的なインターフェース |
| **ハイブリッド暗号** | ✅ 既存技術との併用 | ❌ 従来暗号のみ | ⚠️ 限定的なハイブリッド化 |
| **自動キー管理** | ✅ ローテーションとライフサイクル管理 | ❌ 手動管理が必要 | ⚠️ 基本的な管理のみ |
| **包括的なセキュリティ** | ✅ 多層防御 | ⚠️ アルゴリズム中心 | ⚠️ 限定的な防御 |

---

## 🛡️ 量子対応の保護

```python
# たった数行で量子耐性暗号を生成
kex = QuantumSafeKEX()
transport = SecureTransport(await kex.exchange(peer_awa)[0])
encrypted = await transport.encrypt(your_data)
```

---

## 🔑 主な機能

- **量子耐性暗号**：NIST PQC 最終候補 (Kyber1024, Dilithium3) を実装
- **ハイブリッド暗号**：従来の ECC (X25519) と PQC を組み合わせた防御
- **自動鍵管理**：設定可能な間隔での鍵のローテーションと管理
- **高速パフォーマンス**：ChaCha20-Poly1305 による高速暗号化
- **前方秘匿性**：キーの自動ローテーションで漏洩リスクを最小化
- **強力な攻撃対策**：
  - タイミング攻撃防御
  - サイドチャネル耐性
  - リプレイ攻撃防止
  - 改ざん検知機能

---

## 📊 パフォーマンス設計

- **効率的な鍵交換**：Kyber1024 と X25519 のハイブリッド方式
- **高速な暗号化**：ChaCha20-Poly1305 による効率的なデータ保護
- **最適化された実装**：重要な処理での非同期操作のサポート

---

## 💻 インストール方法

### 必要環境
* Python 3.7+
* liboqs - Open Quantum Safe ライブラリ
* pycryptodome
* cryptography
```bash
# AQE をインストール
pip install AQE
```

---

## 🚦 簡単な使用例

```python
import asyncio
from AQE.kex import QuantumSafeKEX
from AQE.transport import SecureTransport

async def secure_communication():
    kex = QuantumSafeKEX()
    transport = SecureTransport(await kex.exchange(peer_awa)[0])
    encrypted = await transport.encrypt(b"Hello, Quantum World!")
    decrypted = await transport.decrypt(encrypted)
    print("復号化されたメッセージ:", decrypted)

if __name__ == "__main__":
    asyncio.run(secure_communication())
```

---

## 🔧 設定オプション

```ini
[kex]
KEX_ALG = Kyber1024  # NIST PQC 最終候補
EPHEMERAL_KEY_LIFETIME = 3600  # 1 時間ごとに鍵をローテーション

[signature]
SIG_ALG = Dilithium3  # NIST PQC 最終候補
SIG_VERIFY_TIMEOUT = 5  # タイミング攻撃防止

[security]
KEY_ROTATION_INTERVAL = 1000  # 1000 メッセージごとに鍵交換
TIMESTAMP_WINDOW = 300  # リプレイ攻撃防止（秒）
```

---

## 🏢 業界別の活用事例

- **金融**：量子耐性プロトコルで取引を保護
- **医療**：患者データを将来にわたって安全に管理
- **政府機関**：ポスト量子規制要件に対応
- **IoT**：軽量かつ強力な暗号技術を適用
- **軍事/防衛**：ミッション・クリティカルなシステムを保護

---

## 🤝 商用サポート

企業向けのサポートも提供しています。  
詳細は `example.example.1.mm@icloud.com` までお問い合わせください。

---

## 🤝 コントリビューション

プロジェクトへの貢献を歓迎します。issuesの報告や機能リクエスト、プルリクエストなどお待ちしています。

---

## 📝 ライセンス

Apache License 2.0 - 詳細は [LICENSE](LICENSE) を参照してください。