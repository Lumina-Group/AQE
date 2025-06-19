# AQE 使い方ガイド

このドキュメントでは、AQE ライブラリの基本的な利用方法を日本語で解説します。

## セットアップ

```
python -m pip install .
```

## 鍵交換の実行

```python
import asyncio
from AQE import QuantumSafeKEX, ConfigurationManager

async def main():
    config_manager = ConfigurationManager('config.ini')
    alice = QuantumSafeKEX(config_manager=config_manager, is_initiator=True)
    bob = QuantumSafeKEX(config_manager=config_manager, is_initiator=False)

    alice_awa = alice.awa
    bob_awa = bob.awa

    shared_secret_alice, ciphertext = await alice.exchange(bob_awa)
    shared_secret_bob = await bob.decap(ciphertext, alice_awa)

    assert shared_secret_alice == shared_secret_bob

asyncio.run(main())
```

## 暗号化トランスポートの使用

```python
from AQE.transport import SecureTransport

transport = SecureTransport(initial_key=shared_secret_alice, config_manager=config_manager)

cipher = await transport.encrypt(b"hello")
plain = await transport.decrypt(cipher)
```

より詳細な例は `example/` ディレクトリを参照してください。
