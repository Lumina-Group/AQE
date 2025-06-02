import asyncio
from AQE import QuantumSafeKEX, ConfigurationManager
from AQE.transport import SecureTransport

async def main():
    # AQE設定マネージャーの初期化
    config_manager = ConfigurationManager('config.ini')

    # Alice と Bob の QuantumSafeKEX インスタンスの初期化
    alice_kex = QuantumSafeKEX(config_manager=config_manager,is_initiator=True)
    bob_kex = QuantumSafeKEX(config_manager=config_manager,is_initiator=False)

    # 公開鍵の交換（相互取得）
    alice_awa = alice_kex.awa
    bob_awa = bob_kex.awa

    # --- 鍵交換プロセス ---
    # Alice が暗号文と共有秘密鍵を生成（encap）
    alice_shared_secret, ciphertext = await alice_kex.exchange(bob_awa)
    
    #鍵のエクスポート検証
    print(f"Alice`s export keys {alice_kex.export_keys()}")



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

    #transportの鍵のエクスポート検証
    print(f"Alice`s export transport keys {alice_transport.export_key_state()}")

    # --- メッセージ暗号化・復号テスト ---
    try:
        message = b"Hello!"
        encrypted_msg = await alice_transport.encrypt(message)
        print(f"Encrypted message: {encrypted_msg}")
        decrypted_by_bob = await bob_transport.decrypt(encrypted_msg)
        print(f"Decrypted message: {decrypted_by_bob.decode()}")

        encrypted_msg2 = await alice_transport.encrypt(message)
        decrypted_by_bob2 = await bob_transport.decrypt(encrypted_msg2)

        print(f"Decrypted message 1: {decrypted_by_bob.decode()}")
        print(f"Decrypted message 2: {decrypted_by_bob2.decode()}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())