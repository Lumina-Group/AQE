import asyncio
from AQE import QuantumSafeKEX, ConfigurationManager
from AQE.transport import SecureTransport

async def perform_key_exchange(config_manager):
    """鍵交換処理をまとめた関数"""
    alice_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=True)
    bob_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=False)

    alice_awa = alice_kex.awa
    bob_awa = bob_kex.awa

    alice_shared_secret, ciphertext = await alice_kex.exchange(bob_awa)
    bob_shared_secret = await bob_kex.decap(ciphertext, alice_awa)

    if alice_shared_secret != bob_shared_secret:
        raise ValueError("Shared secrets do not match!")

    alice_transport = SecureTransport(initial_key=alice_shared_secret, config_manager=config_manager)
    bob_transport = SecureTransport(initial_key=bob_shared_secret, config_manager=config_manager)

    print("🔁 Key has been rotated.")
    return alice_transport, bob_transport

async def main():
    config_manager = ConfigurationManager('config.ini')
    alice_transport, bob_transport = await perform_key_exchange(config_manager)

    message = b"Hello!"
    count = 50
    rotate_interval = 10  # 鍵をローテーションする間隔

    for i in range(1, count + 1):
        # 鍵ローテーション判定
        if i % rotate_interval == 0:
            alice_transport, bob_transport = await perform_key_exchange(config_manager)

        encrypted_msg = await alice_transport.encrypt(message)
        print(f"[{i}] Encrypted message: {encrypted_msg}")
        decrypted_by_bob = await bob_transport.decrypt(encrypted_msg)
        print(f"Alice`s export transport keys {alice_transport.export_key_state()}")

        await asyncio.sleep(1)

        encrypted_msg2 = await alice_transport.encrypt(message)
        decrypted_by_bob2 = await bob_transport.decrypt(encrypted_msg2)

        print(f"[{i}] Decrypted message 1: {decrypted_by_bob.decode()}")
        print(f"[{i}] Decrypted message 2: {decrypted_by_bob2.decode()}")

if __name__ == "__main__":
    asyncio.run(main())
