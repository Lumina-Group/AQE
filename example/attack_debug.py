import asyncio
from AQE import QuantumSafeKEX, ConfigurationManager
from AQE.transport import SecureTransport
from AQE.errors import ReplayAttackError, DecryptionError, RateLimitExceededError, SignatureVerificationError, HandshakeTimeoutError

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

async def simulate_replay_attack(transport):
    message = b"Replay Attack Test"
    encrypted_msg = await transport.encrypt(message)
    try:
        # 同じメッセージを2回復号してリプレイ攻撃をシミュレート
        await transport.decrypt(encrypted_msg)
        print(f"Alice`s export transport keys {transport.export_key_state()}")
        await transport.decrypt(encrypted_msg)
        print(f"Alice`s export transport keys {transport.export_key_state()}")
    except ReplayAttackError as e:
        print(f"Replay attack detected: {e}")
    else:
        print("Replay attack was not detected.")

async def simulate_decryption_error(transport):
    message = b"Decryption Error Test"
    encrypted_msg = await transport.encrypt(message)
    # 暗号文を改ざんして復号エラーをシミュレート
    tampered_msg = encrypted_msg[:-1] + b'X'
    try:
        await transport.decrypt(tampered_msg)
    except DecryptionError as e:
        print(f"Decryption error detected: {e}")
    else:
        print("Decryption error was not detected.")

async def simulate_rate_limit(transport):
    message = b"Rate Limit Test"
    try:
        # 短時間に大量のリクエストを送信してレート制限をシミュレート
        tasks = [transport.encrypt(message) for _ in range(100)]
        await asyncio.gather(*tasks)
    except RateLimitExceededError as e:
        print(f"Rate limit exceeded: {e}")
    else:
        print("Rate limit was not exceeded.")

async def simulate_signature_verification_error(transport, kex):
    """署名検証エラーをシミュレートする関数"""
    try:
        # 仮の改ざんされたAWAデータを作成
        tampered_awa = kex.awa[:-1] + b'X'
        await kex.verify_peer_awa(tampered_awa)
    except SignatureVerificationError as e:
        print(f"Signature verification error detected: {e}")
    else:
        print("Signature verification error was not detected.")

async def simulate_handshake_timeout(a_kex,kex):
    """ハンドシェイクタイムアウトをシミュレートする関数"""
    try:
        # タイムアウトを強制的に短く設定
        original_timeout = kex.config_manager.getint("timeouts", "HANDSHAKE_TIMEOUT", fallback=30)
        kex.config_manager.set("timeouts", "HANDSHAKE_TIMEOUT", "1")
        await asyncio.sleep(2)  # タイムアウトを待つために少し待つ
        _, ciphertext = await a_kex.exchange(kex.awa)
        await kex.decap(ciphertext, a_kex.awa)
        # 元のタイムアウト設定に戻す
        kex.config_manager.set("timeouts", "HANDSHAKE_TIMEOUT", str(original_timeout))
    except HandshakeTimeoutError as e:
        print(f"Handshake timeout detected: {e}")
    else:
        print("Handshake timeout was not detected.")

async def main():
    config_manager = ConfigurationManager('config.ini')
    alice_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=True)
    bob_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=False)
    alice_transport, bob_transport = await perform_key_exchange(config_manager)

    # print("\nTesting replay attack...")
    # await simulate_replay_attack(bob_transport)

    print("\nTesting decryption error...")
    await simulate_decryption_error(bob_transport)

    print("\nTesting rate limit...")
    await simulate_rate_limit(bob_transport)

    print("\nTesting signature verification error...")
    await simulate_signature_verification_error(bob_transport, alice_kex)

    print("\nTesting handshake timeout...")
    await simulate_handshake_timeout(alice_kex,bob_kex)

    # message = b"Hello!"
    # count = 50
    # rotate_interval = 10  # 鍵をローテーションする間隔

    # for i in range(1, count + 1):
    #     # 鍵ローテーション判定
    #     if i % rotate_interval == 0:
    #         alice_transport, bob_transport = await perform_key_exchange(config_manager)

    #     encrypted_msg = await alice_transport.encrypt(message)
    #     print(f"[{i}] Encrypted message: {encrypted_msg}")
    #     decrypted_by_bob = await bob_transport.decrypt(encrypted_msg)

    #     await asyncio.sleep(1)

    #     encrypted_msg2 = await alice_transport.encrypt(message)
    #     decrypted_by_bob2 = await bob_transport.decrypt(encrypted_msg2)

    #     print(f"[{i}] Decrypted message 1: {decrypted_by_bob.decode()}")
    #     print(f"[{i}] Decrypted message 2: {decrypted_by_bob2.decode()}")

if __name__ == "__main__":
    asyncio.run(main())
