import asyncio
import logging
from AQE.kex import QuantumSafeKEX
from AQE.transport import SecureTransport
from AQE.configuration import ConfigurationManager

# ロギングの設定
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def initialize_secure_communication(config_file="config.ini"):
    """
    2者間の鍵交換と暗号化／復号をシミュレーションするサンプルコードです。
    この例では、量子耐性鍵交換 (QuantumSafeKEX) を用いて、Alice と Bob の間で
    安全な通信路を確立し、暗号化／復号処理を行います。

    Args:
        config_file (str): 設定ファイルのパス。サンプルでは "config.ini" を使用。

    Returns:
        bytes: 復号された平文メッセージ。
    """
    logger.info("Initializing secure communication...")
    
    # 設定マネージャーを生成
    logger.debug(f"Loading configuration from {config_file}")
    config = ConfigurationManager(config_file)

    # Alice と Bob の鍵交換インスタンスを生成
    logger.debug("Creating QuantumSafeKEX instances for Alice and Bob")
    alice_kex = QuantumSafeKEX(config_manager=config)
    bob_kex = QuantumSafeKEX(config_manager=config)

    # 各エンティティの AWA (認証付き公開鍵) を取得
    logger.debug("Retrieving AWA for Alice and Bob")
    alice_awa = alice_kex.awa  # Alice の AWA
    bob_awa = bob_kex.awa      # Bob の AWA

    # --- ここから鍵交換のシミュレーション ---
    logger.info("Simulating key exchange between Alice and Bob")
    alice_shared_secret, ciphertext = await alice_kex.exchange(bob_awa)
    logger.debug(f"Alice's shared secret: {alice_shared_secret}")
    logger.debug(f"Ciphertext from key exchange: {ciphertext}")
    # ----------------------------------------------------------------

    # 共有秘密鍵を初期鍵として利用して、SecureTransport を初期化します。
    logger.debug("Initializing SecureTransport for Alice")
    alice_transport = SecureTransport(initial_key=alice_shared_secret, config_manager=config)
    bob_transport = SecureTransport(initial_key=alice_shared_secret, config_manager=config)

    # --- メッセージの暗号化／復号のシミュレーション ---
    logger.info("Simulating message encryption and decryption")
    for i in range(50):
     # Alice がメッセージを暗号化します
     plaintext_message = b"Hello, Quantum World!"
     encrypted_message = await alice_transport.encrypt(plaintext_message)


     # Bob が受信したメッセージを復号化します
     plaintext = await bob_transport.decrypt(encrypted_message)
     logger.debug(f"Bob's decrypted message: {plaintext}")

     # サンプルとして、Alice 自身も暗号化したメッセージを復号化できることを確認します
     alice_plaintext = await alice_transport.decrypt(encrypted_message)
     logger.debug(f"Alice's decrypted message: {alice_plaintext}")
     # ----------------------------------------------------------------

    return plaintext


# サンプル実行: このスクリプトが直接実行された場合にのみ動作します
if __name__ == "__main__":
    logger.info("Starting secure communication example")
    decrypted_message = asyncio.run(initialize_secure_communication())

