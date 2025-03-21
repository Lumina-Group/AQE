import asyncio
from AQE.kex import QuantumSafeKEX
from AQE.transport import SecureTransport
from AQE.configuration import ConfigurationManager

async def initialize_secure_communication(config_file="config.ini"):
    """
    この関数は、量子耐性鍵交換および暗号化／復号のシミュレーションを行うサンプルです。
    
    サンプルでは、以下の流れで通信をシミュレーションしています:
      1. 設定ファイルからセキュリティ関連のパラメータを読み込む。
      2. 量子耐性鍵交換 (QuantumSafeKEX) を利用して認証付き公開鍵 (AWA) を生成する。
      3. 事前に定義した共有鍵を初期鍵として SecureTransport を初期化し、
         メッセージの暗号化／復号を行う。

    Args:
        config_file (str): 設定ファイルのパス。デフォルトでは "config.ini" を使用します。

    Returns:
        bytes: 復号された平文メッセージ。
    """
    # 設定マネージャーの生成
    # 設定ファイルから必要なパラメータを読み込み、各種コンポーネントの初期化に利用します。
    config = ConfigurationManager(config_file)

    # 鍵交換クラスの生成
    # QuantumSafeKEX を利用して、量子耐性の鍵交換に必要な認証付き公開鍵 (AWA) を生成します。
    kex = QuantumSafeKEX(config_manager=config)
    awa = kex.awa  # 生成された AWA は、実際のシナリオでは相手側に送信され、検証されます。

    # 送信側での SecureTransport 初期化
    # ここではサンプルとして、あらかじめ定義された共有鍵 'some_shared_key' を初期鍵として利用します。
    transport = SecureTransport(initial_key=b'some_shared_key', config_manager=config)

    # メッセージの暗号化
    # "Hello, Quantum World!" をバイト列として暗号化し、安全な通信経路用の暗号文を生成します。
    encrypted_message = await transport.encrypt(b"Hello, Quantum World!")
    print("暗号化メッセージ:", encrypted_message)
    
    # 受信側での復号
    # 同一の鍵状態を用いて、暗号化されたメッセージを復号し、元の平文に戻します。
    plaintext = await transport.decrypt(encrypted_message)
    
    return plaintext

# サンプル実行: このスクリプトが直接実行された場合に動作します
if __name__ == "__main__":
    decrypted_message = asyncio.run(initialize_secure_communication())
    print("復号化されたメッセージ:", decrypted_message)