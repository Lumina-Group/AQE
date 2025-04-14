# AQE (Anti-Quantum Encryption)

[LICENSE](LICENSE)

[日本語](README_JA.md)

**AQE** is a next-generation encryption library designed for the quantum computing era. By combining traditional elliptic curve cryptography with cutting-edge lattice-based cryptography in a hybrid approach, it ensures security both now and in the future.

## ✨ Key Features

- **Quantum-resistant key exchange** - Robust key exchange using the Kyber algorithm
- **Strong encryption** - Fast and secure encryption/decryption with ChaCha20-Poly1305
- **Automatic key rotation** - Regular key updates for enhanced security
- **Advanced protection features**
  - Replay attack prevention
  - Sequence number verification
  - Security event logging
  - Comprehensive metrics tracking

## 🔧 Installation

```bash
pip install .
```

### Dependencies

| Package | Required Version |
|---------|------------------|
| cryptography | >=36.0.0 |
| pycryptodome | >=3.14.0 |
| configparser | >=5.3.0 |
| asyncio | >=3.4.3 |
| liboqs-python | >=0.7.0 |

## 📘 Usage

Here's a basic implementation example:

```python
import asyncio
from AQE import QuantumSafeKEX, ConfigurationManager
from AQE.transport import SecureTransport

async def main():
    # Initialize configuration manager
    config_manager = ConfigurationManager('config.ini')
    
    # Initialize QuantumSafeKEX instances for Alice and Bob
    alice_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=True)
    bob_kex = QuantumSafeKEX(config_manager=config_manager, is_initiator=False)
    
    # Exchange public keys (mutual retrieval)
    alice_awa = alice_kex.awa
    bob_awa = bob_kex.awa
    
    # --- Key exchange process ---
    # Alice generates ciphertext and shared secret (encap)
    alice_shared_secret, ciphertext = await alice_kex.exchange(bob_awa)
    
    # Bob recovers shared secret using received ciphertext (decap)
    bob_shared_secret = await bob_kex.decap(ciphertext, alice_awa)
    
    print(f"Bob's shared secret: {bob_shared_secret.hex()}")
    print(f"Alice's shared secret: {alice_shared_secret.hex()}")
    
    # Verify secret keys match
    if alice_shared_secret != bob_shared_secret:
        raise ValueError("Shared secrets do not match!")
    
    # Initialize SecureTransport
    alice_transport = SecureTransport(initial_key=alice_shared_secret, config_manager=config_manager)
    bob_transport = SecureTransport(initial_key=bob_shared_secret, config_manager=config_manager)
    
    # --- Message encryption/decryption test ---
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

## ⚙️ Configuration

Customize settings via the `config.ini` file:

## 📊 Security Logging and Metrics

AQE provides comprehensive security event logging and metrics tracking.
See the `AQE/logger.py` module for implementation details.

## 👥 Contribution

We welcome contributions to this project!

- If you find any bugs, please create an Issue
- Pull requests for new features and improvements are welcome

## 📜 License

This project is licensed under the [Apache Software License](LICENSE).