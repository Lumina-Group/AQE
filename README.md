
[日本語](README_JA.md)

# AQE (Anti-Quantum Encryption) - Quantum-Resistant Hybrid Encryption Library

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-see%20below-orange)](README.md#-dependencies)

**AQE** is a next-generation encryption library designed for the quantum computing era. It combines traditional elliptic curve cryptography with cutting-edge lattice-based cryptography in a hybrid approach to ensure security both now and in the future.

## 🌟 Key Features

- **Quantum-Resistant Key Exchange** - Robust key exchange using Kyber algorithm
- **Powerful Encryption** - Fast and secure encryption/decryption with ChaCha20-Poly1305
- **Advanced Protection Features**
  - Replay attack prevention
  - Sequence number verification
  - Security event logging
  - Comprehensive metrics tracking
- **Mutual Authentication** - Verify communication peer authenticity
- **Forward Secrecy** - Ensures session key security

## 🚀 Installation

```bash
pip install AQE
```

### Dependencies

| Package | Required Version |
|---------|------------------|
| cryptography | >=36.0.0 |
| pycryptodome | >=3.14.0 |
| configparser | >=5.3.0 |
| asyncio | >=3.4.3 |
| [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) | >=0.7.0 |

## 📚 Basic Usage

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
    
    # Exchange public keys (mutual acquisition)
    alice_awa = alice_kex.awa
    bob_awa = bob_kex.awa
    
    # --- Key exchange process ---
    # Alice generates ciphertext and shared secret (encap)
    alice_shared_secret, ciphertext = await alice_kex.exchange(bob_awa)
    
    # Bob recovers shared secret from received ciphertext (decap)
    bob_shared_secret = await bob_kex.decap(ciphertext, alice_awa)
    
    print(f"Bob's shared secret: {bob_shared_secret.hex()}")
    print(f"Alice's shared secret: {alice_shared_secret.hex()}")
    
    # Verify secret keys match
    if alice_shared_secret != bob_shared_secret:
        raise ValueError("Shared secrets don't match!")
    
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
        
        print(f"Decrypted message1: {decrypted_by_bob.decode()}")
        print(f"Decrypted message2: {decrypted_by_bob2.decode()}")
    except Exception as e:
        print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
```

## ⚙️ Configuration

Customize settings in the `config.ini` file:

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

## 🔒 Security Architecture

AQE employs a two-layer security architecture:

1. **QuantumSafeKEX (Key Exchange Layer)**
   - Hybrid combination of classical cryptography (X25519) and quantum-resistant cryptography (Kyber)
   - Communication peer authentication via Dilithium signatures
   - Secure key derivation using HKDF

2. **SecureTransport (Transport Layer)**
   - Authenticated encryption with ChaCha20-Poly1305
   - Replay attack prevention via sequence numbers and timestamps
   - Encryption security ensured through nonce management

## 📊 Security Logging and Metrics

AQE provides comprehensive security event logging and metrics tracking.
See the `AQE/logger.py` module for details.

## 🤝 Contributing

Contributions to this project are welcome!

- Create an Issue if you find any bugs
- Pull requests for new features or improvements are also welcome

## 📜 License

This project is licensed under the [Apache Software License](LICENSE).
