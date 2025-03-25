# AQE: Anti-Quantum Encryption
[日本語](/README_JA.md)
**AQE** is a next-generation quantum-resistant encryption library designed for the post-quantum era. While conventional cryptographic libraries face the risk of being broken by quantum computers, AQE provides practical protection that is available right now.

---

## 🚀 Key Features of AQE

| Feature                  | AQE                                | Conventional Encryption Libraries    | Other Post-Quantum Encryption Libraries |
|--------------------------|------------------------------------|--------------------------------------|-----------------------------------------|
| **Quantum Resistance**   | ✅ Complete hybrid protection      | ❌ Vulnerable to quantum attacks     | ⚠️ Partial protection                   |
| **Performance**          | ✅ Optimized for practical use     | ✅ High-speed                        | ❌ Slow and cumbersome                  |
| **Ease of Use**          | ✅ Simple API                      | ⚠️ Complex configuration required    | ❌ Experimental interfaces              |
| **Hybrid Encryption**    | ✅ Combines existing techniques    | ❌ Traditional cryptography only     | ⚠️ Limited hybridization                |
| **Automatic Key Management** | ✅ Supports key rotation and lifecycle management | ❌ Requires manual management | ⚠️ Basic management only           |
| **Comprehensive Security**  | ✅ Multi-layer defense             | ⚠️ Algorithm-focused                 | ⚠️ Limited defenses                     |

---

## 🛡️ Quantum-Ready Protection

```python
# Generate quantum-resistant encryption in just a few lines
kex = QuantumSafeKEX()
transport = SecureTransport(await kex.exchange(peer_awa)[0])
encrypted = await transport.encrypt(your_data)
```

---

## 🔑 Main Features

- **Quantum-Resistant Encryption**: Implements NIST PQC final candidates (Kyber1024, Dilithium3).
- **Hybrid Encryption**: Combines traditional ECC (X25519) with post-quantum cryptography.
- **Automatic Key Management**: Configurable key rotation and management at set intervals.
- **High-Speed Performance**: Efficient data protection via ChaCha20-Poly1305 encryption.
- **Forward Secrecy**: Minimizes risk of key compromise through automatic key rotation.
- **Robust Attack Protections**:
  - Defense against timing attacks
  - Side-channel resistance
  - Replay attack prevention
  - Tamper detection

---

## 📊 Performance Design

- **Efficient Key Exchange**: Hybrid method using Kyber1024 and X25519.
- **Fast Encryption**: Efficient data protection with ChaCha20-Poly1305.
- **Optimized Implementation**: Support for asynchronous operations in critical processes.

---

## 💻 Installation

### Requirements
* Python 3.7+
* liboqs - Open Quantum Safe library
* pycryptodome
* cryptography

```bash
# Install AQE
pip install AQE
```

---

## 🚦 Simple Usage Example

```python
import asyncio
from AQE.kex import QuantumSafeKEX
from AQE.transport import SecureTransport

async def secure_communication():
    kex = QuantumSafeKEX()
    transport = SecureTransport(await kex.exchange(peer_awa)[0])
    encrypted = await transport.encrypt(b"Hello, Quantum World!")
    decrypted = await transport.decrypt(encrypted)
    print("Decrypted message:", decrypted)

if __name__ == "__main__":
    asyncio.run(secure_communication())
```

---

## 🔧 Configuration Options

```ini
[kex]
KEX_ALG = Kyber1024  # NIST PQC final candidate
EPHEMERAL_KEY_LIFETIME = 3600  # Rotate key every 1 hour

[signature]
SIG_ALG = Dilithium3  # NIST PQC final candidate
SIG_VERIFY_TIMEOUT = 5  # Prevent timing attacks

[security]
KEY_ROTATION_INTERVAL = 1000  # Exchange key every 1000 messages
TIMESTAMP_WINDOW = 300  # Prevent replay attacks (in seconds)
```

---

## 🏢 Industry Use Cases

- **Finance**: Protect transactions with quantum-resistant protocols.
- **Healthcare**: Secure patient data for the long term.
- **Government Agencies**: Comply with post-quantum regulatory requirements.
- **IoT**: Apply lightweight yet robust encryption techniques.
- **Military/Defense**: Safeguard mission-critical systems.

---

## 🤝 Commercial Support

Commercial support for enterprises is also available.  
For more details, please contact: `example.example.1.mm@icloud.com`.

---

## 🤝 Contributions

Contributions to the project are welcome.  
Feel free to report issues, request features, or submit pull requests.

---

## 📝 License

Apache License 2.0 - For details, see [LICENSE](LICENSE).
