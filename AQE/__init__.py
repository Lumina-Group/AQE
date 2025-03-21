"""
AQE: 量子暗号 (Anti-Quantum Encryption)
ポスト量子時代のための次世代暗号ライブラリ

このパッケージは、量子コンピュータの脅威に対応した暗号機能を提供します。
"""

__version__ = '0.1.0'
__author__ = 'Meow'

# 主要コンポーネントをインポートして公開
from .kex import QuantumSafeKEX
from .transport import SecureTransport
from .configuration import ConfigurationManager
from .errors import (
    SecurityError,
    AuthenticationError,
    DecryptionError,
    ReplayAttackError,
    SignatureVerificationError,
    
)

# 公開するシンボルを指定
__all__ = [
    'QuantumSafeKEX',
    'SecureTransport',
    'ConfigurationManager',
    'SecurityError',
    'AuthenticationError',
    'DecryptionError',
    'ReplayAttackError',
    'SignatureVerificationError'
]
