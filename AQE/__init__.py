"""
AQE: 対量子ハイブリッド暗号 (Anti-Quantum Encryption)
ポスト量子時代のための次世代暗号ライブラリ

このパッケージは、量子コンピュータの脅威に対応した暗号機能を提供します。
"""
import warnings
warnings.filterwarnings("ignore", category=UserWarning) #liboqsとlioqs-pythonのバージョン齟齬による警告を非表示する。
__version__ = '0.1.0'
__author__ = 'Meow'

# --- モジュールからのインポート ---
from .kex import QuantumSafeKEX
from .transport import SecureTransport
from .configuration import ConfigurationManager
from .errors import (
    ErrorSeverity,  # ErrorSeverity を追加
    SecurityError,
    AuthenticationError,
    ProtocolError,
    RateLimitExceededError,
    DecryptionError,
    ReplayAttackError,
    SignatureVerificationError,
    HandshakeTimeoutError,
)
from .logger import (
    SecurityEvent,
    SecurityMetrics,
    EnhancedSecurityLogger,
    setup_logging,
)


# --- 公開するシンボルを指定 ---
__all__ = [
    # Core components
    'QuantumSafeKEX',
    'SecureTransport',
    'ConfigurationManager',

    # Error classes and Severity
    'ErrorSeverity', 
    'SecurityError',
    'AuthenticationError',
    'DecryptionError',
    'ReplayAttackError',
    'SignatureVerificationError', 
    'HandshakeTimeoutError',
    'ProtocolError',
    'RateLimitExceededError',

    # Logging components
    'SecurityEvent',
    'SecurityMetrics',
    'EnhancedSecurityLogger',
    'setup_logging',
]
