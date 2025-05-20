import enum
import traceback
import time
from typing import Dict, Any, Optional

class ErrorSeverity(enum.Enum):
    """
    セキュリティエラーの重大度を定義する列挙型
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SecurityError(Exception):
    """
    セキュリティ関連の基本エラークラス
    """
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 details: Optional[Dict[str, Any]] = None, save_traceback: bool = False):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.details = details or {}
        self.timestamp = time.time()
        self.traceback = traceback.format_exc() if save_traceback else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.__class__.__name__,
            'message': self.message,
            'severity': self.severity.value,
            'details': self.details,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

class AuthenticationError(SecurityError):
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.HIGH,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, severity, details)

class ProtocolError(SecurityError):
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, severity, details)

class HandshakeTimeoutError(SecurityError):
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.HIGH,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, severity, details)

class RateLimitExceededError(SecurityError):
    def __init__(self, message: str, attempts: int, max_attempts: int, window: int,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 details: Optional[Dict[str, Any]] = None):
        details = details or {}
        details.update({
            'attempts': attempts,
            'max_attempts': max_attempts,
            'window_seconds': window
        })
        super().__init__(message, severity, details)

class ConfigurationError(SecurityError):
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.CRITICAL,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, severity, details)

class DecryptionError(SecurityError):
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.HIGH,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, severity, details)

class InvalidNonceError(DecryptionError):
    pass

class AuthenticationTagMismatchError(DecryptionError):
    pass

class ReplayAttackError(SecurityError):
    def __init__(self, message: str, sequence: Optional[int] = None,
                 severity: ErrorSeverity = ErrorSeverity.CRITICAL,
                 details: Optional[Dict[str, Any]] = None):
        details = details or {}
        if sequence is not None:
            details['sequence'] = sequence
        super().__init__(message, severity, details)

class CryptoOperationError(SecurityError):
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.HIGH,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, severity, details)

class SignatureVerificationError(AuthenticationError):
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.CRITICAL,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, severity, details)
