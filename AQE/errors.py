import enum
import traceback
import time
from typing import Dict, Any, Optional

class ErrorSeverity(enum.Enum):
    """
    セキュリティエラーの重大度を定義する列挙型です。
    
    Attributes:
        LOW: 低重大度のエラー。情報提供目的で、即時対応は不要。
        MEDIUM: 中程度の重大度のエラー。監視が必要だが緊急ではない。
        HIGH: 高重大度のエラー。早急な調査と対応が必要。
        CRITICAL: 極めて重大なエラー。即時対応が必要で、セキュリティ侵害の可能性あり。
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SecurityError(Exception):
    """
    セキュリティ関連のエラーの基本クラスです。
    すべてのセキュリティエラーはこのクラスを継承します。
    
    Attributes:
        message: エラーメッセージ
        severity: エラーの重大度（ErrorSeverityの値）
        details: エラーに関する追加情報の辞書
        timestamp: エラー発生時のタイムスタンプ
        traceback: エラー発生時のスタックトレース
    """
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM, details: Dict[str, Any] = None):
        """
        SecurityErrorを初期化します。
        
        Args:
            message: エラーメッセージ
            severity: エラーの重大度（デフォルトはMEDIUM）
            details: エラーに関する詳細情報を含む辞書（オプション）
        """
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.details = details or {}
        self.timestamp = time.time()
        self.traceback = traceback.format_exc()
        
    def to_dict(self) -> Dict[str, Any]:
        """
        エラー情報を辞書形式で返します。
        ログ記録や診断目的で利用できます。
        
        Returns:
            Dict[str, Any]: エラー情報を含む辞書
        """
        return {
            'type': self.__class__.__name__,
            'message': self.message,
            'severity': self.severity.value,
            'details': self.details,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

class AuthenticationError(SecurityError):
    """
    認証に関連するエラーを表すクラスです。
    無効な認証情報、アクセス拒否などの場合に使用します。
    """
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.HIGH, details: Dict[str, Any] = None):
        """
        AuthenticationErrorを初期化します。
        
        Args:
            message: エラーメッセージ
            severity: エラーの重大度（デフォルトはHIGH）
            details: エラーに関する詳細情報を含む辞書（オプション）
        """
        super().__init__(message, severity, details)

class ProtocolError(SecurityError):
    """
    プロトコルに関連するエラーを表すクラスです。
    プロトコルの仕様に違反した通信や操作が検出された場合に使用します。
    """
    pass

class RateLimitExceeded(SecurityError):
    """
    レート制限超過エラーを表すクラスです。
    短時間に多数のリクエストや操作が検出された場合に使用します。
    """
    def __init__(self, message: str, attempts: int, max_attempts: int, window: int, 
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM, details: Dict[str, Any] = None):
        """
        RateLimitExceededを初期化します。
        
        Args:
            message: エラーメッセージ
            attempts: 検出された試行回数
            max_attempts: 許容される最大試行回数
            window: 監視ウィンドウのサイズ（秒）
            severity: エラーの重大度（デフォルトはMEDIUM）
            details: エラーに関する詳細情報を含む辞書（オプション）
        """
        details = details or {}
        details.update({
            'attempts': attempts,
            'max_attempts': max_attempts,
            'window_seconds': window
        })
        super().__init__(message, severity, details)

class DecryptionError(SecurityError):
    """
    復号に関連するエラーを表すクラスです。
    暗号文の復号に失敗した場合に使用します。
    """
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.HIGH, details: Dict[str, Any] = None):
        """
        DecryptionErrorを初期化します。
        
        Args:
            message: エラーメッセージ
            severity: エラーの重大度（デフォルトはHIGH）
            details: エラーに関する詳細情報を含む辞書（オプション）
        """
        super().__init__(message, severity, details)

class InvalidNonceError(DecryptionError):
    """
    無効なノンスに関連するエラーを表すクラスです。
    暗号化や復号で使用されるノンスの形式や値に問題がある場合に使用します。
    """
    pass

class AuthenticationTagMismatchError(DecryptionError):
    """
    認証タグの不一致エラーを表すクラスです。
    AEAD暗号方式で復号時に認証タグの検証に失敗した場合に使用します。
    これは通常、データが改ざんされた可能性を示します。
    """
    pass

class ReplayAttackError(SecurityError):
    """
    リプレイ攻撃検出エラーを表すクラスです。
    以前に処理されたメッセージが再送されたことを検出した場合に使用します。
    """
    def __init__(self, message: str, sequence: Optional[int] = None, 
                 severity: ErrorSeverity = ErrorSeverity.CRITICAL, details: Dict[str, Any] = None):
        """
        ReplayAttackErrorを初期化します。
        
        Args:
            message: エラーメッセージ
            sequence: 検出されたシーケンス番号（オプション）
            severity: エラーの重大度（デフォルトはCRITICAL）
            details: エラーに関する詳細情報を含む辞書（オプション）
        """
        details = details or {}
        if sequence is not None:
            details['sequence'] = sequence
        super().__init__(message, severity, details)


class SignatureVerificationError(AuthenticationError):
    """
    署名検証エラーを表すクラスです。
    デジタル署名の検証に失敗した場合に使用します。
    データの改ざんや無効な署名鍵の使用を示す可能性があります。
    """
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.CRITICAL, details: Dict[str, Any] = None):
        """
        SignatureVerificationErrorを初期化します。
        
        Args:
            message: エラーメッセージ
            severity: エラーの重大度（デフォルトはCRITICAL）
            details: エラーに関する詳細情報を含む辞書（オプション）
        """
        super().__init__(message, severity, details)

class KeyRotationError(SecurityError):
    """
    鍵ローテーションエラーを表すクラスです。
    暗号鍵のローテーション処理中にエラーが発生した場合に使用します。
    """
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.HIGH, details: Dict[str, Any] = None):
        """
        KeyRotationErrorを初期化します。
        
        Args:
            message: エラーメッセージ
            severity: エラーの重大度（デフォルトはHIGH）
            details: エラーに関する詳細情報を含む辞書（オプション）
        """
        super().__init__(message, severity, details)
