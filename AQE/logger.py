import logging
import asyncio
import time
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any
from .errors import ErrorSeverity

class SecurityEvent:
    def __init__(self, severity, event_type, details, timestamp, metadata=None):
        """
        セキュリティイベントを表すクラスを初期化します。
        
        このクラスはセキュリティに関連するイベントを表現し、ログや分析のために使用されます。
        
        Args:
            severity: イベントの重大度（ErrorSeverityの値または文字列）
            event_type: イベントの種類を示す識別子
            details: イベントの詳細説明
            timestamp: イベント発生時のタイムスタンプ
            metadata: イベントに関する追加メタデータ（オプション）
        """
        self.severity = severity if isinstance(severity, ErrorSeverity) else getattr(ErrorSeverity, severity)
        self.event_type = event_type
        self.details = details
        self.timestamp = timestamp
        self.metadata = metadata or {}

class SecurityMetrics:
    def __init__(self):
        """
        セキュリティメトリクスクラスを初期化します。
        
        このクラスはセキュリティ関連のメトリクスを追跡し、統計情報を提供します。
        スレッドセーフな操作のために非同期ロックを使用します。
        """
        self.metrics = defaultdict(int)
        self.timeline = []
        self._lock = asyncio.Lock()
        self.last_reset = time.time()

    async def increment_metric(self, metric_name: str, value: int = 1):
        """
        指定されたメトリックを増加させます。
        
        Args:
            metric_name: 増加させるメトリックの名前
            value: 増加させる値（デフォルト: 1）
            
        Returns:
            なし
        """
        async with self._lock:
            self.metrics[metric_name] += value
            self.timeline.append({
                'timestamp': time.time(),
                'metric': metric_name,
                'value': value
            })

    async def get_metrics(self) -> Dict[str, int]:
        """
        現在のメトリックを取得します。
        
        Returns:
            Dict[str, int]: メトリック名とその値の辞書
        """
        async with self._lock:
            return dict(self.metrics)

    async def get_timeline(self, since: float = 0) -> list:
        """
        タイムライン情報を取得します。
        特定の時間以降のイベントのみをフィルタリングできます。
        
        Args:
            since: この時間以降のイベントのみを返す（Unixタイムスタンプ）。
                  0以下の値を指定すると、すべてのイベントが返されます。
            
        Returns:
            list: タイムラインイベントのリスト
        """
        async with self._lock:
            if since <= 0:
                return self.timeline
            return [e for e in self.timeline if e['timestamp'] > since]

    async def reset_metrics(self):
        """
        メトリックをリセットします。
        すべてのメトリック値とタイムラインをクリアし、last_resetタイムスタンプを更新します。
        
        Returns:
            なし
        """
        async with self._lock:
            self.metrics.clear()
            self.timeline = []
            self.last_reset = time.time()

class EnhancedSecurityLogger:
    def __init__(self, logger: logging.Logger, metrics: SecurityMetrics):
        """
        拡張セキュリティロガークラスを初期化します。
        
        このクラスは標準のロギングと統計メトリクス追跡を組み合わせ、
        セキュリティイベントの包括的な記録と分析を提供します。
        
        Args:
            logger: 使用するロガーインスタンス
            metrics: セキュリティメトリクスを記録するためのSecurityMetricsインスタンス
        """
        self.logger = logger
        self.metrics = metrics

    async def log_security_event(self, event: SecurityEvent):
        """
        セキュリティイベントをログに記録し、メトリックを更新します。
        
        Args:
            event: ログに記録するSecurityEventインスタンス
            
        Returns:
            なし
        """
        await self.metrics.increment_metric(f"{event.severity.value}_{event.event_type}")
        log_func = {
            ErrorSeverity.LOW: self.logger.info,
            ErrorSeverity.MEDIUM: self.logger.warning,
            ErrorSeverity.HIGH: self.logger.error,
            ErrorSeverity.CRITICAL: self.logger.critical
        }[event.severity]
        log_func(
            f"Security Event [{event.severity.value}]: {event.event_type} - {event.details}",
            extra={
                "timestamp": datetime.fromtimestamp(event.timestamp).isoformat(),
                "metadata": event.metadata
            }
        )
        if event.severity == ErrorSeverity.CRITICAL:
            await self._handle_critical_event(event)

    async def _handle_critical_event(self, event: SecurityEvent):
        """
        クリティカルなセキュリティイベントを処理します。
        
        Args:
            event: 処理するクリティカルなSecurityEventインスタンス
            
        Returns:
            なし
        """
        # 管理者に通知などの処理を実装可能
        pass

    async def get_metrics_summary(self) -> Dict[str, Any]:
        """
        メトリックのサマリーを取得します。
        
        Returns:
            Dict[str, Any]: メトリックサマリーを含む辞書
        """
        metrics = await self.metrics.get_metrics()
        return {
            'total_events': sum(metrics.values()),
            'by_severity': {
                severity.value: sum(v for k, v in metrics.items() if k.startswith(severity.value))
                for severity in ErrorSeverity
            },
            'by_type': {
                k.split('_', 1)[1]: v for k, v in metrics.items() if '_' in k
            },
            'last_reset': self.metrics.last_reset
        }

def setup_logging(log_level: str = "INFO", log_file: str = "quantum_secure_comm.log") -> logging.Logger:
    """
    ロギングシステムの設定を行います。
    
    ファイルとコンソールの両方にログを出力するロガーを設定します。
    
    Args:
        log_level: ロギングレベル（デフォルト: "INFO"）
        log_file: ログファイルのパス（デフォルト: "quantum_secure_comm.log"）
        
    Returns:
        logging.Logger: 設定されたロガーインスタンス
    """
    logger = logging.getLogger("QuantumSecureComm")
    logger.setLevel(getattr(logging, log_level))
    
    # ファイルハンドラの設定
    fh = logging.FileHandler(log_file)
    fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(fh)
    
    # コンソールハンドラの設定
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
    logger.addHandler(ch)
    
    return logger