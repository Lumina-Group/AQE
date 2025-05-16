import logging
import asyncio
import time
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any, List, Optional
class ErrorSeverity: # type: ignore
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEvent:
    def __init__(self, severity: Any, event_type: str, details: str, timestamp: float, metadata: Optional[Dict[str, Any]] = None):
        """
        セキュリティイベントを表すクラスを初期化します。
        
        このクラスはセキュリティに関連するイベントを表現し、ログや分析のために使用されます。
        
        Args:
            severity: イベントの重大度（ErrorSeverityの値または文字列）
            event_type: イベントの種類を示す識別子
            details: イベントの詳細説明
            timestamp: イベント発生時のタイムスタンプ (Unixタイムスタンプ)
            metadata: イベントに関する追加メタデータ（オプション）
        """
        if isinstance(severity, str):
            try:
                self.severity = getattr(ErrorSeverity, severity.upper())
            except AttributeError:
                # 不明な重大度の場合はデフォルト値を設定するか、エラーを発生させる
                logging.getLogger("AQE").warning(f"Unknown severity '{severity}' specified, treating as MEDIUM.")
                self.severity = ErrorSeverity.MEDIUM # type: ignore
        else:
            self.severity = severity # ErrorSeverity enum instance

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
        self.metrics: Dict[str, int] = defaultdict(int)
        self.timeline: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self.last_reset: float = time.time()

    async def increment_expired_messages(self):
        """
        有効期限切れのメッセージ数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('expired_messages')

    async def increment_successful_decryptions(self):
        """
        成功した復号操作の数をインクリメントします。

        Returns:
            なし
        """
        await self.increment_metric('successful_decryptions')

    async def increment_decryption_failures(self):
        """
        復号操作の失敗数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('decryption_failures')

    async def increment_encryption_failures(self):
        """
        暗号化操作の失敗数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('encryption_failures')

    async def increment_encryption_successes(self):
        """
        成功した暗号化操作の数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('encryption_successes')

    async def increment_key_exchange_failures(self):
        """
        鍵交換操作の失敗数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('key_exchange_failures')

    async def increment_key_exchange_successes(self):
        """
        成功した鍵交換操作の数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('key_exchange_successes')

    async def increment_signature_verification_failures(self):
        """
        署名検証操作の失敗数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('signature_verification_failures')

    async def increment_signature_verification_successes(self):
        """
        成功した署名検証操作の数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('signature_verification_successes')

    async def increment_authentication_failures(self):
        """
        認証操作の失敗数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('authentication_failures')

    async def increment_authentication_successes(self):
        """
        成功した認証操作の数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('authentication_successes')

    async def increment_replay_attacks(self):
        """
        リプレイ攻撃の発生数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('replay_attacks')

    async def increment_security_events(self):
        """
        セキュリティイベントの発生数をインクリメントします。
        Returns:
            なし
        """
        await self.increment_metric('security_events')
    
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

    async def get_timeline(self, since: float = 0) -> List[Dict[str, Any]]:
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
                return list(self.timeline) # 変更可能性を考慮してコピーを返す
            return [e for e in self.timeline if e['timestamp'] > since]

    async def update_metrics(self, metrics: Dict[str, int]):
        """
        メトリックを更新します。

        Args:
            metrics: 更新するメトリック名とその値の辞書

        Returns:
            なし
        """
        async with self._lock:
            for metric_name, value in metrics.items():
                self.metrics[metric_name] += value
                self.timeline.append({
                    'timestamp': time.time(),
                    'metric': metric_name,
                    'value': value
                })
                
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
        metric_key_severity = event.severity.value if hasattr(event.severity, 'value') else str(event.severity)
        await self.metrics.increment_metric(f"{metric_key_severity}_{event.event_type}")
        
        log_func_map = {
            ErrorSeverity.LOW: self.logger.info,
            ErrorSeverity.MEDIUM: self.logger.warning,
            ErrorSeverity.HIGH: self.logger.error,
            ErrorSeverity.CRITICAL: self.logger.critical
        }
        log_func = log_func_map.get(event.severity, self.logger.warning) # 不明な場合はWARNING

        log_func(
            f"Security Event [{metric_key_severity}]: {event.event_type} - {event.details}",
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
        self.logger.critical(f"CRITICAL EVENT DETECTED: {event.details}. Notifying administrators.")
    async def get_metrics_summary(self) -> Dict[str, Any]:
        """
        メトリックのサマリーを取得します。
        
        Returns:
            Dict[str, Any]: メトリックサマリーを含む辞書
        """
        metrics = await self.metrics.get_metrics()
        summary: Dict[str, Any] = {
            'total_events': sum(metrics.values()),
            'by_severity': {},
            'by_type': defaultdict(int), # 型ごとの集計を初期化
            'last_reset': datetime.fromtimestamp(self.metrics.last_reset).isoformat()
        }

        # by_severity の集計
        for severity in ErrorSeverity: # type: ignore
            severity_value = severity.value if hasattr(severity, 'value') else str(severity)
            summary['by_severity'][severity_value] = sum(
                v for k, v in metrics.items() if k.startswith(severity_value + "_")
            )
        
        # by_type の集計
        for k, v in metrics.items():
            parts = k.split('_', 1)
            if len(parts) > 1:
                event_type = parts[1]
                summary['by_type'][event_type] += v
            else: # 重大度のみのメトリック（例： increment_security_events で直接記録されたもの）
                summary['by_type'][k] +=v


        return summary

def setup_logging(log_level: str = "INFO", log_file: str = "quantum_secure_comm.log") -> logging.Logger:
    """
    ロギングシステムの設定を行います。
    
    ファイルとコンソールの両方にログを出力するロガーを設定します。
    
    Args:
        log_level: ロギングレベル（デフォルト: "INFO"）。"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL" のいずれか。
        log_file: ログファイルのパス（デフォルト: "quantum_secure_comm.log"）
        
    Returns:
        logging.Logger: 設定されたロガーインスタンス
    """
    logger = logging.getLogger("AQE")
        
    # ログ伝播を無効化し、ルートロガーへの出力を防止
    logger.propagate = False
    # 既存のハンドラをクリア（複数回呼び出された場合の重複防止）
    if logger.hasHandlers():
        logger.handlers.clear()

    # ログレベルの設定（無効な場合はINFOにフォールバック）
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        logging.warning(f"Invalid log level '{log_level}' specified. Using INFO level.")
        numeric_level = logging.INFO
    logger.setLevel(numeric_level)
    
    # ファイルハンドラの設定
    try:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s - Extra: %(extra)s', defaults={'extra': 'None'}))
        logger.addHandler(fh)
    except Exception as e:
        logging.error(f"Failed to set file handler: {log_file}, Error:{e}")
        # コンソールへのログ出力は継続する
    
    # コンソールハンドラの設定
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s - Extra: %(extra)s', defaults={'extra': 'None'}))
    logger.addHandler(ch)
    
    #logger.info(f"The logging system has been configured with level {log_level.upper()}. Log file: {log_file}")
    return logger
