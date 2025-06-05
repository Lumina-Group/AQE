import logging
from AQE.configuration import ConfigurationManager # Added import
import asyncio
import time
import os
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any, List, Optional

class ErrorSeverity:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SecurityEvent:
    def __init__(
        self,
        severity: Any,
        event_type: str,
        details: str,
        timestamp: float,
        metadata: Optional[Dict[str, Any]] = None
    ):
        if isinstance(severity, str):
            try:
                self.severity = getattr(ErrorSeverity, severity.upper())
            except AttributeError:
                logging.getLogger("AQE").warning(
                    f"Unknown severity '{severity}' specified, using MEDIUM."
                )
                self.severity = ErrorSeverity.MEDIUM
        else:
            self.severity = severity

        self.event_type = event_type
        self.details = details
        self.timestamp = timestamp
        self.metadata = metadata or {}

class SecurityMetrics:
    def __init__(self, config_manager: ConfigurationManager, metrics_log_file: str = "security_metrics.log"):
        self.config_manager = config_manager
        self.metrics: Dict[str, int] = defaultdict(int)
        self.timeline: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self.last_reset: float = time.time()
        self.metrics_log_file = metrics_log_file # Store original name

        self._logging_enabled = self.config_manager.getboolean('logging', 'ENABLE_SECURITY_METRICS_LOG', fallback=True)

        if self._logging_enabled:
            # Ensure directory exists if metrics_log_file includes a path
            log_dir = os.path.dirname(self.metrics_log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir) # Create directory if it doesn't exist

            if not os.path.exists(self.metrics_log_file):
                with open(self.metrics_log_file, "w") as f:
                    f.write(f"{datetime.now()}: Metrics log initialized\n") # Added newline
            else:
                # Optional: Log an append marker if the file already exists
                with open(self.metrics_log_file, "a") as f:
                    f.write(f"{datetime.now()}: Metrics logging session started\n") # Added newline
        else:
            self.metrics_log_file = None # Logging is disabled

    async def _log_metric_update(self, metric_name: str, value: int):
        if not self._logging_enabled or not self.metrics_log_file:
            return # Don't log if disabled

        log_entry = f"{datetime.now()}: {metric_name} += {value} (Total: {self.metrics[metric_name]})\n" # Added newline

        def write_log():
            try:
                with open(self.metrics_log_file, "a") as f: # type: ignore
                    f.write(log_entry)
            except Exception as e:
                # Log to main logger if SecurityMetrics logging fails
                main_logger = logging.getLogger("AQE")
                main_logger.error(f"Failed to write to security_metrics.log: {e}")

        await asyncio.to_thread(write_log)

    async def increment_metric(self, metric_name: str, value: int = 1):
        async with self._lock:
            self.metrics[metric_name] += value
            self.timeline.append({
                'timestamp': time.time(),
                'metric': metric_name,
                'value': value
            })
            await self._log_metric_update(metric_name, value)

    async def increment_expired_messages(self):
        await self.increment_metric('expired_messages'.upper())

    async def increment_successful_decryptions(self):
        await self.increment_metric('successful_decryptions'.upper())

    async def increment_decryption_failures(self):
        await self.increment_metric('decryption_failures'.upper())

    async def increment_encryption_failures(self):
        await self.increment_metric('encryption_failures'.upper())

    async def increment_encryption_successes(self):
        await self.increment_metric('encryption_successes'.upper())


    async def increment_key_exchange_successes(self):
        await self.increment_metric('key_exchange_successes'.upper())
    # async def increment_signature_verification_failures(self):
    #     await self.increment_metric('signature_verification_failures'.upper())

    async def increment_signature_verification_successes(self):
        await self.increment_metric('signature_verification_successes'.upper())

    # async def increment_authentication_failures(self):
    #     await self.increment_metric('authentication_failures'.upper())

    # async def increment_authentication_successes(self):
    #     await self.increment_metric('authentication_successes'.upper())

    # async def increment_replay_attacks(self):
    #     await self.increment_metric('replay_attacks'.upper())

    # async def increment_security_events(self):
    #     await self.increment_metric('security_events'.upper())

    async def get_metrics(self) -> Dict[str, int]:
        async with self._lock:
            return dict(self.metrics)

    async def get_timeline(self, since: float = 0) -> List[Dict[str, Any]]:
        async with self._lock:
            return [
                e for e in self.timeline
                if since <= 0 or e['timestamp'] > since
            ]

    async def reset_metrics(self):
        async with self._lock:
            self.metrics.clear()
            self.timeline.clear()
            self.last_reset = time.time()

class EnhancedSecurityLogger:
    def __init__(self, logger: logging.Logger, metrics: SecurityMetrics):
        self.logger = logger
        self.metrics = metrics

    async def log_security_event(self, event: SecurityEvent):
        metric_key = f"{event.severity}_{event.event_type}"
        await self.metrics.increment_metric(metric_key)

        log_levels = {
            ErrorSeverity.LOW: self.logger.info,
            ErrorSeverity.MEDIUM: self.logger.warning,
            ErrorSeverity.HIGH: self.logger.error,
            ErrorSeverity.CRITICAL: self.logger.critical
        }
        
        log_func = log_levels.get(event.severity, self.logger.warning)
        log_message = (
            f"Security Event [{event.severity}]: "
            f"{event.event_type} - {event.details}"
        )

        log_func(
            log_message,
            extra={
                "timestamp": datetime.fromtimestamp(event.timestamp).isoformat(),
                "metadata": event.metadata
            }
        )

        if event.severity == ErrorSeverity.CRITICAL:
            await self._handle_critical_event(event)

    async def _handle_critical_event(self, event: SecurityEvent):
        self.logger.critical(
            "CRITICAL EVENT RESPONSE INITIATED",
            extra={"event_details": event.details}
        )

    async def get_metrics_summary(self) -> Dict[str, Any]:
        metrics = await self.metrics.get_metrics()
        summary: Dict[str, Any] = {
            'total_events': sum(metrics.values()),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'last_reset': datetime.fromtimestamp(self.metrics.last_reset).isoformat()
        }

        for metric, count in metrics.items():
            if '_' in metric:
                severity, _, event_type = metric.partition('_')
                summary['by_severity'][severity] += count
                summary['by_type'][event_type] += count
            else:
                summary['by_type'][metric] += count

        return summary

def setup_logging(
    config_manager: ConfigurationManager, # Added config_manager
    log_level: str = "INFO",
    log_file: str = "quantum_secure_comm.log"
) -> logging.Logger:
    logger = logging.getLogger("AQE")
    logger.propagate = False
    
    if logger.hasHandlers():
        logger.handlers.clear()

    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Retrieve timestamp preference
    log_timestamps = config_manager.getboolean('logging', 'LOG_TIMESTAMPS', fallback=True)

    # Define formatter_string based on log_timestamps
    if log_timestamps:
        formatter_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    else:
        formatter_string = '%(name)s - %(levelname)s - %(message)s'

    formatter = logging.Formatter(formatter_string) # Use dynamic formatter_string

    try:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logging.error(f"File handler error: {str(e)}")

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    return logger