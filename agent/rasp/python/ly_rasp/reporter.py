import time
import json
import logging
import queue
import threading
from typing import Dict, Any, Optional

try:
    import redis
    from redis.exceptions import RedisError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

    class RedisError(Exception):
        pass

from .bridge import BridgeClient
from .config import RASPConfig, effective_mode
from .runtime_health import RuntimeHealthMixin, WatchdogRuntime


logger = logging.getLogger(__name__)


class Reporter(RuntimeHealthMixin):
    """安全事件上报器"""

    def __init__(self, config: RASPConfig, watchdog_runtime: WatchdogRuntime | None = None):
        self._initialize_runtime_state(config, watchdog_runtime)
        self.bridge_client = BridgeClient(config) if config.bridge_token else None
        if self.bridge_client is not None:
            self._health_status = "healthy"
            self._health_reason = "ready"
            self._exporter_available = True
        else:
            self._connect_redis()
        self._verify_binary_integrity()

    def _initialize_runtime_state(
        self,
        config: RASPConfig,
        watchdog_runtime: WatchdogRuntime | None = None,
    ) -> None:
        self.config = config
        self._watchdog_runtime = watchdog_runtime or WatchdogRuntime()
        self.redis_client = None
        self._rate_second = -1
        self._rate_count = 0
        self._health_status = "degraded"
        self._health_reason = "exporter_unavailable"
        self._exporter_available = False
        self._restart_count = 0
        self._runtime_health_lock = threading.RLock()
        self._watchdog_at = self._utc_now()
        self._watchdog_activity_at = self._watchdog_runtime.clock.monotonic()
        self._watchdog_next_restart_at = self._watchdog_activity_at
        self._watchdog_work_active = False
        self._watchdog_stopped = threading.Event()
        self._watchdog_thread = None
        self._watchdog_lifecycle_lock = threading.Lock()
        self._event_queue = queue.Queue(maxsize=max(1, config.queue_capacity))
        self._queue_admission_lock = threading.Lock()
        self.bridge_client = None

    @property
    def queue_capacity(self) -> int:
        event_queue = getattr(self, "_event_queue", None)
        if event_queue is None:
            return max(1, self.config.queue_capacity)
        configured = min(event_queue.maxsize, max(1, self.config.queue_capacity))
        return max(event_queue.qsize(), configured)

    def _connect_redis(self) -> None:
        """连接 Redis"""
        if not REDIS_AVAILABLE:
            logger.warning("redis package not available, event reporting disabled")
            return

        try:
            # 解析服务器地址
            addr = self.config.server_addr
            if ':' in addr:
                host, port = addr.rsplit(':', 1)
                port = int(port)
            else:
                host = addr
                port = 6379

            self.redis_client = redis.Redis(
                host=host,
                port=port,
                username=self.config.redis_username or None,
                password=(
                    self.config.redis_password
                    if self.config.redis_username and self.config.redis_password
                    else self.config.redis_legacy_password or None
                ),
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            # 测试连接
            self.redis_client.ping()
            self._health_status = "healthy"
            self._health_reason = "ready"
            self._exporter_available = True
            logger.info(f"Connected to Redis at {addr}")
        except (ValueError, OSError, RedisError) as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            self.redis_client = None

    def report(self, event: Dict[str, Any]) -> bool:
        """
        上报安全事件

        Args:
            event: 事件字典

        Returns:
            bool: 上报是否成功
        """
        self._ensure_runtime_health_state()
        with self._runtime_health_lock:
            self._watchdog_at = self._utc_now()
            self._watchdog_activity_at = self._watchdog_runtime.clock.monotonic()
            self._watchdog_work_active = True
        try:
            if self.config.policy_version <= 0 and self.bridge_client is None:
                self._health_status = "degraded"
                self._health_reason = "missing_policy_version"
                return False
            if effective_mode(self.config) == 'off' or not self._allow_event():
                return False
            if not hasattr(self, "_event_queue"):
                self._event_queue = queue.Queue(maxsize=max(1, self.config.queue_capacity))
                self._queue_admission_lock = threading.Lock()
            try:
                with self._queue_admission_lock:
                    if self._event_queue.qsize() >= self.queue_capacity:
                        raise queue.Full
                    self._event_queue.put_nowait(event)
            except queue.Full:
                self._health_status = "degraded"
                self._health_reason = "queue_capacity_exceeded"
                return False
            try:
                return self._report_queued(event)
            finally:
                self._event_queue.get_nowait()
                self._event_queue.task_done()
        finally:
            with self._runtime_health_lock:
                self._watchdog_at = self._utc_now()
                self._watchdog_activity_at = self._watchdog_runtime.clock.monotonic()
                self._watchdog_work_active = False

    def _report_queued(self, event: Dict[str, Any]) -> bool:
        started = time.perf_counter()
        event = self.normalize_event(event)
        encoded = json.dumps(event, default=str, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self.config.memory_budget_bytes:
            self._health_status = "degraded"
            self._health_reason = "memory_budget_exceeded"
            return False
        if (time.perf_counter() - started) * 1000 > self.config.cpu_budget_ms:
            self._health_status = "degraded"
            self._health_reason = "cpu_budget_exceeded"
            return False

        if self.bridge_client is not None:
            delivered = self.bridge_client.report(event)
            self._health_status = "healthy" if delivered else "degraded"
            self._health_reason = "ready" if delivered else self.bridge_client.last_health_reason
            if self._health_reason == "ready":
                self._health_reason = "exporter_unavailable"
            self._exporter_available = delivered
            return delivered

        # 尝试通过 Redis 上报
        if self.redis_client:
            try:
                self.redis_client.xadd(self.config.stream, {
                    'type': 'rasp',
                    'data': json.dumps(event, default=str)
                })
                self._health_status = "healthy"
                self._health_reason = "ready"
                self._exporter_available = True
                logger.info(f"Reported event: {event.get('type')}")
                return True
            except (OSError, RedisError) as e:
                self._health_status = "degraded"
                self._health_reason = "exporter_unavailable"
                self._exporter_available = False
                logger.error(f"Failed to report event via Redis: {e}")
                self._emit_control_health()

        # 回退到本地日志输出
        self._health_status = "degraded"
        self._health_reason = "exporter_unavailable"
        self._exporter_available = False
        logger.warning(f"Event detected (Redis unavailable): {json.dumps(event, default=str)}")
        return False

    def normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize detector output to the shared alerts:rasp contract."""
        normalized = dict(event)
        details = normalized.get('details')
        if isinstance(details, dict):
            for key in ('rule_id', 'severity', 'evidence', 'matched_pattern'):
                if key in details and key not in normalized:
                    normalized[key] = details[key]

        attack_type = normalized.get('attack_type') or normalized.get('type') or 'unknown'
        if attack_type == 'sensitive_file_access':
            attack_type = 'path_traversal'
        if attack_type == 'deserialize_injection':
            attack_type = 'deserialization'

        blocked = bool(normalized.get('blocked', False))
        normalized.update({
            'type': 'rasp.attack',
            'agent_id': self.config.agent_id,
            'language': normalized.get('language') or self.config.language,
            'app': normalized.get('app') or self.config.app,
            'attack_type': attack_type,
            'blocked': blocked,
            'action': normalized.get('action') or ('block' if blocked else 'log'),
            'mode': normalized.get('mode') or ('protect' if blocked else 'monitor'),
            'severity': normalized.get('severity') or 'medium',
            'rule_id': normalized.get('rule_id') or f'python-{attack_type}',
            'policy_version': self.config.policy_version,
            'occurred_at': normalized.get('occurred_at') or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'timestamp': normalized.get('timestamp') or time.time(),
        })
        return normalized

    def report_sql_injection(self, details: Dict[str, Any]) -> bool:
        """上报 SQL 注入事件"""
        return self.report({
            'type': 'sql_injection',
            'details': details,
        })

    def report_command_injection(self, details: Dict[str, Any]) -> bool:
        """上报命令注入事件"""
        return self.report({
            'type': 'command_injection',
            'details': details,
        })

    def report_sensitive_file_access(self, details: Dict[str, Any]) -> bool:
        """上报敏感文件访问事件"""
        return self.report({
            'type': 'sensitive_file_access',
            'details': details,
        })

    def report_deserialize_injection(self, details: Dict[str, Any]) -> bool:
        """上报反序列化漏洞事件"""
        return self.report({
            'type': 'deserialize_injection',
            'details': details,
        })


# 全局 reporter 实例的获取函数
_reporter: Optional[Reporter] = None


def set_reporter(reporter: Optional[Reporter]) -> None:
    """设置全局 reporter 实例"""
    global _reporter
    _reporter = reporter


def get_reporter() -> Optional[Reporter]:
    """获取全局 reporter 实例"""
    return _reporter
