"""RASP 事件上报模块"""
import time
import json
import logging
from typing import Dict, Any, Optional

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from .config import RASPConfig


logger = logging.getLogger(__name__)


class Reporter:
    """安全事件上报器"""

    def __init__(self, config: RASPConfig):
        """
        初始化上报器

        Args:
            config: RASP 配置
        """
        self.config = config
        self.redis_client = None
        self._connect_redis()

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
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            # 测试连接
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {addr}")
        except Exception as e:
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
        event = self.normalize_event(event)

        # 尝试通过 Redis 上报
        if self.redis_client:
            try:
                self.redis_client.xadd(self.config.stream, {
                    'type': 'rasp',
                    'data': json.dumps(event, default=str)
                })
                logger.info(f"Reported event: {event.get('type')}")
                return True
            except Exception as e:
                logger.error(f"Failed to report event via Redis: {e}")

        # 回退到本地日志输出
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


def set_reporter(reporter: Reporter) -> None:
    """设置全局 reporter 实例"""
    global _reporter
    _reporter = reporter


def get_reporter() -> Optional[Reporter]:
    """获取全局 reporter 实例"""
    return _reporter
