"""SQL 注入检测器"""
import re
from typing import Optional, Dict, Any

from .base import BaseDetector


# 默认 SQL 注入特征模式
DEFAULT_PATTERNS = [
    # UNION 注入
    r"UNION\s+(ALL\s+)?SELECT",
    r"UNION\s+\(",
    # DROP/DELETE 操作
    r";\s*DROP\s+(TABLE|DATABASE|INDEX|VIEW)",
    r";\s*DELETE\s+FROM",
    r";\s*TRUNCATE\s+",
    # 注释注入
    r"--\s*$",
    r"/\*.*\*/",
    # 布尔注入
    r"OR\s+1\s*=\s*1",
    r"OR\s+'[^']*'\s*=\s*'[^']*'",
    r"OR\s+\d+\s*=\s*\d+",
    r"AND\s+1\s*=\s*2",
    r"AND\s+1\s*=\s*1",
    # 堆叠查询
    r";\s*\w+",
    # 存储过程
    r"EXEC\s*\(",
    r"EXECUTE\s+",
    r"XP_",
    r"SP_",
    # 时间盲注
    r"SLEEP\s*\(",
    r"BENCHMARK\s*\(",
    r"WAITFOR\s+DELAY",
    r"PG_SLEEP",
    # 联合查询变种
    r"UNION\s+ALL\s+SELECT\s+\d+",
    r"ORDER\s+BY\s+\d+",
    # 字符逃逸
    r"'\s*OR\s+'1'\s*=\s*'1",
    r"'\s+OR\s+'1'\s*=\s*'1",
    # 16进制注入
    r"0x[0-9a-f]+",
    # 编码绕过
    r"CHAR\s*\(",
    r"CONCAT\s*\(",
    r"CONCAT_WS\s*\(",
]


class SQLInjectionDetector(BaseDetector):
    """SQL 注入检测器"""

    def __init__(self, config=None):
        super().__init__(config)
        self.patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in DEFAULT_PATTERNS]

    def detect(self, sql: str, config=None) -> Optional[Dict[str, Any]]:
        """
        检测 SQL 注入

        Args:
            sql: SQL 语句
            config: 配置对象（可选）

        Returns:
            检测结果字典，如果未检测到威胁则返回 None
        """
        if not sql or not isinstance(sql, str):
            return None

        # 规范化 SQL
        normalized_sql = self._normalize(sql)

        # 模式匹配
        for pattern in self.patterns:
            match = pattern.search(normalized_sql)
            if match:
                return self._build_result(
                    pattern.pattern,
                    match.group(0),
                    match.start(),
                    match.end(),
                    sql,
                    normalized_sql,
                )

        # 检查 SQL 长度异常
        if len(sql) > 10000:
            return self._build_result(
                'sql_length_threshold',
                f'SQL length: {len(sql)}',
                0,
                len(sql),
                sql,
                normalized_sql,
            )

        return None

    def _normalize(self, sql: str) -> str:
        """规范化 SQL 语句"""
        # 移除注释
        sql = re.sub(r'--[^\n]*', '', sql)
        sql = re.sub(r'/\*.*?\*/', '', sql, flags=re.DOTALL)

        # 规范化空白字符
        sql = re.sub(r'\s+', ' ', sql)

        # 移除字符串常量的具体内容（保留引号标记）
        sql = re.sub(r"'(?:[^']|'')*'", "''", sql)
        sql = re.sub(r'"(?:[^"]|"")*"', '""', sql)

        return sql.strip()

    def _build_result(
        self,
        matched_pattern: str,
        matched_text: str,
        start: int,
        end: int,
        original_sql: str,
        normalized_sql: str,
    ) -> Dict[str, Any]:
        """构建检测结果"""
        return {
            'matched_pattern': matched_pattern,
            'matched_text': matched_text,
            'position': {'start': start, 'end': end},
            'evidence': self.get_evidence(normalized_sql, start, end),
            'original_sql': original_sql[:500],  # 截断避免过大
            'severity': 'high',
            'category': 'sql_injection',
        }


def detect_sql_injection(sql: str, config=None) -> Optional[Dict[str, Any]]:
    """
    SQL 注入检测函数

    Args:
        sql: SQL 语句
        config: 配置对象（可选）

    Returns:
        检测结果字典，如果未检测到威胁则返回 None
    """
    detector = SQLInjectionDetector(config)
    return detector.detect(sql, config)