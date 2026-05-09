"""SQL 解析工具"""
import re
from typing import List, Dict, Any, Optional


class SQLTokenizer:
    """SQL 语句分词器"""

    # SQL 关键字
    SQL_KEYWORDS = {
        'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'EXISTS',
        'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE',
        'CREATE', 'TABLE', 'DROP', 'ALTER', 'INDEX', 'VIEW',
        'UNION', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON',
        'GROUP', 'BY', 'ORDER', 'ASC', 'DESC', 'LIMIT', 'OFFSET',
        'HAVING', 'DISTINCT', 'AS', 'BETWEEN', 'LIKE', 'IS', 'NULL',
        'TRUE', 'FALSE', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
        'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'COALESCE', 'NULLIF',
        'CAST', 'CONVERT', 'EXTRACT', 'DATE', 'TIME', 'TIMESTAMP',
        'INTERVAL', 'CURRENT', 'USER', 'SESSION', 'GLOBAL',
    }

    # 危险关键字
    DANGEROUS_KEYWORDS = {
        'DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'EXEC', 'EXECUTE',
        'XP_', 'SP_', 'SLEEP', 'BENCHMARK', 'WAITFOR', 'PG_SLEEP',
    }

    def __init__(self):
        self.tokens: List[Dict[str, Any]] = []
        self.current_position = 0

    def tokenize(self, sql: str) -> List[Dict[str, Any]]:
        """
        分词 SQL 语句

        Args:
            sql: SQL 语句

        Returns:
            Token 列表
        """
        self.tokens = []
        self.current_position = 0
        sql = sql.strip()

        i = 0
        while i < len(sql):
            char = sql[i]

            # 跳过空白
            if char in ' \t\n\r':
                i += 1
                continue

            # 字符串常量
            if char in ('"', "'"):
                token, i = self._extract_string(sql, i, char)
                self.tokens.append(token)
                continue

            # 数字
            if char.isdigit() or (char == '.' and i + 1 < len(sql) and sql[i + 1].isdigit()):
                token, i = self._extract_number(sql, i)
                self.tokens.append(token)
                continue

            # 标识符或关键字
            if char.isalpha() or char == '_':
                token, i = self._extract_identifier(sql, i)
                self.tokens.append(token)
                continue

            # 操作符
            if char in '=><!+-*/%(),.;':
                self.tokens.append({
                    'type': 'operator',
                    'value': char,
                    'position': i,
                })
                i += 1
                continue

            # 注释
            if char == '-' and i + 1 < len(sql) and sql[i + 1] == '-':
                token, i = self._extract_comment(sql, i, '--')
                self.tokens.append(token)
                continue

            if char == '/' and i + 1 < len(sql) and sql[i + 1] == '*':
                token, i = self._extract_comment(sql, i, '/*')
                self.tokens.append(token)
                continue

            # 未知字符
            i += 1

        return self.tokens

    def _extract_string(self, sql: str, start: int, quote: str) -> tuple:
        """提取字符串常量"""
        i = start + 1
        while i < len(sql):
            if sql[i] == quote:
                # 检查转义
                if i + 1 < len(sql) and sql[i + 1] == quote:
                    i += 2
                    continue
                break
            i += 1

        value = sql[start:i + 1]
        return {
            'type': 'string',
            'value': value,
            'position': start,
        }, i + 1

    def _extract_number(self, sql: str, start: int) -> tuple:
        """提取数字"""
        i = start
        has_dot = False
        while i < len(sql) and (sql[i].isdigit() or sql[i] == '.'):
            if sql[i] == '.':
                if has_dot:
                    break
                has_dot = True
            i += 1

        return {
            'type': 'number',
            'value': sql[start:i],
            'position': start,
        }, i

    def _extract_identifier(self, sql: str, start: int) -> tuple:
        """提取标识符或关键字"""
        i = start
        while i < len(sql) and (sql[i].isalnum() or sql[i] == '_'):
            i += 1

        value = sql[start:i].upper()
        token_type = 'keyword' if value in self.SQL_KEYWORDS else 'identifier'

        return {
            'type': token_type,
            'value': value,
            'original': sql[start:i],
            'position': start,
            'is_dangerous': value in self.DANGEROUS_KEYWORDS or any(
                value.startswith(d) for d in self.DANGEROUS_KEYWORDS
            ),
        }, i

    def _extract_comment(self, sql: str, start: int, marker: str) -> tuple:
        """提取注释"""
        if marker == '--':
            i = sql.find('\n', start + 2)
            if i == -1:
                i = len(sql)
        else:  # /*
            i = sql.find('*/', start + 2)
            if i == -1:
                i = len(sql)
            else:
                i += 2

        return {
            'type': 'comment',
            'value': sql[start:i],
            'position': start,
        }, i

    def get_keywords(self) -> List[str]:
        """获取所有关键字"""
        return [t['value'] for t in self.tokens if t['type'] == 'keyword']

    def get_dangerous_keywords(self) -> List[str]:
        """获取危险关键字"""
        return [t['value'] for t in self.tokens if t.get('is_dangerous')]

    def has_union_select(self) -> bool:
        """检查是否有 UNION SELECT"""
        tokens = self.get_keywords()
        for i, token in enumerate(tokens):
            if token == 'UNION' and i + 1 < len(tokens) and tokens[i + 1] == 'SELECT':
                return True
        return False

    def has_or_1_equals_1(self) -> bool:
        """检查是否有 OR 1=1"""
        sql = ' '.join(t.get('original', t['value']) for t in self.tokens)
        return bool(re.search(r'\bOR\b\s+\d+\s*=\s*\d+', sql, re.IGNORECASE))

    def has_comment_termination(self) -> bool:
        """检查是否以注释结尾"""
        if not self.tokens:
            return False
        last_token = self.tokens[-1]
        return last_token.get('type') == 'comment' or last_token.get('value', '').endswith('--')


def analyze_sql(sql: str) -> Dict[str, Any]:
    """
    分析 SQL 语句

    Args:
        sql: SQL 语句

    Returns:
        分析结果
    """
    tokenizer = SQLTokenizer()
    tokens = tokenizer.tokenize(sql)

    return {
        'tokens': tokens,
        'keyword_count': len(tokenizer.get_keywords()),
        'dangerous_keywords': tokenizer.get_dangerous_keywords(),
        'has_union_select': tokenizer.has_union_select(),
        'has_or_1_equals_1': tokenizer.has_or_1_equals_1(),
        'has_comment_termination': tokenizer.has_comment_termination(),
        'is_suspicious': bool(tokenizer.get_dangerous_keywords()) or tokenizer.has_or_1_equals_1(),
    }