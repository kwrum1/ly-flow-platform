"""SQL 注入检测测试"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ly_rasp.detector.sql_injection import detect_sql_injection, SQLInjectionDetector


class TestSQLInjectionDetection:
    """SQL 注入检测测试"""

    def test_union_select_detection(self):
        """测试 UNION SELECT 检测"""
        sql = "SELECT * FROM users WHERE id=1 UNION SELECT * FROM admin"
        result = detect_sql_injection(sql)
        assert result is not None
        assert 'UNION' in result.get('matched_pattern', '')

    def test_drop_table_detection(self):
        """测试 DROP TABLE 检测"""
        sql = "SELECT * FROM users; DROP TABLE users"
        result = detect_sql_injection(sql)
        assert result is not None
        assert 'DROP' in result.get('matched_pattern', '')

    def test_comment_injection(self):
        """测试注释注入检测"""
        sql = "SELECT * FROM users WHERE id=1--"
        result = detect_sql_injection(sql)
        assert result is not None

    def test_or_1_equals_1_detection(self):
        """测试 OR 1=1 检测"""
        sql = "SELECT * FROM users WHERE id=1 OR 1=1"
        result = detect_sql_injection(sql)
        assert result is not None

    def test_sleep_injection(self):
        """测试时间盲注检测"""
        sql = "SELECT * FROM users WHERE id=1 AND SLEEP(5)"
        result = detect_sql_injection(sql)
        assert result is not None
        assert 'SLEEP' in result.get('matched_pattern', '')

    def test_normal_sql(self):
        """测试正常 SQL 不被误报"""
        sql = "SELECT id, name FROM users WHERE status = 'active'"
        result = detect_sql_injection(sql)
        assert result is None

    def test_quoted_strings_ignored(self):
        """测试带引号字符串的 SQL 不是注入"""
        sql = "SELECT * FROM posts WHERE title = 'OR 1=1'"
        result = detect_sql_injection(sql)
        # 正常转义的值不应该是注入
        assert result is None

    def test_empty_input(self):
        """测试空输入"""
        result = detect_sql_injection("")
        assert result is None

        result = detect_sql_injection(None)
        assert result is None

    def test_multiline_sql(self):
        """测试多行 SQL"""
        sql = """SELECT * FROM users
                 WHERE id = 1
                   AND name = 'admin'
                   OR 1=1"""
        result = detect_sql_injection(sql)
        assert result is not None

    def test_detector_with_config(self):
        """测试使用配置"""
        from ly_rasp.config import RASPConfig

        config = RASPConfig()
        detector = SQLInjectionDetector(config)

        sql = "SELECT * FROM users; DROP TABLE users"
        result = detector.detect(sql, config)
        assert result is not None


class TestSQLNormalization:
    """SQL 规范化测试"""

    def test_comments_removed(self):
        """测试注释被移除"""
        detector = SQLInjectionDetector()

        sql_with_comment = "SELECT * FROM users -- comment"
        normalized = detector._normalize(sql_with_comment)
        assert '--' not in normalized

    def test_whitespace_normalized(self):
        """测试空白字符规范化"""
        detector = SQLInjectionDetector()

        sql_with_tabs = "SELECT\t*\tFROM users"
        normalized = detector._normalize(sql_with_tabs)
        assert '\t' not in normalized
        assert '  ' not in normalized


if __name__ == '__main__':
    pytest.main([__file__, '-v'])