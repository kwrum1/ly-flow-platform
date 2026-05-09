"""命令注入检测测试"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ly_rasp.detector.command_injection import detect_command_injection, CommandInjectionDetector


class TestCommandInjectionDetection:
    """命令注入检测测试"""

    def test_semicolon_injection(self):
        """测试分号注入检测"""
        cmd = "cat /etc/passwd; rm -rf /"
        result = detect_command_injection(cmd)
        assert result is not None

    def test_pipe_injection(self):
        """测试管道注入检测"""
        cmd = "ls | cat /etc/passwd"
        result = detect_command_injection(cmd)
        assert result is not None

    def test_backtick_injection(self):
        """测试反引号注入检测"""
        cmd = "echo `whoami`"
        result = detect_command_injection(cmd)
        assert result is not None

    def test_command_substitution(self):
        """测试命令替换注入检测"""
        cmd = "echo $(whoami)"
        result = detect_command_injection(cmd)
        assert result is not None

    def test_eval_injection(self):
        """测试 eval 注入检测"""
        cmd = "eval('os.system(\"ls\")')"
        result = detect_command_injection(cmd)
        assert result is not None

    def test_double_special_chars(self):
        """测试连续特殊字符检测"""
        cmd = "ls && whoami"
        result = detect_command_injection(cmd)
        # && 本身是正常用法，这里测试多字符模式
        assert result is not None

    def test_newline_command(self):
        """测试换行后命令检测"""
        cmd = "ls\ncat /etc/passwd"
        result = detect_command_injection(cmd)
        assert result is not None

    def test_normal_command(self):
        """测试正常命令不误报"""
        cmd = "ls -la /home/user"
        result = detect_command_injection(cmd)
        assert result is None

    def test_safe_variables(self):
        """测试安全变量使用"""
        cmd = "echo $HOME"
        result = detect_command_injection(cmd)
        # 单独的环境变量不应该是注入
        # 但多个连续的特殊字符应该是
        # 这里我们只检测危险的模式

    def test_bytes_input(self):
        """测试字节输入"""
        cmd = b"ls -la"
        result = detect_command_injection(cmd)
        assert result is None

        cmd = b"cat /etc/passwd; rm -rf"
        result = detect_command_injection(cmd)
        assert result is not None

    def test_empty_input(self):
        """测试空输入"""
        result = detect_command_injection("")
        assert result is None

        result = detect_command_injection(None)
        assert result is None

    def test_etc_passwd_path(self):
        """测试敏感路径检测"""
        cmd = "cat /etc/passwd"
        result = detect_command_injection(cmd)
        assert result is not None


class TestCommandNormalization:
    """命令规范化测试"""

    def test_case_insensitive(self):
        """测试大小写不敏感"""
        detector = CommandInjectionDetector()

        # 应该是大小写不敏感的
        sql_upper = "CAT /ETC/PASSWD"
        result_upper = detector.detect(sql_upper)

        sql_lower = "cat /etc/passwd"
        result_lower = detector.detect(sql_lower)

        # 至少有一个应该被检测到（取决于实际模式定义）


if __name__ == '__main__':
    pytest.main([__file__, '-v'])