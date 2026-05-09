"""命令注入检测器"""
import re
from typing import Optional, Dict, Any

from .base import BaseDetector


# 默认命令注入特征模式
DEFAULT_PATTERNS = [
    # 文件系统操作
    r";\s*rm\s",
    r";\s*rmdir",
    r";\s*del\s",
    r";\s*rmdir\s",
    r";\s*format\s",
    r";\s*mkfs\s",
    # 管道命令
    r"\|\s*cat\s",
    r"\|\s*grep\s",
    r"\|\s*awk\s",
    r"\|\s*sed\s",
    r"\|\s*nc\s",
    r"\|\s*ncat\s",
    r"\|\s*/bin/(\w+)",
    # 后台执行
    r"&\s*notepad",
    r"&\s*cmd",
    r"&\s*powershell",
    r"&\s*bash",
    r"&\s*sh\s",
    # 命令替换
    r"`[^`]+`",
    r"\$\([^)]+\)",
    # Python 动态执行
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__\s*\(",
    r"compile\s*\(",
    # 危险协议
    r"wget\s+http",
    r"curl\s+http",
    r"lynx\s+http",
    # 网络操作
    r"/etc/hosts",
    r"/etc/passwd",
    r"/etc/shadow",
    r"\\Windows\\System32\\",
    r"C:\\Windows\\System32\\",
    # 变量注入
    r"\$\{[^}]+\}",
    r"\$[a-zA-Z_][a-zA-Z0-9_]*",
    # 换行注入
    r"\n\s*rm\s",
    r"\n\s*cat\s",
    r"\n\s*wget\s",
]


class CommandInjectionDetector(BaseDetector):
    """命令注入检测器"""

    def __init__(self, config=None):
        super().__init__(config)
        self.patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in DEFAULT_PATTERNS]

    def detect(self, cmd: str, config=None) -> Optional[Dict[str, Any]]:
        """
        检测命令注入

        Args:
            cmd: 命令字符串
            config: 配置对象（可选）

        Returns:
            检测结果字典，如果未检测到威胁则返回 None
        """
        if not cmd or not isinstance(cmd, (str, bytes)):
            return None

        # 转换为字符串
        if isinstance(cmd, bytes):
            try:
                cmd = cmd.decode('utf-8', errors='ignore')
            except Exception:
                return None

        # 模式匹配
        for pattern in self.patterns:
            match = pattern.search(cmd)
            if match:
                return self._build_result(
                    pattern.pattern,
                    match.group(0),
                    match.start(),
                    match.end(),
                    cmd,
                )

        # 检查特殊字符
        dangerous_chars = self._check_dangerous_chars(cmd)
        if dangerous_chars:
            return dangerous_chars

        return None

    def _check_dangerous_chars(self, cmd: str) -> Optional[Dict[str, Any]]:
        """检查危险字符组合"""
        # 检查连续的特殊字符
        if re.search(r'[;&|`$]{2,}', cmd):
            return self._build_result(
                'multiple_special_chars',
                'Multiple special command characters detected',
                0,
                0,
                cmd,
            )

        # 检查换行符后跟命令
        if re.search(r'\n\s*[a-zA-Z]', cmd):
            return self._build_result(
                'newline_command_injection',
                'Newline followed by command character',
                0,
                0,
                cmd,
            )

        return None

    def _build_result(
        self,
        matched_pattern: str,
        matched_text: str,
        start: int,
        end: int,
        original_cmd: str,
    ) -> Dict[str, Any]:
        """构建检测结果"""
        return {
            'matched_pattern': matched_pattern,
            'matched_text': matched_text,
            'position': {'start': start, 'end': end},
            'evidence': self.get_evidence(original_cmd, start, end),
            'original_cmd': original_cmd[:500],
            'severity': 'high',
            'category': 'command_injection',
        }


def detect_command_injection(cmd: str, config=None) -> Optional[Dict[str, Any]]:
    """
    命令注入检测函数

    Args:
        cmd: 命令字符串
        config: 配置对象（可选）

    Returns:
        检测结果字典，如果未检测到威胁则返回 None
    """
    detector = CommandInjectionDetector(config)
    return detector.detect(cmd, config)