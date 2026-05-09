"""敏感文件访问检测器"""
import re
import os
from typing import Optional, Dict, Any

from .base import BaseDetector


# 默认敏感路径模式
DEFAULT_SENSITIVE_PATHS = [
    # Unix 密码和认证文件
    r"/etc/passwd",
    r"/etc/shadow",
    r"/etc/sudoers",
    r"/etc/sudoers\.d/",
    r"/etc/pam\.d/",
    r"/etc/security/",
    r"/etc/ssh/ssh_host",
    # 进程信息
    r"/proc/self/",
    r"/proc/environ",
    r"/proc/cmdline",
    r"/proc/[0-9]+/mem",
    r"/proc/[0-9]+/maps",
    # SSH 和密钥
    r"\.ssh/authorized_keys",
    r"\.ssh/id_rsa",
    r"\.ssh/id_dsa",
    r"\.ssh/id_ed25519",
    r"\.ssh/known_hosts",
    r"/root/\.ssh/",
    r"/home/[^/]+/\.ssh/",
    # Shell 历史
    r"\.bash_history",
    r"\.bashrc",
    r"\.profile",
    r"\.zsh_history",
    r"\.zshrc",
    # Windows 系统文件
    r"C:\\Windows\\System32\\config\\SAM",
    r"C:\\Windows\\System32\\config\\SYSTEM",
    r"C:\\Windows\\System32\\config\\SECURITY",
    r"C:\\Windows\\System32\\config\\SOFTWARE",
    r"C:\\Windows\\System32\\drivers\\etc\\hosts",
    r"\\System32\\config\\SAM",
    r"\\System32\\config\\SYSTEM",
    # 其他敏感文件
    r"\/\.aws/credentials",
    r"\/\.aws/config",
    r"\/\.git/config",
    r"\/\.git/credentials",
    r"\/\.env",
    r"\/\.npmrc",
    r"\/\.pypirc",
]


class FileAccessDetector(BaseDetector):
    """敏感文件访问检测器"""

    def __init__(self, config=None):
        super().__init__(config)
        self.patterns = [re.compile(p, re.IGNORECASE) for p in DEFAULT_SENSITIVE_PATHS]

    def detect(self, path: str, config=None) -> Optional[Dict[str, Any]]:
        """
        检测敏感文件访问

        Args:
            path: 文件路径
            config: 配置对象（可选）

        Returns:
            检测结果字典，如果未检测到威胁则返回 None
        """
        if not path or not isinstance(path, (str, bytes)):
            return None

        # 转换为字符串
        if isinstance(path, bytes):
            try:
                path = path.decode('utf-8', errors='ignore')
            except Exception:
                return None

        # 规范化路径
        normalized_path = self._normalize_path(path)

        # 模式匹配
        for pattern in self.patterns:
            match = pattern.search(normalized_path)
            if match:
                return self._build_result(
                    pattern.pattern,
                    match.group(0),
                    match.start(),
                    match.end(),
                    path,
                    normalized_path,
                )

        # 检查路径遍历攻击
        traversal_result = self._check_path_traversal(path, normalized_path)
        if traversal_result:
            return traversal_result

        return None

    def _normalize_path(self, path: str) -> str:
        """规范化路径"""
        # 替换反斜杠为正斜杠
        path = path.replace('\\', '/')

        # 移除多余的斜杠
        while '//' in path:
            path = path.replace('//', '/')

        # 移除 ./ 
        path = re.sub(r'/\./', '/', path)

        # 解析 ../ 
        parts = path.split('/')
        result = []
        for part in parts:
            if part == '..':
                if result and result[-1] != '..':
                    result.pop()
                else:
                    result.append(part)
            else:
                result.append(part)

        return '/'.join(result)

    def _check_path_traversal(self, original_path: str, normalized_path: str) -> Optional[Dict[str, Any]]:
        """检查路径遍历攻击"""
        # 检测 ../../../etc/passwd 类型的攻击
        if normalized_path.count('../') >= 2:
            return self._build_result(
                'path_traversal',
                'Path traversal detected',
                original_path.find('../'),
                original_path.find('../') + 3,
                original_path,
                normalized_path,
            )

        # 检测包含 /../ 的路径
        if '/../' in normalized_path or normalized_path.startswith('../'):
            return self._build_result(
                'path_traversal',
                'Path traversal pattern detected',
                0,
                len(original_path),
                original_path,
                normalized_path,
            )

        return None

    def _build_result(
        self,
        matched_pattern: str,
        matched_text: str,
        start: int,
        end: int,
        original_path: str,
        normalized_path: str,
    ) -> Dict[str, Any]:
        """构建检测结果"""
        return {
            'matched_pattern': matched_pattern,
            'matched_text': matched_text,
            'path': original_path,
            'normalized_path': normalized_path,
            'evidence': f"Accessing sensitive path: {matched_text}",
            'severity': 'medium',
            'category': 'sensitive_file_access',
        }


def detect_sensitive_file(path: str, config=None) -> Optional[Dict[str, Any]]:
    """
    敏感文件检测函数

    Args:
        path: 文件路径
        config: 配置对象（可选）

    Returns:
        检测结果字典，如果未检测到威胁则返回 None
    """
    detector = FileAccessDetector(config)
    return detector.detect(path, config)