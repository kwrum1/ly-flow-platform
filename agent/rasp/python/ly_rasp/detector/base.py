"""检测器基类"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
import re


class BaseDetector(ABC):
    """检测器基类"""

    def __init__(self, config=None):
        self.config = config
        self.patterns: List[re.Pattern] = []

    @abstractmethod
    def detect(self, *args, **kwargs) -> Optional[Dict[str, Any]]:
        """
        执行检测

        Returns:
            检测结果字典，如果未检测到威胁则返回 None
        """
        pass

    def match_pattern(self, text: str, patterns: Optional[List[str]] = None) -> Optional[str]:
        """
        匹配模式

        Args:
            text: 待检测文本
            patterns: 模式列表，如果为 None 则使用 self.patterns

        Returns:
            匹配到的模式名称，未匹配则返回 None
        """
        if patterns is None:
            patterns = [p.pattern if hasattr(p, 'pattern') else str(p) for p in self.patterns]

        for pattern in patterns:
            try:
                if isinstance(pattern, str):
                    compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                else:
                    compiled = pattern

                match = compiled.search(text)
                if match:
                    return match.group(0)
            except re.error:
                continue

        return None

    def get_evidence(self, text: str, start: int, end: int, context_len: int = 30) -> str:
        """
        获取匹配的证据上下文

        Args:
            text: 原始文本
            start: 匹配开始位置
            end: 匹配结束位置
            context_len: 上下文长度

        Returns:
            包含上下文的证据字符串
        """
        start_idx = max(0, start - context_len)
        end_idx = min(len(text), end + context_len)

        evidence = text[start_idx:end_idx]
        if start_idx > 0:
            evidence = f"...{evidence}"
        if end_idx < len(text):
            evidence = f"{evidence}..."

        return evidence