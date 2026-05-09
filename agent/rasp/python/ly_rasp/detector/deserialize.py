"""反序列化漏洞检测器"""
import re
import os
from typing import Optional, Dict, Any

from .base import BaseDetector


# Pickle 恶意类标记
PICKLE_GADGET_PATTERNS = [
    # 常见危险模块
    r'subprocess',
    r'os\.system',
    r'os\.popen',
    r'pty\.spawn',
    r'socket\.create_connection',
    r'urllib\.request',
    r'http\.client',
    r'telnetlib',
    r'ssh\.SSHClient',
    r'docker',
    r'kubernetes',
    # 代码执行基类
    r'code\.InteractiveInterpreter',
    r'base64\.b64decode',
    r'codecs\.decode',
    # 危险导入
    r'import\s+os',
    r'import\s+subprocess',
    r'import\s+socket',
    r'import\s+pty',
]

# YAML 危险标签
YAML_DANGEROUS_TAGS = [
    '!!python/object/apply:',
    '!!python/object/lookup:',
    '!!python/object:',
    '!!python/name:',
    '!!exec',
    '!!eval',
    'tag:yaml.org,2002:python/object/apply',
    'tag:yaml.org,2002:python/object',
]


class DeserializeDetector(BaseDetector):
    """反序列化漏洞检测器"""

    def __init__(self, config=None):
        super().__init__(config)
        self.pickle_patterns = [re.compile(p, re.IGNORECASE) for p in PICKLE_GADGET_PATTERNS]
        self.yaml_tags = YAML_DANGEROUS_TAGS

    def detect_pickle(self, data: bytes, config=None) -> Optional[Dict[str, Any]]:
        """
        检测 pickle 反序列化攻击

        Args:
            data: Pickle 数据
            config: 配置对象（可选）

        Returns:
            检测结果字典，如果未检测到威胁则返回 None
        """
        if not data or not isinstance(data, bytes):
            return None

        # 检查 pickle 操作码
        dangerous_opcodes = [
            b'c',   # GLOBAL
            b'o',   # OBJ
            b't',   # INST
            b'R',   # REDUCE
            b'v',   # BUILD
            b'eval',  # Python 2 compatibility
        ]

        for opcode in dangerous_opcodes:
            if opcode in data:
                return self._build_result(
                    'pickle_opcode',
                    f'Dangerous pickle opcode: {opcode.decode()}',
                    data.index(opcode),
                    data.index(opcode) + len(opcode),
                    data,
                    'pickle',
                )

        # 检查是否包含可执行的 Python 代码
        for pattern in self.pickle_patterns:
            try:
                data_str = data.decode('latin-1')
                match = pattern.search(data_str)
                if match:
                    return self._build_result(
                        'pickle_gadget',
                        match.group(0),
                        match.start(),
                        match.end(),
                        data,
                        'pickle',
                    )
            except Exception:
                continue

        return None

    def detect_yaml(self, data: str, config=None) -> Optional[Dict[str, Any]]:
        """
        检测 YAML 反序列化攻击

        Args:
            data: YAML 字符串
            config: 配置对象（可选）

        Returns:
            检测结果字典，如果未检测到威胁则返回 None
        """
        if not data or not isinstance(data, (str, dict)):
            return None

        # 如果是字典，转换为 YAML 字符串表示
        if isinstance(data, dict):
            return None  # 正常字典不需要检查

        data_str = str(data)

        # 检查危险标签
        for tag in self.yaml_tags:
            if tag in data_str:
                return self._build_result(
                    'yaml_dangerous_tag',
                    f'Dangerous YAML tag: {tag}',
                    data_str.index(tag),
                    data_str.index(tag) + len(tag),
                    data_str,
                    'yaml',
                )

        # 检查 Python 对象序列化模式
        python_object_patterns = [
            r'!!python/object/apply',
            r'!!python/object/lookup',
            r'!!python/object:',
            r'!!python/name:',
        ]

        for pattern in python_object_patterns:
            match = re.search(pattern, data_str)
            if match:
                return self._build_result(
                    'yaml_python_object',
                    match.group(0),
                    match.start(),
                    match.end(),
                    data_str,
                    'yaml',
                )

        return None

    def _build_result(
        self,
        matched_pattern: str,
        matched_text: str,
        start: int,
        end: int,
        original_data: Any,
        serialize_type: str,
    ) -> Dict[str, Any]:
        """构建检测结果"""
        # 截断原始数据
        if isinstance(original_data, bytes):
            data_preview = original_data[:100].hex()
        else:
            data_preview = str(original_data)[:100]

        return {
            'matched_pattern': matched_pattern,
            'matched_text': matched_text,
            'serialize_type': serialize_type,
            'data_preview': data_preview,
            'severity': 'critical',
            'category': 'deserialize_injection',
        }


def detect_pickle_injection(data: bytes, config=None) -> Optional[Dict[str, Any]]:
    """
    Pickle 反序列化漏洞检测函数

    Args:
        data: Pickle 数据
        config: 配置对象（可选）

    Returns:
        检测结果字典，如果未检测到威胁则返回 None
    """
    detector = DeserializeDetector(config)
    return detector.detect_pickle(data, config)


def detect_yaml_injection(data: str, config=None) -> Optional[Dict[str, Any]]:
    """
    YAML 反序列化漏洞检测函数

    Args:
        data: YAML 字符串
        config: 配置对象（可选）

    Returns:
        检测结果字典，如果未检测到威胁则返回 None
    """
    detector = DeserializeDetector(config)
    return detector.detect_yaml(data, config)