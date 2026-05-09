"""检测器模块"""
from . import sql_injection
from . import command_injection
from . import file_access
from . import deserialize

__all__ = [
    'sql_injection',
    'command_injection',
    'file_access',
    'deserialize',
]