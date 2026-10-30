"""SQL 相关函数 Hook 模块"""
import sys
import functools
import logging
from typing import Any, Callable, Optional

from ..config import RASPConfig
from ..detector.sql_injection import detect_sql_injection


logger = logging.getLogger(__name__)

# 原始函数存储
_original_functions = {}


def _create_wrapper(func: Callable, func_name: str, config: RASPConfig) -> Callable:
    """创建包装器函数"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # 检查 SQL 参数
        for arg in args:
            if isinstance(arg, str) and any(key in func_name.lower() for key in ['execute', 'query', 'sql']):
                result = detect_sql_injection(arg, config)
                if result:
                    _report_detection('sql_injection', result, func_name, args)

        # 检查关键字参数
        for key, value in kwargs.items():
            if isinstance(value, str):
                result = detect_sql_injection(value, config)
                if result:
                    _report_detection('sql_injection', result, func_name, kwargs)

        return func(*args, **kwargs)

    return wrapper


def _report_detection(event_type: str, result: dict, func_name: str, args: Any, enforce: bool = True) -> None:
    from ..blocking import handle_detection
    handle_detection(event_type, result, func_name, args, enforce=enforce)


def _patch_sqlite3() -> None:
    """Patch sqlite3 module"""
    try:
        import sqlite3
        _original_functions['sqlite3_Cursor_execute'] = sqlite3.Cursor.execute
        _original_functions['sqlite3_Cursor_executemany'] = sqlite3.Cursor.executemany

        # 注意：sqlite3.Cursor 是内部类，方法不能在类级别 patch
        # 需要在连接创建时 patch
        _original_functions['sqlite3_connect'] = sqlite3.connect

        def patched_connect(*args, **kwargs):
            conn = _original_functions['sqlite3_connect'](*args, **kwargs)
            # 包装游标方法
            original_cursor = conn.cursor

            def patched_cursor():
                cursor = original_cursor()
                cursor.execute = functools.partial(
                    _create_wrapper(cursor.execute, 'sqlite3.Cursor.execute', None),
                )
                cursor.executemany = functools.partial(
                    _create_wrapper(cursor.executemany, 'sqlite3.Cursor.executemany', None),
                )
                return cursor

            conn.cursor = patched_cursor
            return conn

        sqlite3.connect = patched_connect
        logger.info("sqlite3 hooks applied")
    except ImportError:
        logger.debug("sqlite3 not available")


def _patch_psycopg2() -> None:
    """Patch psycopg2 module"""
    try:
        import psycopg2
        from psycopg2 import extensions

        _original_functions['psycopg2_cursor_execute'] = psycopg2.extensions.cursor.execute

        def patched_cursor_execute(self, query, params=None):
            result = detect_sql_injection(str(query))
            if result:
                _report_detection('sql_injection', result, 'psycopg2.cursor.execute', query)
            return _original_functions['psycopg2_cursor_execute'](self, query, params)

        psycopg2.extensions.cursor.execute = patched_cursor_execute
        logger.info("psycopg2 hooks applied")
    except ImportError:
        logger.debug("psycopg2 not available")


def _patch_mysql_connector() -> None:
    """Patch mysql-connector module"""
    try:
        import mysql.connector.cursor

        _original_functions['mysql_cursor_execute'] = mysql.connector.cursor.Cursor.execute
        _original_functions['mysql_cursor_executemany'] = mysql.connector.cursor.Cursor.executemany

        def patched_execute(self, operation, params=None, multi=False):
            result = detect_sql_injection(str(operation))
            if result:
                _report_detection('sql_injection', result, 'mysql.cursor.execute', operation)
            return _original_functions['mysql_cursor_execute'](self, operation, params, multi)

        mysql.connector.cursor.Cursor.execute = patched_execute
        logger.info("mysql-connector hooks applied")
    except ImportError:
        logger.debug("mysql-connector not available")


def _patch_pymongo() -> None:
    """Patch pymongo module"""
    try:
        import pymongo.collection

        _original_functions['pymongo_find'] = pymongo.collection.Collection.find
        _original_functions['pymongo_find_one'] = pymongo.collection.Collection.find_one

        def patched_find(self, filter=None, *args, **kwargs):
            if filter and isinstance(filter, str):
                result = detect_sql_injection(filter)
                if result:
                    _report_detection('sql_injection', result, 'pymongo.find', filter)
            return _original_functions['pymongo_find'](self, filter, *args, **kwargs)

        pymongo.collection.Collection.find = patched_find
        logger.info("pymongo hooks applied")
    except ImportError:
        logger.debug("pymongo not available")


def patch() -> None:
    """应用 SQL 相关 Hook"""
    _patch_sqlite3()
    _patch_psycopg2()
    _patch_mysql_connector()
    _patch_pymongo()


def unpatch() -> None:
    """卸载 SQL 相关 Hook"""
    # 恢复 sqlite3
    try:
        import sqlite3
        if 'sqlite3_connect' in _original_functions:
            sqlite3.connect = _original_functions['sqlite3_connect']
    except ImportError:
        pass

    # 恢复 psycopg2
    try:
        import psycopg2.extensions
        if 'psycopg2_cursor_execute' in _original_functions:
            psycopg2.extensions.cursor.execute = _original_functions['psycopg2_cursor_execute']
    except ImportError:
        pass

    # 恢复 mysql-connector
    try:
        import mysql.connector.cursor
        if 'mysql_cursor_execute' in _original_functions:
            mysql.connector.cursor.Cursor.execute = _original_functions['mysql_cursor_execute']
    except ImportError:
        pass

    # 恢复 pymongo
    try:
        import pymongo.collection
        if 'pymongo_find' in _original_functions:
            pymongo.collection.Collection.find = _original_functions['pymongo_find']
    except ImportError:
        pass

    _original_functions.clear()
    logger.info("SQL hooks unloaded")