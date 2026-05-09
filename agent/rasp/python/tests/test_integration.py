"""集成测试"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestIntegration:
    """集成测试"""

    def test_config_loading(self):
        """测试配置加载"""
        from ly_rasp.config import RASPConfig, load_config

        config = load_config(server_addr="localhost:6379", agent_id="test-agent")
        assert config.server_addr == "localhost:6379"
        assert config.agent_id == "test-agent"
        assert config.sql_enabled is True

    def test_sql_detector_integration(self):
        """测试 SQL 检测器集成"""
        from ly_rasp.detector.sql_injection import detect_sql_injection
        from ly_rasp.config import RASPConfig

        config = RASPConfig()
        config.sql_block_patterns = [r"OR\s+1\s*=\s*1"]

        sql = "SELECT * FROM users WHERE id=1 OR 1=1"
        result = detect_sql_injection(sql, config)
        assert result is not None

    def test_reporter_initialization(self):
        """测试上报器初始化"""
        from ly_rasp.config import RASPConfig
        from ly_rasp.reporter import Reporter

        config = RASPConfig(server_addr="localhost:6379", agent_id="test")
        # 不连接真实 Redis，只测试初始化
        config.server_addr = "nonexistent:9999"  # 使用不存在的地址
        reporter = Reporter(config)
        # 应该优雅失败，不抛出异常
        assert reporter is not None

    def test_tracer_function(self):
        """测试追踪器函数结构"""
        from ly_rasp.tracer import rasp_trace

        # 追踪器函数应该可以接受任何参数
        result = rasp_trace(None, 'call', None)
        assert result == rasp_trace  # 应该返回自身以继续追踪


class TestEndToEnd:
    """端到端测试"""

    def test_full_detection_flow(self):
        """测试完整检测流程"""
        from ly_rasp.config import RASPConfig, load_config
        from ly_rasp.detector.sql_injection import detect_sql_injection

        # 1. 加载配置
        config = load_config(server_addr="localhost:6379", agent_id="e2e-test")

        # 2. 创建检测器
        from ly_rasp.detector.sql_injection import SQLInjectionDetector
        detector = SQLInjectionDetector(config)

        # 3. 执行检测
        malicious_sql = "SELECT * FROM users; DROP TABLE users"
        result = detector.detect(malicious_sql, config)

        # 4. 验证结果
        assert result is not None
        assert result.get('category') == 'sql_injection'
        assert result.get('severity') == 'high'
        assert 'matched_pattern' in result
        assert 'matched_text' in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])