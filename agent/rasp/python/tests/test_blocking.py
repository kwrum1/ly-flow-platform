import pytest

from ly_rasp.blocking import RASPBlockedError, handle_detection
from ly_rasp.config import RASPConfig, set_config
from ly_rasp.reporter import set_reporter


class RecordingReporter:
    def __init__(self):
        self.events = []

    def report(self, event):
        self.events.append(event)
        return True


def _activate(mode, block_on_hit):
    config = RASPConfig(mode=mode, block_on_hit=block_on_hit, policy_version=9)
    set_config(config)
    reporter = RecordingReporter()
    set_reporter(reporter)
    return reporter


def teardown_function():
    set_config(None)
    set_reporter(None)


def test_dry_run_reports_would_block_without_raising():
    reporter = _activate('block', False)

    handle_detection('command_injection', {'matched_pattern': '; rm'}, 'os.system', 'id; rm -rf /')

    assert len(reporter.events) == 1
    event = reporter.events[0]
    assert event['blocked'] is False
    assert event['would_block'] is True
    assert event['action'] == 'log'


def test_promoted_policy_raises_and_reports_block():
    reporter = _activate('block', True)

    with pytest.raises(RASPBlockedError):
        handle_detection('sql_injection', {'matched_pattern': 'UNION SELECT'}, 'Cursor.execute', 'x UNION SELECT y')

    event = reporter.events[0]
    assert event['blocked'] is True
    assert event['would_block'] is False
    assert event['action'] == 'block'


def test_monitor_policy_never_blocks():
    reporter = _activate('monitor', True)

    handle_detection('command_injection', {'matched_pattern': '; rm'}, 'os.system', 'id')

    assert reporter.events[0]['blocked'] is False
    assert reporter.events[0]['would_block'] is False
