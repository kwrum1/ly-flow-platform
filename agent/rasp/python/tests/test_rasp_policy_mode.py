from ly_rasp.config import RASPConfig, normalize_mode, should_block


def test_invalid_mode_falls_back_to_monitor():
    assert normalize_mode("godmode") == "monitor"


def test_protect_mode_blocks_only_when_enabled():
    assert should_block(RASPConfig(mode="protect", block_on_hit=True)) is True
    assert should_block(RASPConfig(mode="protect", block_on_hit=False)) is False
    assert should_block(RASPConfig(mode="monitor", block_on_hit=True)) is False
