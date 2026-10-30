import pytest

from ly_rasp.bridge import ConfigIntegrityError, parse_config_expiry


def test_parse_config_expiry_accepts_nanoseconds_and_z():
    value = parse_config_expiry("2026-10-30T17:00:00.123456789Z")
    assert value.year == 2026
    assert value.microsecond == 123456
    assert value.utcoffset().total_seconds() == 0


def test_parse_config_expiry_accepts_offset():
    value = parse_config_expiry("2026-10-30T17:00:00+08:00")
    assert value.utcoffset().total_seconds() == 8 * 3600


@pytest.mark.parametrize("raw", ["", "not-a-time", "2026-10-30T17:00:00"])
def test_parse_config_expiry_rejects_invalid(raw):
    with pytest.raises(ConfigIntegrityError):
        parse_config_expiry(raw)

def test_parse_config_expiry_allows_missing():
    assert parse_config_expiry(None) is None
