import pytest

from sphinx_win.core.querylog import QueryLog


def test_ring_buffer_caps_and_evicts_oldest():
    log = QueryLog(capacity=3)
    for i in range(5):
        log.record(f"host{i}.example.com", blocked=False, timestamp_ms=i)
    assert len(log) == 3
    names = [e.name for e in log.snapshot()]
    assert names == ["host4.example.com", "host3.example.com", "host2.example.com"]


def test_snapshot_newest_first_and_is_a_copy():
    log = QueryLog()
    log.record("a.example.com", True, 1)
    log.record("b.example.com", False, 2)
    snap = log.snapshot()
    assert [e.name for e in snap] == ["b.example.com", "a.example.com"]
    snap.clear()
    assert len(log) == 2  # mutating the snapshot doesn't touch the log


def test_clear():
    log = QueryLog()
    log.record("a.example.com", True, 1)
    log.clear()
    assert len(log) == 0
    assert log.snapshot() == []


def test_capacity_must_be_positive():
    with pytest.raises(ValueError):
        QueryLog(capacity=0)


def test_default_capacity_is_500():
    log = QueryLog()
    for i in range(600):
        log.record(f"h{i}.example.com", False, i)
    assert len(log) == 500
