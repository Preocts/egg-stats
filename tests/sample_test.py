from __future__ import annotations

from egg_stats import sample


def test_main():
    """Test main."""
    assert sample.main()


def test_squared():
    """Test squared."""
    assert sample.squared(2) == 4


def test_isodd():
    """Test isodd."""
    assert sample.isodd(2) is False
    assert sample.isodd(3) is True
