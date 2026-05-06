"""Unit tests for tty_reader."""
import struct
from pathlib import Path

import pytest

from app.tty_reader import (
    read_finite,
    DEAD_AIR_THRESHOLD_MS,
    DEAD_AIR_CLAMP_MS,
    _poisoned,
    OP_WRITE,
    TYPE_OUTPUT,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures"


# ── read_finite ────────────────────────────────────────────────────────────────

class TestReadFinite:
    def test_returns_list_of_tuples(self):
        frames = read_finite(FIXTURE_DIR / "sample.tty")
        assert isinstance(frames, list)
        assert all(isinstance(f, tuple) and len(f) == 2 for f in frames)

    def test_frame_count(self):
        # sample.tty has 4 OP_WRITE/OUTPUT frames (login: Password: $ Welcome)
        frames = read_finite(FIXTURE_DIR / "sample.tty")
        assert len(frames) == 4

    def test_data_bytes(self):
        frames = read_finite(FIXTURE_DIR / "sample.tty")
        payload = b"".join(data for _, data in frames)
        assert b"login: " in payload
        assert b"Password: " in payload
        assert b"$ " in payload
        assert b"Welcome" in payload

    def test_first_frame_delay_is_zero(self):
        frames = read_finite(FIXTURE_DIR / "sample.tty")
        assert frames[0][0] == 0

    def test_delays_are_non_negative(self):
        frames = read_finite(FIXTURE_DIR / "sample.tty")
        assert all(delay >= 0 for delay, _ in frames)

    def test_truncated_file_returns_partial(self):
        frames = read_finite(FIXTURE_DIR / "truncated.tty")
        # Should return the one complete frame without raising
        assert len(frames) == 1
        assert frames[0][1] == b"hello"

    def test_missing_file_returns_empty(self):
        frames = read_finite(Path("/nonexistent/path/file.tty"))
        assert frames == []

    def test_dead_air_compression(self):
        frames = read_finite(FIXTURE_DIR / "dead_air.tty")
        # Frame B has a 9-second gap which should be clamped to 500 ms
        delays = [d for d, _ in frames]
        for d in delays[1:]:
            assert d <= DEAD_AIR_CLAMP_MS or d < DEAD_AIR_THRESHOLD_MS

    def test_large_gap_clamped_to_500ms(self):
        frames = read_finite(FIXTURE_DIR / "dead_air.tty")
        # Frame B (index 1) had a 9s gap — must be clamped
        assert frames[1][0] == DEAD_AIR_CLAMP_MS

    def test_small_gap_preserved(self):
        frames = read_finite(FIXTURE_DIR / "dead_air.tty")
        # Frame C (index 2) had a 100ms gap — should remain 100ms
        assert frames[2][0] == 100

    def test_poisoned_file_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.tty"
        bad.write_bytes(b"\xff\xff\xff\xff" * 10)
        frames = read_finite(bad)
        assert frames == []


# ── parametrize dead-air boundary ─────────────────────────────────────────────

@pytest.mark.parametrize("gap_ms, expected", [
    (0,    0),
    (1999, 1999),
    (2000, 2000),   # threshold is > 2000, so 2000 is kept
    (2001, 500),    # exceeds threshold → clamp
    (10000, 500),
])
def test_dead_air_boundary(gap_ms, expected):
    from app.tty_reader import _apply_dead_air
    prev = 0
    cur  = gap_ms
    result = _apply_dead_air(prev, cur)
    assert result == expected
