"""Shared pytest fixtures — generates binary TTY fixture files before tests run."""
import struct
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"

_HEADER_FMT  = "<iLiiLL"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)

OP_OPEN  = 1
OP_CLOSE = 2
OP_WRITE = 3
TYPE_INPUT  = 1
TYPE_OUTPUT = 2


def _pack_frame(op: int, direction: int, sec: int, usec: int, data: bytes = b"") -> bytes:
    return struct.pack(_HEADER_FMT, op, 0, len(data), direction, sec, usec) + data


@pytest.fixture(scope="session", autouse=True)
def tty_fixtures() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    # sample.tty — valid file with 3 output frames spread over 5 seconds
    sample = (
        _pack_frame(OP_OPEN,  0,          0,       0)
        + _pack_frame(OP_WRITE, TYPE_OUTPUT, 1,       0,      b"login: ")
        + _pack_frame(OP_WRITE, TYPE_OUTPUT, 1,  500_000,     b"Password: ")
        + _pack_frame(OP_WRITE, TYPE_OUTPUT, 3,  100_000,     b"$ ")
        + _pack_frame(OP_WRITE, TYPE_OUTPUT, 5,        0,     b"Welcome\r\n")
        + _pack_frame(OP_CLOSE, 0,         10,       0)
    )
    (FIXTURE_DIR / "sample.tty").write_bytes(sample)

    # truncated.tty — one complete frame followed by an incomplete header
    truncated = (
        _pack_frame(OP_WRITE, TYPE_OUTPUT, 1, 0, b"hello")
        + b"\x03\x00\x00\x00"   # half a header — truncated
    )
    (FIXTURE_DIR / "truncated.tty").write_bytes(truncated)

    # dead_air.tty — frames with an inter-frame gap > 2000 ms to test compression
    dead_air = (
        _pack_frame(OP_OPEN,  0,    0,   0)
        + _pack_frame(OP_WRITE, TYPE_OUTPUT,  1,       0, b"A")
        + _pack_frame(OP_WRITE, TYPE_OUTPUT, 10,       0, b"B")   # 9-second gap
        + _pack_frame(OP_WRITE, TYPE_OUTPUT, 10, 100_000, b"C")   # 100 ms gap
        + _pack_frame(OP_CLOSE, 0,   11,   0)
    )
    (FIXTURE_DIR / "dead_air.tty").write_bytes(dead_air)
