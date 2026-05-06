"""Parse Cowrie TTY binary recordings and yield (delay_ms, data) frames."""
import struct
from pathlib import Path

# Cowrie TTY opcodes (from cowrie/scripts/playlog.py)
OP_OPEN = 1
OP_CLOSE = 2
OP_WRITE = 3
OP_EXEC = 4

TYPE_INPUT = 1
TYPE_OUTPUT = 2
TYPE_INTERACT = 3

HEADER_FMT = "<iLiiLL"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# Dead-air compression: gaps longer than this are clamped to CLAMP
DEAD_AIR_THRESHOLD_MS = 2000
DEAD_AIR_CLAMP_MS = 500

# Poisoned files are skipped for the lifetime of the process
_poisoned: set[Path] = set()


def _read_frames(data: bytes) -> list[tuple[int, int, int, int, bytes]]:
    """Parse all complete frames from raw bytes. Returns (op, direction, sec, usec, payload)."""
    frames = []
    offset = 0
    while offset + HEADER_SIZE <= len(data):
        try:
            op, _tty, length, direction, sec, usec = struct.unpack_from(
                HEADER_FMT, data, offset
            )
        except struct.error:
            break
        offset += HEADER_SIZE
        payload = data[offset : offset + length]
        if len(payload) < length:
            break
        offset += length
        frames.append((op, direction, sec, usec, payload))
    return frames


def _infer_output_direction(frames: list[tuple]) -> int:
    """Return the first non-interact direction seen — that's the output direction."""
    for op, direction, *_ in frames:
        if op == OP_WRITE and direction != TYPE_INTERACT:
            return direction
    return TYPE_OUTPUT


def _apply_dead_air(prev_ms: int, cur_ms: int) -> int:
    gap = cur_ms - prev_ms
    return DEAD_AIR_CLAMP_MS if gap > DEAD_AIR_THRESHOLD_MS else gap


def read_finite(path: Path) -> list[tuple[int, bytes]]:
    """
    Read a complete TTY file and return (delay_ms, data) tuples.
    Returns [] for poisoned or unreadable files.
    """
    path = Path(path)
    if path in _poisoned:
        return []
    try:
        raw = path.read_bytes()
    except OSError:
        return []

    try:
        frames = _read_frames(raw)
    except Exception:
        _poisoned.add(path)
        return []

    if not frames:
        return []

    output_dir = _infer_output_direction(frames)
    result: list[tuple[int, bytes]] = []
    prev_ms = 0

    for op, direction, sec, usec, payload in frames:
        if op != OP_WRITE:
            continue
        if direction != output_dir and direction != TYPE_INTERACT:
            continue
        cur_ms = sec * 1000 + usec // 1000
        delay = _apply_dead_air(prev_ms, cur_ms) if result else 0
        prev_ms = cur_ms
        result.append((delay, payload))

    return result


async def tail(
    path: Path,
    stop_event,
    poll_interval: float = 0.1,
):
    """
    Follow a TTY file as it grows. Yields (delay_ms, data).
    Terminates when stop_event is set.
    """
    import asyncio

    path = Path(path)
    if path in _poisoned:
        return

    offset = 0
    prev_ms = 0
    output_dir: int | None = None

    while not stop_event.is_set():
        try:
            raw = path.read_bytes()
        except OSError:
            await asyncio.sleep(poll_interval)
            continue

        new_data = raw[offset:]
        if not new_data:
            await asyncio.sleep(poll_interval)
            continue

        try:
            frames = _read_frames(new_data)
        except Exception:
            _poisoned.add(path)
            return

        offset = len(raw)

        if output_dir is None and frames:
            output_dir = _infer_output_direction(frames)

        for op, direction, sec, usec, payload in frames:
            if op != OP_WRITE:
                continue
            if output_dir is not None and direction != output_dir and direction != TYPE_INTERACT:
                continue
            cur_ms = sec * 1000 + usec // 1000
            delay = _apply_dead_air(prev_ms, cur_ms) if prev_ms else 0
            prev_ms = cur_ms
            yield delay, payload

        await asyncio.sleep(poll_interval)
