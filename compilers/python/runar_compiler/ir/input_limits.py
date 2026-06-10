"""DoS-bound input limits + typed errors for the Python ANF IR loader.

Mirrors ``InputLimits`` from ``packages/runar-ir-schema/src/input-limits.ts``
and the Go reference at ``compilers/go/ir/input_limits.go``.

BUG-008 follow-up.
"""

from __future__ import annotations


#: Mirrors InputLimits.MAX_IR_BYTES (16 MiB) from the TS schema package.
#: Any ANF IR JSON larger than this is rejected at the loader entry point
#: (``load_ir``) BEFORE ``json.loads`` runs.
MAX_IR_BYTES: int = 16 * 1024 * 1024

#: Mirrors InputLimits.MAX_NESTING (512) from the TS schema package.
#: ANF IR JSON whose structural nesting (objects + arrays) exceeds this
#: is rejected.
MAX_IR_NESTING: int = 512


class IRSizeExceededError(Exception):
    """Raised when an IR JSON payload exceeds :data:`MAX_IR_BYTES` at a
    public loader entry point. Distinct typed exception so callers can
    distinguish DoS-bound rejection from generic deserialisation
    failures."""

    def __init__(self, limit: int, actual: int) -> None:
        super().__init__(
            f"IR JSON exceeds MAX_IR_BYTES (limit={limit}, actual={actual})"
        )
        self.limit = limit
        self.actual = actual


class IRNestingExceededError(Exception):
    """Raised when an IR JSON payload's structural nesting (objects +
    arrays) exceeds :data:`MAX_IR_NESTING`."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"IR JSON nesting exceeds MAX_NESTING (limit={limit})")
        self.limit = limit


def assert_ir_bytes_under_limit(data: bytes | str) -> None:
    """Raise :class:`IRSizeExceededError` if ``data`` exceeds
    :data:`MAX_IR_BYTES`."""
    if isinstance(data, str):
        n = len(data.encode("utf-8"))
    else:
        n = len(data)
    if n > MAX_IR_BYTES:
        raise IRSizeExceededError(limit=MAX_IR_BYTES, actual=n)


def assert_ir_nesting_under_limit(data: bytes | str) -> None:
    """Walk the raw JSON bytes and raise :class:`IRNestingExceededError`
    the first time the nesting depth (objects + arrays) exceeds
    :data:`MAX_IR_NESTING`. Runs BEFORE ``json.loads`` so a deeply-nested
    payload cannot exhaust the Python interpreter's recursion stack.

    Skips strings (respecting backslash-escapes) so a ``{`` inside a JSON
    string doesn't count toward depth.
    """
    if isinstance(data, str):
        buf = data.encode("utf-8")
    else:
        buf = data
    depth = 0
    in_string = False
    escaped = False
    for b in buf:
        if in_string:
            if escaped:
                escaped = False
                continue
            if b == 0x5C:  # '\\'
                escaped = True
                continue
            if b == 0x22:  # '"'
                in_string = False
            continue
        if b == 0x22:  # '"'
            in_string = True
        elif b == 0x7B or b == 0x5B:  # '{' or '['
            depth += 1
            if depth > MAX_IR_NESTING:
                raise IRNestingExceededError(limit=MAX_IR_NESTING)
        elif b == 0x7D or b == 0x5D:  # '}' or ']'
            if depth > 0:
                depth -= 1
