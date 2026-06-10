"""DoS-bound input limits + typed errors for the Python compiler frontend.

Mirrors ``InputLimits`` from ``packages/runar-ir-schema/src/input-limits.ts``.
See ``compilers/go/frontend/input_limits.go`` for the reference shape.
"""

from __future__ import annotations


# Mirrors ``InputLimits.MAX_SOURCE_BYTES`` (4 MiB) from the TS schema package.
# Rúnar source files larger than this are rejected at the parser entry
# point (``parse_source``) BEFORE the tokenizer touches the input.
# BUG-008 follow-up.
MAX_SOURCE_BYTES: int = 4 * 1024 * 1024


class SourceSizeExceededError(Exception):
    """Raised when a source payload exceeds :data:`MAX_SOURCE_BYTES` at a
    public parser entry point. Distinct typed exception so callers can
    distinguish DoS-bound rejection from generic syntax errors."""

    def __init__(self, limit: int, actual: int) -> None:
        super().__init__(
            f"source exceeds MAX_SOURCE_BYTES (limit={limit}, actual={actual})"
        )
        self.limit = limit
        self.actual = actual


def assert_source_bytes_under_limit(source: str) -> None:
    """Raise :class:`SourceSizeExceededError` if ``source`` (encoded as
    UTF-8) exceeds :data:`MAX_SOURCE_BYTES`."""
    n = len(source.encode("utf-8"))
    if n > MAX_SOURCE_BYTES:
        raise SourceSizeExceededError(limit=MAX_SOURCE_BYTES, actual=n)
