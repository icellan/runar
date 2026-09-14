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


class IRFloatValueError(Exception):
    """Raised when an IR JSON payload contains a number written in float
    syntax. N-131.

    The ANF IR has no float-typed field. The schema
    (``packages/runar-ir-schema/src/schemas/anf-ir.schema.json``) types
    ``loop.count``, ``loop.step`` and the ``raw_script`` arities as
    ``integer``, and ``loop.start`` / ``load_const.value`` as
    integer-or-string; an oversize value is written as a decimal string with
    an ``n`` suffix. So what the six ``--ir`` tiers did with a float was
    unspecified, and they disagreed in emitted BYTES: ``{"start":1e30}``
    produced three different answers, and this tier read ``{"step":1.5}`` as
    ``step = 1`` while Ruby read it as ``1.5`` and unrolled ``i`` over
    ``0,1,3,4,6``.

    The rule is LEXICAL — float syntax, not fractional value — so ``1.0`` and
    ``1e2`` are refused too. That is what Go and Java, the two tiers already
    correct here, do, and it is the line every tier's JSON parser already
    draws at the token rather than the value.
    """

    def __init__(self, token: str) -> None:
        super().__init__(
            f"IR JSON contains a floating-point number ({token}); every "
            f"numeric field in the ANF IR is an integer (write an oversize "
            f"value as a decimal string with an `n` suffix)"
        )
        self.token = token


def reject_json_float(token: str):
    """``json.loads(parse_float=...)`` hook: refuse the number outright.

    CPython calls this for every number token containing a ``.`` or an
    exponent and hands over the token VERBATIM, which is precisely the
    lexical rule N-131 settles on — so the stdlib scanner does the
    classification and there is no hand-written number scanner in this tier
    to get wrong. It runs DURING parsing, before the ``float`` ever exists,
    which matters: the old failure was not the parse but what came after it.
    """
    raise IRFloatValueError(token)


def reject_json_constant(token: str):
    """``json.loads(parse_constant=...)`` hook: refuse ``NaN`` / ``Infinity``.

    CPython's ``json`` accepts these three JSON extensions by default; no
    other tier's parser does (Go, serde_json, Ruby and std.json all reject
    them as syntax errors). Today this tier still refuses them, but by
    raising out of a later ``int()`` conversion — an accident, not a rule.
    Refusing them here makes the rejection deliberate and keeps the reason
    the same one the peers give.
    """
    raise IRFloatValueError(token)
