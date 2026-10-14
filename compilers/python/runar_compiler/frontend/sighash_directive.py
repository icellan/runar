"""``@sighash`` directive parsing (issue #123).

A public method may carry a ``/** @sighash <FLAGS> */`` comment directive that
declares which BIP-143 sighash type its auto-injected covenant (and the
SDK-built preimage) commits to. ``<FLAGS>`` is a ``|``-separated set of SigHash
names, e.g. ``SINGLE|FORKID``, ``ALL|ANYONECANPAY|FORKID``, ``NONE|FORKID``.

The default (no directive) is ``ALL|FORKID`` (0x41) — byte-identical to the
historically-pinned mode, so existing fixtures see ZERO change.

Reuses the exact two-surface directive shape #109 established for
``@embedAlways`` (JSDoc block + leading trivia); the *detection* lives in the
parser, this module owns the *flag grammar* (name → value, combo validity).

Port of packages/runar-compiler/src/passes/sighash-directive.ts.
"""

from __future__ import annotations

from dataclasses import dataclass

# Numeric value of each sighash flag name.
_FLAG_VALUES: dict[str, int] = {
    "ALL": 0x01,
    "NONE": 0x02,
    "SINGLE": 0x03,
    "FORKID": 0x40,
    "ANYONECANPAY": 0x80,
}

# The base-type names. Exactly one MUST appear in a directive.
_BASE_TYPE_NAMES = frozenset({"ALL", "NONE", "SINGLE"})

# SIGHASH_ALL | SIGHASH_FORKID — the default when no directive is present.
SIGHASH_DEFAULT = 0x41

# Base-type mask. ``sig_hash_type & BASE_TYPE_MASK`` recovers 1/2/3
# (ALL/NONE/SINGLE) after the FORKID/ANYONECANPAY high bits are stripped.
BASE_TYPE_MASK = 0x1F
BASE_ALL = 0x01
BASE_NONE = 0x02
BASE_SINGLE = 0x03
FLAG_FORKID = 0x40
FLAG_ANYONECANPAY = 0x80


@dataclass
class SighashParseResult:
    """Discriminated result: exactly one of ``value`` / ``error`` is set."""
    value: int | None = None
    error: str | None = None


def parse_sighash_flags(flags_text: str) -> SighashParseResult:
    """Parse the flag list of an ``@sighash`` directive.

    ``flags_text`` is the raw text following ``@sighash`` (e.g. ``"SINGLE|FORKID"``),
    with any trailing comment punctuation already stripped by the caller.

    Validation (security-relevant — a mis-declared mode is an exploit class):
      - every name must be a known flag (reject typos like ``FORKD``)
      - EXACTLY ONE base type (ALL/NONE/SINGLE) — reject zero, and reject
        nonsensical combos such as ``ALL|NONE``. This is checked on NAMES, not on
        the OR-ed numeric value, because ``ALL|NONE`` (0x01|0x02) collides with
        the numeric value of SINGLE (0x03) — a silent, dangerous aliasing a
        purely numeric check would miss.
      - reject a duplicated flag name (signals a copy/paste error).
      - FORKID is mandatory on BSV (the whole OP_PUSH_TX / BIP-143 machinery is
        FORKID-only) — reject a FORKID-less flag set (deploy-to-brick).
    """
    raw = flags_text.strip()
    if raw == "":
        return SighashParseResult(
            error="@sighash directive requires at least one flag "
                  "(e.g. `@sighash ALL|FORKID`)"
        )

    names = [n.strip() for n in raw.split("|")]
    seen: set[str] = set()
    base_types: list[str] = []
    value = 0

    for name in names:
        if name == "":
            return SighashParseResult(
                error=f'@sighash directive has an empty flag in "{raw}"'
            )
        if name not in _FLAG_VALUES:
            return SighashParseResult(
                error=f'@sighash: unknown flag "{name}" '
                      f"(valid: ALL, NONE, SINGLE, FORKID, ANYONECANPAY)"
            )
        if name in seen:
            return SighashParseResult(
                error=f'@sighash: duplicate flag "{name}" in "{raw}"'
            )
        seen.add(name)
        if name in _BASE_TYPE_NAMES:
            base_types.append(name)
        value |= _FLAG_VALUES[name]

    if len(base_types) == 0:
        return SighashParseResult(
            error=f"@sighash: must specify exactly one base type "
                  f'(ALL, NONE, or SINGLE); got "{raw}"'
        )
    if len(base_types) > 1:
        return SighashParseResult(
            error=f"@sighash: cannot combine base types ({'|'.join(base_types)}) "
                  f"— pick exactly one of ALL/NONE/SINGLE"
        )

    # FORKID is mandatory on BSV: the entire OP_PUSH_TX / BIP-143 preimage
    # machinery is FORKID-only, so a FORKID-less flag set deploys a covenant
    # whose derived signature can never verify (deploy-to-brick). Reject it up
    # front rather than let a spendable-looking script ship.
    if (value & _FLAG_VALUES["FORKID"]) == 0:
        return SighashParseResult(
            error=f"@sighash: FORKID is mandatory on BSV; write e.g. "
                  f'@sighash {base_types[0]}|FORKID (got "{raw}")'
        )

    return SighashParseResult(value=value)


# Shared diagnostics (F-039) — identical text in all seven tiers. A marker that
# is present but not followed by a well-formed flag list, or a second marker on
# the same method, is a compile error, never a silent fall-back to the default
# ALL|FORKID mode.
SIGHASH_MALFORMED_ERROR = (
    "@sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a "
    "|-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)"
)
SIGHASH_MULTIPLE_ERROR = "@sighash: more than one @sighash directive on this method; declare exactly one"

_SIGHASH_MARKER = "@sighash"
_WORD_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
_SEGMENT_CHARS = _WORD_CHARS | frozenset("| \t")


def extract_sighash_directive(comment_text: str) -> SighashParseResult | None:
    """Extract and parse an ``@sighash`` directive from a method's leading-comment
    text (all of its leading comments, concatenated).

    Returns ``None`` only when no ``@sighash`` marker is present, otherwise the
    parse result (value or error). Mirrors the TS reference.

    A marker is every occurrence of ``@sighash``, whatever follows it (N-039,
    user decision R85): ``@sighashSINGLE|FORKID`` or ``@sighashType`` is a
    malformed directive, never prose. Once a marker is present (fail-closed,
    F-039): more than one marker is
    ``SIGHASH_MULTIPLE_ERROR``; the segment after the marker, up to ``*/``, a
    newline, CR or the end, must be empty, or start with a space/tab and contain
    only ``[A-Za-z0-9_|]``, spaces and tabs, else ``SIGHASH_MALFORMED_ERROR``;
    the flag list itself is then validated by ``parse_sighash_flags``.
    """
    markers: list[int] = []
    i = comment_text.find(_SIGHASH_MARKER)
    while i != -1:
        markers.append(i)
        i = comment_text.find(_SIGHASH_MARKER, i + 1)
    if not markers:
        return None
    if len(markers) > 1:
        return SighashParseResult(error=SIGHASH_MULTIPLE_ERROR)

    after = comment_text[markers[0] + len(_SIGHASH_MARKER):]
    end = len(after)
    for j, c in enumerate(after):
        if c in "\n\r" or (c == "*" and after[j + 1:j + 2] == "/"):
            end = j
            break
    seg = after[:end]
    if seg and not (seg[0] in " \t" and all(c in _SEGMENT_CHARS for c in seg)):
        return SighashParseResult(error=SIGHASH_MALFORMED_ERROR)
    return parse_sighash_flags(seg)


def lost_directive_message(directive: str) -> str:
    """N-199 (R75): shared diagnostic, identical in all seven tiers, for a
    ``@sighash`` / ``@embedAlways`` marker inside the contract class body that
    is not in the leading comments of the member kind that reads it
    (``@sighash`` -> a method, ``@embedAlways`` -> a property). Mirrors the TS
    reference's ``lostDirectiveMessage`` (sighash-directive.ts)."""
    target = "method" if directive == "@sighash" else "property"
    return (
        f"{directive} directive is not attached to any {target} and would be silently ignored; "
        f"put the comment on its own line directly above the {target} it annotates "
        f"(a comment that shares a line with the preceding code belongs to that code)"
    )


def describe_sighash(value: int) -> str:
    """Human-readable rendering of a sighash value (for diagnostics)."""
    parts: list[str] = []
    base = value & BASE_TYPE_MASK
    if base == BASE_ALL:
        parts.append("ALL")
    elif base == BASE_NONE:
        parts.append("NONE")
    elif base == BASE_SINGLE:
        parts.append("SINGLE")
    else:
        parts.append(f"0x{base:x}")
    if value & FLAG_ANYONECANPAY:
        parts.append("ANYONECANPAY")
    if value & FLAG_FORKID:
        parts.append("FORKID")
    return "|".join(parts)


def resolve_native_sighash(
    method_name: str,
    is_public: bool,
    specs: list[str | None],
) -> SighashParseResult | None:
    """N-093 (R38): resolve a sighash declared with a surface's NATIVE spelling
    (Solidity ``sighash(...)``, Move/Rust ``#[sighash(...)]``, Go
    ``//runar:sighash ...``, Python ``@public(sighash="...")``, Zig
    ``runar.Sighash("...")``, Ruby ``runar_sighash '...'``, Java
    ``@Sighash("...")``).

    ``specs`` holds one entry per spelling found on the method: the flag text,
    or ``None`` when the spelling's argument was not well formed. Returns
    ``None`` when there is no spelling, else the numeric type or the diagnostic
    -- the SAME diagnostics the ``.runar.ts`` comment directive produces,
    checked in the same order: non-public method, then more than one spelling,
    then malformed, then the flag grammar of ``parse_sighash_flags``. Mirrors
    the TS reference's ``resolveNativeSighash``.
    """
    if not specs:
        return None
    if not is_public:
        return SighashParseResult(
            error=f"@sighash directive on non-public method '{method_name}' has no effect "
                  "— only public methods are spending entry points"
        )
    if len(specs) > 1:
        return SighashParseResult(error=f"Method '{method_name}': {SIGHASH_MULTIPLE_ERROR}")
    spec = specs[0]
    if spec is None:
        return SighashParseResult(error=f"Method '{method_name}': {SIGHASH_MALFORMED_ERROR}")
    result = parse_sighash_flags(spec)
    if result.error is not None:
        return SighashParseResult(error=f"Method '{method_name}': {result.error}")
    return result


def unknown_go_directive_message(name: str) -> str:
    """N-093: the Go DSL directive comment ``//runar:<name> ...``. Only
    ``sighash`` exists; any other name is refused rather than ignored."""
    return f"unknown Go DSL directive '//runar:{name}'; the only directive is //runar:sighash <FLAGS>"


def unknown_move_attribute_message(attr: str) -> str:
    """N-093: an attribute on the Move surface other than the two directives."""
    return (
        f"unsupported Move attribute #[{attr}]; the supported attributes are "
        "#[embed_always] and #[sighash(<FLAGS>)]"
    )
