"""N-065 / N-060 -- compiler-reserved names.

Several passes mint names into the SAME namespace user identifiers live in,
and every later pass resolves a name by string equality, so a user name
spelled like a minted one aliases two different values (e.g. a local ``t2``
read as the ANF temp ``t2``). Every minted family is reserved and a program
that declares one is refused with ONE sentence shared verbatim by all seven
tiers. Mirrors ``packages/runar-compiler/src/passes/reserved-names.ts`` (see
it for the per-pass inventory and what is deliberately NOT reserved).
"""

from __future__ import annotations

import re


def reserved_name_message(name: str) -> str:
    """The diagnostic, shared verbatim by all seven tiers (source and --ir)."""
    return f"'{name}' is reserved for compiler-generated names and cannot be used as an identifier"


# 05-stack-lower: _codePart, __param_<name>, __shadowed_<n>_<name>, _pub_<n>.
_STACK_LOWERING_RESERVED = [
    re.compile(r"^_codePart\Z"),
    re.compile(r"^__param_"),
    re.compile(r"^__shadowed_"),
    re.compile(r"^_pub_[0-9]+\Z"),
]

# 04-anf-lower: ANF temps and merged-local temps.
_ANF_BINDING_RESERVED = [
    re.compile(r"^t[0-9]+\Z"),
    re.compile(r"^__merge\$[0-9]+\Z"),
]

# 03b FixedArray slot / hoisted temps, and the auto-injected parameters.
_SOURCE_ONLY_RESERVED = [
    re.compile(r"^.+__[0-9]+\Z"),
    re.compile(r"^__idx_[0-9]+\Z"),
    re.compile(r"^__val_[0-9]+\Z"),
    re.compile(r"^_changePKH\Z"),
    re.compile(r"^_changeAmount\Z"),
    re.compile(r"^_newAmount\Z"),
    re.compile(r"^_serialisedOutputs\Z"),
    re.compile(r"^_prevOutScript_[0-9]+\Z"),
]


def _matches_any(name: str, patterns: list[re.Pattern[str]]) -> bool:
    # `\Z`, not `$`: Python's `$` also matches before a trailing newline,
    # JavaScript's (the TS reference) does not.
    return any(p.search(name) is not None for p in patterns)


def is_reserved_source_name(name: str, stateful: bool) -> bool:
    """True if a SOURCE program may not declare ``name`` (after name mapping)."""
    return (
        _matches_any(name, _STACK_LOWERING_RESERVED)
        or _matches_any(name, _ANF_BINDING_RESERVED)
        or _matches_any(name, _SOURCE_ONLY_RESERVED)
        or (stateful and name == "txPreimage")
    )


def is_reserved_ir_name(name: str, declaration: bool) -> bool:
    """``--ir`` rule. ``declaration`` is True for a property, method, parameter
    or loop-variable name and for the name a load_param / load_prop /
    update_prop addresses; False for a binding name or a binding reference."""
    return _matches_any(name, _STACK_LOWERING_RESERVED) or (
        declaration and _matches_any(name, _ANF_BINDING_RESERVED)
    )
