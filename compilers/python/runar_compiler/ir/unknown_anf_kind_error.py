"""Typed error raised by ANF / Stack-IR / constant-fold dispatch sites
when they encounter an ANFValue kind they don't recognize.

Historically these dispatchers used silent fall-throughs (empty refs list,
unchanged ANFValue, ``False`` for side-effect checks). Adding a new ANFValue
variant and forgetting to wire it into every dispatch site (see
``CLAUDE.md`` -> "Adding a New ANF Value Kind") would then silently corrupt
output instead of failing loudly.

Every former silent default now raises this error so the regression is
caught at the first dispatch site instead of leaking into Stack IR / hex.

Direct port of ``packages/runar-ir-schema/src/unknown-anf-kind-error.ts``.
"""

from __future__ import annotations


class UnknownANFKindError(Exception):
    """Raised by ANF dispatch when it encounters a kind it doesn't handle.

    Typically because a new ANFValue variant was added without updating
    all dispatch sites -- see CLAUDE.md "Adding a New ANF Value Kind".
    """

    def __init__(self, kind: str, location: str) -> None:
        self.kind = kind
        self.location = location
        super().__init__(
            f"unknown ANF kind {kind!r} encountered in {location} -- "
            f"if you added a new ANFValue variant, update all dispatch sites "
            f"(see CLAUDE.md 'Adding a New ANF Value Kind' for the 14-step recipe)"
        )
