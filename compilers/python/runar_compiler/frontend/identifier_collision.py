"""F-017 — the identifier-collision rule.

Five surfaces rename identifiers on the way into the AST: ``.runar.py``,
``.runar.rb``, ``.runar.rs``, ``.runar.move`` (snake_case -> camelCase) and
``.runar.go`` (PascalCase -> camelCase). None of those mappings is injective:
``tmp`` and ``tmp_``, ``a_b`` and ``aB``, ``_tmp`` and ``tmp`` (.py/.rb),
``Tmp`` and ``tmp`` (.go) each land on one Rúnar name. Before this rule both
spellings were bound to ONE variable, so ``tmp = n + 1; tmp_ = n + 2;
assert_(tmp == tmp_)`` -- always false in the source language -- compiled to
a self-comparison that always passes.

While parsing one contract, the surface parser records (source spelling,
Rúnar name) for every identifier it DECLARES: properties / struct fields,
method names (not the constructor), parameters (not receivers), locals at
every declaration or bare-name assignment target, and loop variables. If two
recorded pairs share a Rúnar name but differ in spelling, the contract is
refused with exactly one error whose text is identical in all seven tiers.
Mirrors ``identifierCollisionMessage`` in
packages/runar-compiler/src/passes/snake-to-camel.ts.
"""
from __future__ import annotations

from runar_compiler.frontend.diagnostic import Diagnostic, Severity


def identifier_collision_message(decls: list[tuple[str, str]]) -> str | None:
    """The collision with the smallest Rúnar name and, for it, the two
    smallest source spellings (ordinal order), so the report does not depend
    on declaration order. ``None`` when every name has one spelling."""
    spellings: dict[str, set[str]] = {}
    for raw, name in decls:
        spellings.setdefault(name, set()).add(raw)
    colliding = sorted(name for name, raws in spellings.items() if len(raws) >= 2)
    if not colliding:
        return None
    name = colliding[0]
    a, b = sorted(spellings[name])[:2]
    return (
        f"identifier collision: '{a}' and '{b}' both convert to '{name}'; "
        f"rename one of them"
    )


def collision_diagnostics(decls: list[tuple[str, str]]) -> list[Diagnostic]:
    """The single F-017 error as a diagnostic list (empty when none)."""
    msg = identifier_collision_message(decls)
    return [] if msg is None else [Diagnostic(message=msg, severity=Severity.ERROR)]
