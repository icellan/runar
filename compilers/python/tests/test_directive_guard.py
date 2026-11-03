"""Fail-closed directive guard (issues #123 @sighash / #109 @embedAlways).

The ``@sighash`` and ``@embedAlways`` comment directives are honoured only on
the TypeScript (.runar.ts) surface, which reads leading trivia. The non-TS
surface parsers ignore comments, so ``parse_source`` must FAIL CLOSED on those
formats rather than silently drop a security-critical directive. These tests
pin both halves of that policy.
"""

from __future__ import annotations

from runar_compiler.frontend.parser_dispatch import parse_source


def _errors(src: str, file_name: str) -> str:
    return "\n".join(parse_source(src, file_name).error_strings())


def test_ts_surface_honours_sighash_directive() -> None:
    src = (
        "class C extends StatefulSmartContract {\n"
        "  n: bigint;\n"
        "  constructor(n: bigint) { super(n); this.n = n; }\n"
        "  /** @sighash SINGLE|FORKID */\n"
        "  public bump(): void { this.n = this.n + 1n; }\n"
        "}\n"
    )
    r = parse_source(src, "C.runar.ts")
    assert not r.errors, r.error_strings()
    m = next(m for m in r.contract.methods if m.name == "bump")
    assert m.sighash_type == 0x43


def test_non_ts_surface_rejects_sighash_directive() -> None:
    src = (
        "contract Counter {\n"
        "  // @sighash SINGLE|FORKID\n"
        "  function unlock() public {}\n"
        "}\n"
    )
    joined = _errors(src, "Counter.runar.sol")
    assert "@sighash" in joined
    assert "#123" in joined


def test_non_ts_surface_rejects_embed_always_directive() -> None:
    src = (
        "module Counter {\n"
        "  // @embedAlways\n"
        "  x: u64;\n"
        "}\n"
    )
    joined = _errors(src, "Counter.runar.move")
    assert "@embedAlways" in joined
    assert "#109" in joined


def test_word_boundary_identifier_does_not_trip_guard() -> None:
    # A field named `sighashType` (no `@`) must NOT trip the `@sighash` guard.
    src = (
        "class C extends SmartContract {\n"
        "  readonly sighashType: bigint;\n"
        "  constructor(sighashType: bigint) { super(sighashType); this.sighashType = sighashType; }\n"
        "  public unlock(): void {}\n"
        "}\n"
    )
    joined = _errors(src, "C.runar.ts")
    assert "not supported" not in joined
