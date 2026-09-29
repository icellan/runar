"""F-039 — a present-but-malformed ``@sighash`` marker is a compile error.

Before F-039, ``/** @sighash SINGLE|FORKID! */`` (a one-character typo) did not
match the extractor regex, so the method was read as having NO directive and
compiled, silently, under the default ALL|FORKID. A second directive on one
method was silently ignored.

Proves: the Python TS-surface parser refuses each malformed / duplicated shape
with the diagnostic shared by all seven tiers, keeps the reference
word-boundary rule (``@sighashSINGLE`` / ``@sighashType`` are prose, not
markers), and still honours a well-formed multi-line JSDoc directive.
Does not prove: cross-tier agreement (conformance/negatives rejection-parity).
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source

MALFORMED = (
    "Method 'bump': @sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS "
    "is a |-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)"
)
MULTIPLE = "Method 'bump': @sighash: more than one @sighash directive on this method; declare exactly one"


def _src(directive: str) -> str:
    return f"""
      class C extends StatefulSmartContract {{
        n: bigint;
        constructor(n: bigint) {{ super(n); this.n = n; }}
        {directive}
        public bump(): void {{ this.addOutput(1000n, this.n); }}
      }}"""


def _errors(directive: str) -> list[str]:
    return [e.message for e in parse_source(_src(directive), "X.runar.ts").errors]


@pytest.mark.parametrize("directive", [
    "/** @sighash SINGLE|FORKID! */",
    "/** @sighash:SINGLE|FORKID */",
    "// @sighash=SINGLE|FORKID",
    "/** @sighash SINGLE,FORKID */",
])
def test_malformed_directive_rejected(directive):
    assert _errors(directive) == [MALFORMED]


def test_bare_marker_line_comment_rejected():
    assert _errors("// @sighash") == [
        "Method 'bump': @sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)"
    ]


@pytest.mark.parametrize("directive", [
    "/** @sighash SINGLE|FORKID\n   * @sighash ALL|FORKID */",
    "/** @sighash SINGLE|FORKID */\n        /** @sighash ALL|FORKID */",
    "/** @sighash SINGLE|FORKID!\n   * @sighash NONE|FORKID */",
])
def test_multiple_directives_rejected(directive):
    assert _errors(directive) == [MULTIPLE]


@pytest.mark.parametrize("directive", ["/** @sighashSINGLE|FORKID */", "/** see the @sighashType docs */"])
def test_word_boundary_prose_is_not_a_marker(directive):
    r = parse_source(_src(directive), "X.runar.ts")
    assert not r.errors
    assert next(m for m in r.contract.methods if m.name == "bump").sighash_type is None


def test_well_formed_multiline_jsdoc_honoured():
    r = parse_source(_src("/**\n   * Bump.\n   * @sighash SINGLE|FORKID\n   */"), "X.runar.ts")
    assert not r.errors
    assert next(m for m in r.contract.methods if m.name == "bump").sighash_type == 0x43
