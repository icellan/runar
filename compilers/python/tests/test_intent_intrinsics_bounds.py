"""Tests for R-2 / R-4 typecheck bounds on intent sub-covenant intrinsics
in the Python tier.

Mirrors the Go reference checks in
``compilers/go/frontend/typecheck.go``:

  * R-2 — ``requireOutputP2PKH(outputIndex, pkh, satoshis)``: the
    ``outputIndex`` literal must satisfy ``0 <= idx <= 1000``. The
    emitted Stack-IR computes ``byte-offset = idx * 34``; values outside
    this window are almost certainly a programming error.

  * R-4 — ``extractPrevOutputScript(index, hash, prefixLen)``: the
    optional ``prefixLen`` literal must satisfy
    ``32 <= prefixLen <= 4 MiB``. The intrinsic hashes
    ``substr(witness, 0, prefixLen)`` and compares against a 32-byte
    SHA-256; prefixLen below 32 cannot cover a hash-sized chunk, and
    prefixLen above ``MAX_SCRIPT_BYTES`` cannot fit in a legal Bitcoin
    Script anyway.
"""

from __future__ import annotations

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check


def _expect_typecheck_error(source: str, substr: str) -> None:
    """Assert that the source produces a typecheck error containing ``substr``."""
    result = parse_source(source, "Test.runar.go")
    assert result.errors == [], result.error_strings()
    assert result.contract is not None
    tc_result = type_check(result.contract)
    msgs = [d.format_message() for d in tc_result.errors]
    assert any(substr in m for m in msgs), (
        f"expected typecheck error containing {substr!r}, got: {msgs}"
    )


# ---------------------------------------------------------------------------
# R-2: requireOutputP2PKH outputIndex bounds [0, 1000]
# ---------------------------------------------------------------------------

class TestRequireOutputP2PKHIndexBounds:
    def test_negative_index_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayBond() {
    runar.RequireOutputP2PKH(-1, c.BondPKH, c.Bond)
}
"""
        _expect_typecheck_error(source, "must be >= 0")

    def test_index_above_1000_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayBond() {
    runar.RequireOutputP2PKH(1001, c.BondPKH, c.Bond)
}
"""
        _expect_typecheck_error(source, "bound to <= 1000")


# ---------------------------------------------------------------------------
# R-4: extractPrevOutputScript prefixLen bounds [32, 4194304]
# ---------------------------------------------------------------------------

class TestExtractPrevOutputScriptPrefixLenBounds:
    def test_prefix_len_below_32_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H runar.ByteString `runar:"readonly"`
}

func (c *Cov) Bind() {
    s := runar.ExtractPrevOutputScript(0, c.H, 31)
    _ = s
}
"""
        _expect_typecheck_error(source, "must be >= 32")

    def test_prefix_len_above_max_script_bytes_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H runar.ByteString `runar:"readonly"`
}

func (c *Cov) Bind() {
    s := runar.ExtractPrevOutputScript(0, c.H, 4194305)
    _ = s
}
"""
        _expect_typecheck_error(source, "must be <= MAX_SCRIPT_BYTES")
