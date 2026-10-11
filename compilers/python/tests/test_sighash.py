"""Issue #123 — per-method ``@sighash`` directive (Python port of the TypeScript
reference: sighash-directive.test.ts, sighash-parse.test.ts,
sighash-codegen.test.ts, sighash-validate.test.ts + the e88f202c security
fixes).
"""

from __future__ import annotations

import json

from runar_compiler.compiler import compile_from_source_str_with_result as _compile
from runar_compiler.frontend.diagnostic import Severity
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.sighash_directive import (
    parse_sighash_flags,
    extract_sighash_directive,
    describe_sighash,
    SIGHASH_DEFAULT,
)


def _errors(r):
    return [d.message for d in r.diagnostics if d.severity == Severity.ERROR]


def _warnings(r):
    return [d.message for d in r.diagnostics if d.severity == Severity.WARNING]


def _compile_ok(src, file_name="X.runar.ts"):
    r = _compile(src, file_name, disable_constant_folding=True)
    assert not _errors(r), _errors(r)
    return r


def _method_by_name(src, name, file_name="X.runar.ts"):
    r = parse_source(src, file_name)
    assert not r.errors, r.error_strings()
    return next(m for m in r.contract.methods if m.name == name)


# ---------------------------------------------------------------------------
# Flag grammar (sighash-directive.test.ts)
# ---------------------------------------------------------------------------

class TestSighashGrammar:
    def test_common_combos(self):
        assert parse_sighash_flags("ALL|FORKID").value == 0x41
        assert parse_sighash_flags("SINGLE|FORKID").value == 0x43
        assert parse_sighash_flags("NONE|FORKID").value == 0x42
        assert parse_sighash_flags("ALL|ANYONECANPAY|FORKID").value == 0xC1

    def test_order_independent_whitespace(self):
        assert parse_sighash_flags(" FORKID | SINGLE ").value == 0x43

    def test_default_constant(self):
        assert SIGHASH_DEFAULT == 0x41
        assert parse_sighash_flags("ALL|FORKID").value == SIGHASH_DEFAULT

    def test_rejects_unknown_flag(self):
        assert "unknown flag \"FORKD\"" in parse_sighash_flags("ALL|FORKD").error

    def test_rejects_all_none_on_names(self):
        assert "cannot combine base types" in parse_sighash_flags("ALL|NONE|FORKID").error

    def test_rejects_two_base_types(self):
        assert parse_sighash_flags("SINGLE|ALL").error is not None

    def test_rejects_no_base_type(self):
        assert "exactly one base type" in parse_sighash_flags("FORKID|ANYONECANPAY").error

    def test_rejects_duplicate(self):
        assert "duplicate flag" in parse_sighash_flags("SINGLE|SINGLE|FORKID").error

    def test_rejects_empty(self):
        assert parse_sighash_flags("").error is not None
        assert parse_sighash_flags("   ").error is not None

    def test_rejects_no_forkid(self):
        # F2: FORKID is mandatory on BSV (deploy-to-brick otherwise).
        for flags in ("SINGLE", "ALL", "NONE", "ALL|ANYONECANPAY"):
            assert "FORKID is mandatory on BSV" in parse_sighash_flags(flags).error

    def test_accepts_once_forkid_added(self):
        assert parse_sighash_flags("SINGLE|FORKID").value == 0x43
        assert parse_sighash_flags("ALL|ANYONECANPAY|FORKID").value == 0xC1

    def test_extract_from_comment(self):
        assert extract_sighash_directive("/** @sighash SINGLE|FORKID */").value == 0x43
        assert extract_sighash_directive("// @sighash NONE|FORKID").value == 0x42
        assert extract_sighash_directive("/** no directive here */") is None

    def test_describe_roundtrips(self):
        assert describe_sighash(0x41) == "ALL|FORKID"
        assert describe_sighash(0x43) == "SINGLE|FORKID"
        assert describe_sighash(0xC1) == "ALL|ANYONECANPAY|FORKID"
        assert describe_sighash(0x42) == "NONE|FORKID"


# ---------------------------------------------------------------------------
# Parsing (sighash-parse.test.ts)
# ---------------------------------------------------------------------------

class TestSighashParse:
    def test_sets_from_jsdoc(self):
        src = """
class C extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  /** @sighash SINGLE|FORKID */
  public bump(): void { this.n = this.n + 1n; }
}"""
        assert _method_by_name(src, "bump").sighash_type == 0x43

    def test_default_undefined(self):
        src = """
class C extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.n = this.n + 1n; }
}"""
        assert _method_by_name(src, "bump").sighash_type is None

    def test_line_comment(self):
        src = """
class C extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  // @sighash NONE|FORKID
  public wipe(): void { this.n = 0n; }
}"""
        assert _method_by_name(src, "wipe").sighash_type == 0x42

    def test_bad_combo_errors(self):
        src = """
class C extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  /** @sighash ALL|NONE|FORKID */
  public bump(): void { this.n = this.n + 1n; }
}"""
        r = parse_source(src, "X.runar.ts")
        assert any("cannot combine base types" in e for e in r.error_strings())

    def test_private_method_errors(self):
        src = """
class C extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  /** @sighash SINGLE|FORKID */
  private helper(): bigint { return 1n; }
  public bump(): void { this.n = this.n + 1n; }
}"""
        r = parse_source(src, "X.runar.ts")
        assert any("non-public method" in e for e in r.error_strings())

    # F-282: the tokenizer accumulated ANY comment seen since the last real
    # token into `pending_comments`, with no newline check, and attached the
    # whole pile to whichever token came next. ts-morph's leading-trivia scan
    # only starts collecting a comment once a line break has been crossed
    # since the preceding token (verified directly against ts-morph: both
    # cases below come back with EMPTY leading comments / jsdocs for the
    # second method), so a comment sharing a line with a PRECEDING token is
    # that token's trailing trivia, never the next node's leading trivia.
    def test_directive_sharing_line_with_preceding_member_is_not_honoured(self):
        src = """
class C extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; } /** @sighash SINGLE|FORKID */ public bump(): void { this.n = this.n + 1n; }
}"""
        assert _method_by_name(src, "bump").sighash_type is None

    def test_trailing_comment_does_not_leak_to_next_method(self):
        src = """
class C extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public bump(): void {} // @sighash SINGLE|FORKID
  public other(): void {}
}"""
        r = parse_source(src, "X.runar.ts")
        assert not r.errors, r.error_strings()
        bump = next(m for m in r.contract.methods if m.name == "bump")
        other = next(m for m in r.contract.methods if m.name == "other")
        assert bump.sighash_type is None
        assert other.sighash_type is None


# ---------------------------------------------------------------------------
# Codegen (sighash-codegen.test.ts + e88f202c)
# ---------------------------------------------------------------------------

def _counter(directive):
    return f"""
class Counter extends StatefulSmartContract {{
  n: bigint;
  constructor(n: bigint) {{ super(n); this.n = n; }}
  {directive}
  public bump(): void {{ this.n = this.n + 1n; }}
}}"""


# SINGLE-safe body: a legitimate pairwise covenant emits an explicit single
# addOutput (a mutate-only continuation is rejected under SINGLE — F1).
def _counter_out(directive):
    return f"""
class Counter extends StatefulSmartContract {{
  n: bigint;
  constructor(n: bigint) {{ super(n); this.n = n; }}
  {directive}
  public bump(): void {{ this.addOutput(1000n, this.n); }}
}}"""


class TestSighashCodegen:
    def test_default_equals_explicit_all_forkid(self):
        no = _compile_ok(_counter(""), "Counter.runar.ts")
        allf = _compile_ok(_counter("/** @sighash ALL|FORKID */"), "Counter.runar.ts")
        # ALL|FORKID equals the historically-pinned default → identical script.
        assert allf.script_hex == no.script_hex
        assert (
            _serialize_anf(allf.artifact) == _serialize_anf(no.artifact)
        )

    def test_single_changes_script(self):
        dflt = _compile_ok(_counter_out(""), "Counter.runar.ts")
        single = _compile_ok(_counter_out("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts")
        assert single.script_hex != dflt.script_hex
        # SINGLE|FORKID flag byte 0x43 pushed as OP_DATA_1 0x43 = "0143".
        assert "0143" in single.script_hex
        # default is still pinned to the 0x41 push.
        assert "0141" in dflt.script_hex

    def test_abi_sig_hash_type(self):
        single = _compile_ok(_counter_out("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts")
        dflt = _compile_ok(_counter_out(""), "Counter.runar.ts")
        assert next(m for m in single.artifact.abi.methods if m.name == "bump").sig_hash_type == 0x43
        assert next(m for m in dflt.artifact.abi.methods if m.name == "bump").sig_hash_type is None

    def test_preimage_assert_uses_declared_mode(self):
        # The auto-injected preimage-type assert const is 0x43 = 67.
        single = _compile_ok(_counter_out("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts")
        found = _find_const_int(single.anf, 67)
        assert found, "expected a load_const 67 (0x43) in the ANF"

    def test_single_binding_byte_swapped_from_default(self):
        # Wire parity: the SINGLE binding blob is the default blob with ONLY the
        # appended sighash flag byte swapped 0x41 -> 0x43.
        from runar_compiler.codegen.stack import (
            _CHECK_PREIMAGE_BINDING_HEX,
            _binding_hex_with_sighash_flag,
        )
        swapped = _binding_hex_with_sighash_flag(0x43)
        assert swapped != _CHECK_PREIMAGE_BINDING_HEX
        assert "0143" in swapped
        assert "0141" not in swapped
        # Exactly one byte differs (the append byte 0x41 -> 0x43): a single
        # hex nibble in the string.
        diff = sum(1 for a, b in zip(swapped, _CHECK_PREIMAGE_BINDING_HEX) if a != b)
        assert diff == 1


def _serialize_anf(artifact):
    from runar_compiler.compiler import _serialize_anf_program
    return json.dumps(_serialize_anf_program(artifact.anf), sort_keys=True) if artifact.anf else None


def _find_const_int(program, target):
    if program is None:
        return False
    from runar_compiler.ir.types import decode_constants
    decode_constants(program)

    def walk(bindings):
        for b in bindings:
            v = b.value
            if v.kind == "load_const" and v.const_int == target:
                return True
            if v.kind == "load_const" and v.const_big_int == target:
                return True
            for nested in (v.then, v.else_, v.body):
                if nested and walk(nested):
                    return True
        return False

    return any(walk(m.body) for m in program.methods)


# ---------------------------------------------------------------------------
# Field-usage validation — the 5 security rules (sighash-validate.test.ts)
# ---------------------------------------------------------------------------

def _compiles(src, file_name="X.runar.ts"):
    r = _compile(src, file_name)
    return bool(r.artifact) and not _errors(r)


def _errors_of(src, file_name="X.runar.ts"):
    return _errors(_compile(src, file_name))


def _warnings_of(src, file_name="X.runar.ts"):
    return _warnings(_compile(src, file_name))


class TestSighashValidateAnyoneCanPay:
    GUARD = staticmethod(lambda d: f"""
class Guard extends SmartContract {{
  readonly expected: ByteString;
  constructor(expected: ByteString) {{ super(expected); this.expected = expected; }}
  {d}
  public spend(pre: SigHashPreimage): void {{
    assert(checkPreimage(pre));
    assert(extractHashPrevouts(pre) === this.expected);
  }}
}}""")

    def test_rejects_hashprevouts_under_acp(self):
        errs = _errors_of(self.GUARD("/** @sighash ALL|ANYONECANPAY|FORKID */"))
        assert any("hashPrevouts" in e and "zeroed under ANYONECANPAY" in e for e in errs)

    def test_rejects_prevout_script_under_acp(self):
        src = """
class Co extends StatefulSmartContract {
  readonly h0: ByteString;
  n: bigint;
  constructor(h0: ByteString, n: bigint) { super(h0, n); this.h0 = h0; this.n = n; }
  /** @sighash ALL|ANYONECANPAY|FORKID */
  public coSpend(): void {
    const s = extractPrevOutputScript(1n, this.h0);
    assert(len(s) > 0n);
  }
}"""
        errs = _errors_of(src)
        assert any("companion input" in e or "prevout script" in e for e in errs)

    def test_accepts_hashprevouts_under_default(self):
        assert _compiles(self.GUARD(""))
        assert _compiles(self.GUARD("/** @sighash ALL|FORKID */"))


class TestSighashValidateHashSequence:
    def test_rejects_hashsequence_under_single(self):
        src = """
class Seq extends SmartContract {
  readonly expected: ByteString;
  constructor(expected: ByteString) { super(expected); this.expected = expected; }
  /** @sighash SINGLE|FORKID */
  public spend(pre: SigHashPreimage): void {
    assert(checkPreimage(pre));
    assert(extractHashSequence(pre) === this.expected);
  }
}"""
        errs = _errors_of(src)
        assert any("hashSequence" in e and "SIGHASH_ALL" in e for e in errs)

    def test_accepts_hashsequence_under_default(self):
        src = """
class Seq extends SmartContract {
  readonly expected: ByteString;
  constructor(expected: ByteString) { super(expected); this.expected = expected; }
  public spend(pre: SigHashPreimage): void {
    assert(checkPreimage(pre));
    assert(extractHashSequence(pre) === this.expected);
  }
}"""
        assert _compiles(src)


class TestSighashValidateNone:
    def test_rejects_continuation_under_none(self):
        src = """
class Counter extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  /** @sighash NONE|FORKID */
  public bump(): void { this.n = this.n + 1n; }
}"""
        errs = _errors_of(src)
        assert any("NONE commits to NO outputs" in e or "continuation" in e for e in errs)

    def test_accepts_mutation_under_default(self):
        src = """
class Counter extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.n = this.n + 1n; }
}"""
        assert _compiles(src)


class TestSighashValidateSingle:
    def test_rejects_multi_output_under_single(self):
        src = """
class Multi extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  /** @sighash SINGLE|FORKID */
  public split(): void {
    this.addOutput(1000n, this.count);
    this.addOutput(2000n, this.count);
  }
}"""
        errs = _errors_of(src)
        assert any("SINGLE commits ONLY to the output at this input" in e for e in errs)

    def test_rejects_mutate_only_under_single(self):
        # F1: the mutate-only auto-continuation is value-skimmable under SINGLE.
        src = """
class Counter extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  /** @sighash SINGLE|FORKID */
  public bump(): void { this.n = this.n + 1n; }
}"""
        errs = _errors_of(src)
        assert any(
            "mutate-only SINGLE continuation is unsound" in e
            or "sized by the caller-chosen _newAmount" in e
            for e in errs
        )
        assert not _compiles(src)

    def test_accepts_single_output_with_warning(self):
        # F1: the legitimate pairwise covenant is ALLOWED, with a value-pinning WARNING.
        src = """
class Pay extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  /** @sighash SINGLE|FORKID */
  public settle(): void { this.addOutput(1000n, this.n); }
}"""
        assert _compiles(src)
        assert any(
            "SINGLE commits ONLY to the output at this input" in w
            or "carries the FULL protected value" in w
            for w in _warnings_of(src)
        )

    def test_rejects_require_output_p2pkh_under_single(self):
        # F4: fixed-index output not provably same-index.
        src = """
class Cov extends StatefulSmartContract {
  readonly bondPKH: ByteString;
  readonly bond: bigint;
  constructor(bondPKH: ByteString, bond: bigint) { super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond; }
  /** @sighash SINGLE|FORKID */
  public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); }
}"""
        errs = _errors_of(src)
        assert any("'requireOutputP2PKH' asserts an output at a fixed index" in e and "SINGLE" in e for e in errs)

    def test_accepts_require_output_p2pkh_under_default(self):
        src = """
class Cov extends StatefulSmartContract {
  readonly bondPKH: ByteString;
  readonly bond: bigint;
  constructor(bondPKH: ByteString, bond: bigint) { super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond; }
  public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); }
}"""
        assert _compiles(src)

    def test_accepts_multi_output_under_default(self):
        src = """
class Multi extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public split(): void {
    this.addOutput(1000n, this.count);
    this.addOutput(2000n, this.count);
  }
}"""
        assert _compiles(src)


class TestSighashValidateTransitiveWalk:
    def test_hashoutputs_in_for_condition_under_none(self):
        # F3: the walk must cover the for-loop CONDITION.
        src = """
class C extends SmartContract {
  readonly expected: ByteString;
  constructor(expected: ByteString) { super(expected); this.expected = expected; }
  /** @sighash NONE|FORKID */
  public spend(pre: SigHashPreimage): void {
    for (let i = 0n; i < 3n && extractOutputHash(pre) === this.expected; i++) { assert(i < 2n); }
    assert(checkPreimage(pre));
  }
}"""
        errs = _errors_of(src)
        assert any("hashOutputs" in e and "zeroed under NONE" in e for e in errs)
