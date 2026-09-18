"""R-025 / R-026 — ``expand_fixed_arrays`` must not drop AST node fields.

The pass rebuilt ``MethodNode``, ``CallExpr`` and the synthetic ``PropertyNode``
field-by-field, so any field the reconstruction forgot silently reverted to its
dataclass default. Two fields were being lost, and every one of them moves
emitted bytes for a contract that *also* declares a ``FixedArray`` property:

* ``MethodNode.sighash_type`` — a contract declaring ``@sighash SINGLE|FORKID``
  compiled as if it had declared the default ``ALL|FORKID`` (0x41). Validation
  has already ACCEPTED the non-default mode by the time this pass runs, so the
  author gets a different signature-hash commitment than they wrote, with no
  diagnostic.
* ``CallExpr.asm_return_type`` — an expression-form ``asm<ByteString>()`` lost
  its byte tag, so ``a + a`` lowered to OP_ADD instead of OP_CAT.
Each test pairs the FixedArray case with the SAME contract minus the FixedArray
property, so the control isolates the expansion path as the cause.
"""

from __future__ import annotations

from runar_compiler.compiler import compile_from_source_str_with_result as _compile
from runar_compiler.frontend.diagnostic import Severity
from runar_compiler.frontend.expand_fixed_arrays import expand_fixed_arrays
from runar_compiler.frontend.parser_dispatch import parse_source


def _errors(r):
    return [d.message for d in r.diagnostics if d.severity == Severity.ERROR]


def _ok(src, file_name="Boardy.runar.ts"):
    r = _compile(src, file_name, disable_constant_folding=True)
    assert not _errors(r), _errors(r)
    return r


def _parse(src, file_name="Boardy.runar.ts"):
    r = parse_source(src, file_name)
    assert not r.errors, r.error_strings()
    return r.contract


# ---------------------------------------------------------------------------
# MethodNode.sighash_type
# ---------------------------------------------------------------------------

_ARRAY_PROP = "  board: FixedArray<bigint, 3> = [0n, 0n, 0n];\n"


def _sighash_src(directive: str, array_prop: str) -> str:
    # A mutate-only continuation is rejected under SINGLE (rule F1), so the
    # body emits an explicit addOutput -- the shape a real pairwise covenant
    # uses. The array slots ride along in the continuation state.
    values = "this.board[0], this.board[1], this.board[2], " if array_prop else ""
    return f"""
class Boardy extends StatefulSmartContract {{
{array_prop}  n: bigint;
  constructor(n: bigint) {{ super(n); this.n = n; }}
  {directive}
  public bump(): void {{ this.addOutput(1000n, {values}this.n); }}
}}"""


SINGLE_FORKID = 0x43


class TestSighashTypeSurvivesExpansion:
    def test_ast_field_survives_rewrite_method(self):
        contract = _parse(_sighash_src("/** @sighash SINGLE|FORKID */", _ARRAY_PROP))
        assert next(m for m in contract.methods if m.name == "bump").sighash_type == SINGLE_FORKID
        result = expand_fixed_arrays(contract)
        assert not result.errors, result.errors
        assert (
            next(m for m in result.contract.methods if m.name == "bump").sighash_type
            == SINGLE_FORKID
        ), "expand_fixed_arrays dropped MethodNode.sighash_type"

    def test_emitted_flag_is_the_declared_mode(self):
        r = _ok(_sighash_src("/** @sighash SINGLE|FORKID */", _ARRAY_PROP))
        # OP_DATA_1 0x43 -- the sighash flag pinned into the OP_PUSH_TX binding.
        assert "0143" in r.script_hex, "emitted script pins the DEFAULT 0x41, not the declared 0x43"
        assert "0141" not in r.script_hex
        abi = next(m for m in r.artifact.abi.methods if m.name == "bump")
        assert abi.sig_hash_type == SINGLE_FORKID

    def test_control_without_fixed_array_is_unchanged(self):
        # Discriminator: the same contract with no FixedArray property already
        # honoured the directive, so a failure above is the expansion path.
        r = _ok(_sighash_src("/** @sighash SINGLE|FORKID */", ""))
        assert "0143" in r.script_hex
        assert "0141" not in r.script_hex
        assert next(m for m in r.artifact.abi.methods if m.name == "bump").sig_hash_type == SINGLE_FORKID

    def test_default_mode_still_pins_0x41(self):
        r = _ok(_sighash_src("", _ARRAY_PROP))
        assert "0141" in r.script_hex
        assert next(m for m in r.artifact.abi.methods if m.name == "bump").sig_hash_type is None


# ---------------------------------------------------------------------------
# CallExpr.asm_return_type
# ---------------------------------------------------------------------------

def _asm_src(array_prop: str) -> str:
    tail = "    assert(this.board[0] === this.n);\n" if array_prop else "    assert(this.n === this.n);\n"
    return f"""
class Boardy extends UnsafeSmartContract {{
{array_prop}  readonly n: bigint;
  constructor(n: bigint) {{ super(n); this.n = n; }}
  public go(): void {{
    const a: ByteString = asm<ByteString>({{ body: '00', in_arity: 0, out_arity: 1 }});
    const c: ByteString = a + a;
    assert(len(c) === 2n);
{tail}  }}
}}"""


_ASM_ARRAY_PROP = "  readonly board: FixedArray<bigint, 3> = [1n, 2n, 3n];\n"


class TestAsmReturnTypeSurvivesExpansion:
    def test_ast_field_survives_rewrite_expression(self):
        contract = _parse(_asm_src(_ASM_ARRAY_PROP))
        result = expand_fixed_arrays(contract)
        assert not result.errors, result.errors
        go = next(m for m in result.contract.methods if m.name == "go")
        decl = go.body[0]
        assert decl.name == "a"
        assert decl.init.asm_return_type == "ByteString", (
            "expand_fixed_arrays dropped CallExpr.asm_return_type"
        )

    def test_concat_emits_op_cat_not_op_add(self):
        r = _ok(_asm_src(_ASM_ARRAY_PROP))
        ops = (r.script_asm or "").split()
        assert "OP_CAT" in ops, "byte concat lowered to numeric OP_ADD after expansion"
        assert "OP_ADD" not in ops

    def test_control_without_fixed_array_is_unchanged(self):
        r = _ok(_asm_src(""))
        ops = (r.script_asm or "").split()
        assert "OP_CAT" in ops
        assert "OP_ADD" not in ops
