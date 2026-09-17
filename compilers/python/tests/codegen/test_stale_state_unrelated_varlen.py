"""A terminal read of a FIXED-SIZE state field goes stale when a SIBLING field is var-length.

R-074, the third member of the issue-#100 family.

``_lower_deserialize_state`` picks its extraction strategy from a CONTRACT-level
fact — ``has_variable_length``, i.e. "does ANY mutable property carry a
push-data length prefix". When that is true, the only way to locate the state
section inside the BIP-143 scriptCode is the ``_codePart``-relative offset, so
the whole deserialization is gated on ``self.sm.has("_codePart")``; without it
the pass takes its ``OP_DROP`` shortcut and pushes NO mutable property at all,
and every later ``load_prop`` silently resolves to the DEPLOY-TIME constructor
placeholder baked into the locking script.

``_compute_uses_code_part``, which decides whether ``_codePart`` is on the
stack, asked a strictly NARROWER, METHOD-level question: "does this method read
a var-length property". A terminal method that reads only the ``bigint``
sibling answered no, so ``_codePart`` was never provisioned and the contract's
own state became invisible to it.

The two questions must agree. ``6dc1979b`` (R-015 / CL-BUG-138) fixed a
different divergence in this same predicate -- which TYPES count as
variable-length -- and left this one live: there the method read the var-length
field itself, here it merely shares a contract with one.

Observed: ``check`` compiled to ``... OP_SPLIT OP_2DROP OP_0 OP_SWAP
OP_NUMEQUAL`` -- the state section split off and discarded, then the deploy-time
``count`` placeholder compared against the caller's argument. A rotating key or
a counter authorises with its original value forever; every on-chain update is
invisible to the script.

The matched control is the same contract with ``tag: bigint``: no var-length
property, ``has_variable_length`` False, the fixed-width split path, and a
correct live-state read all along. It must stay BYTE-IDENTICAL -- the fix is
confined to contracts that actually declare var-length state.
"""

from __future__ import annotations

import hashlib

from runar_compiler.compiler import compile_from_source_str_with_result


# `count` is fixed-size and IS read by the terminal method; `tag` is
# variable-length and is NOT touched by it.
PROBE_SRC = """
class StaleStateProbe extends StatefulSmartContract {
  count: bigint;
  tag: ByteString;
  constructor(count: bigint, tag: ByteString) {
    super(count, tag);
    this.count = count;
    this.tag = tag;
  }
  public check(expected: bigint) { assert(this.count == expected); }
}
"""

# Matched control: identical in every respect except `tag`'s type, which is the
# single input to `has_variable_length`.
CONTROL_SRC = """
class StaleStateProbe extends StatefulSmartContract {
  count: bigint;
  tag: bigint;
  constructor(count: bigint, tag: bigint) {
    super(count, tag);
    this.count = count;
    this.tag = tag;
  }
  public check(expected: bigint) { assert(this.count == expected); }
}
"""

# Same shape, reached through a private helper. Private methods are INLINED
# into the caller's stack context (deep-review finding C18), so the recursion
# that `_method_reads_var_len_state` already performs must keep working once
# the property set it is handed is widened.
PRIVATE_HELPER_SRC = """
class StaleStateProbe extends StatefulSmartContract {
  count: bigint;
  tag: ByteString;
  constructor(count: bigint, tag: ByteString) {
    super(count, tag);
    this.count = count;
    this.tag = tag;
  }
  private current(): bigint { return this.count; }
  public check(expected: bigint) { assert(this.current() == expected); }
}
"""

# A terminal method that reads NO mutable state at all. `has_variable_length`
# is true, but there is nothing to deserialize, so `_codePart` must stay off
# the stack -- the fix must not provision it unconditionally.
NO_STATE_READ_SRC = """
class StaleStateProbe extends StatefulSmartContract {
  count: bigint;
  tag: ByteString;
  constructor(count: bigint, tag: ByteString) {
    super(count, tag);
    this.count = count;
    this.tag = tag;
  }
  public check(expected: bigint) { assert(expected > 0); }
}
"""

# Byte-invariance pins, captured from the PRE-fix build. The control and the
# no-state-read variant are outside the fix's blast radius and must not move.
CONTROL_SHA256 = "4b1bff88a334cbc0604fada46ea297efada0825ed26769bbeef8c888c08b6722"

# The broken script this finding is about. Pinned as a MUST-NOT-EQUAL so a
# future regression cannot quietly restore it.
PROBE_BROKEN_SHA256 = (
    "150cb2a01cca2eb26bbbe02e2c090aa5d0c33957b07a7e385d951ec6452e0fb8"
)

# The BIP-143 scriptCode varint-strip cascade emitted by
# `_emit_strip_script_code_varint`. It appears ONLY on the `_codePart`-relative
# live-state path -- never on the fixed-width path and never on the discard
# shortcut -- so its presence is a structural proof that the method reads the
# state section rather than the constructor placeholder.
LIVE_STATE_MARKER = "<fd00> OP_LESSTHAN OP_IF"


def _compile(src: str):
    r = compile_from_source_str_with_result(
        src, "StaleStateProbe.runar.ts", disable_constant_folding=True
    )
    assert r.success, [d.message for d in r.diagnostics]
    return r


def _sha256(hex_str: str) -> str:
    return hashlib.sha256(hex_str.encode()).hexdigest()


def _uses_code_part(result) -> bool:
    for m in result.artifact.abi.methods:
        if m.name == "check":
            return bool(m.uses_code_part)
    raise AssertionError("method 'check' not found in ABI")


class TestTerminalReadWithUnrelatedVarLenSibling:
    def test_probe_provisions_code_part(self):
        """The read needs the `_codePart`-relative offset, so the ABI must
        declare the implicit parameter that carries it."""
        assert _uses_code_part(_compile(PROBE_SRC)) is True

    def test_probe_reads_live_state_not_the_deploy_placeholder(self):
        asm = _compile(PROBE_SRC).script_asm
        assert LIVE_STATE_MARKER in asm, (
            "terminal read of `count` did not take the live-state path; "
            f"asm tail: ...{asm[-160:]}"
        )

    def test_probe_no_longer_compiles_to_the_broken_script(self):
        assert _sha256(_compile(PROBE_SRC).script_hex) != PROBE_BROKEN_SHA256

    def test_private_helper_variant_matches_the_direct_read(self):
        assert (
            _compile(PRIVATE_HELPER_SRC).script_hex == _compile(PROBE_SRC).script_hex
        )

    def test_control_without_a_var_length_sibling_is_byte_unchanged(self):
        control = _compile(CONTROL_SRC)
        assert _sha256(control.script_hex) == CONTROL_SHA256
        assert _uses_code_part(control) is False

    def test_terminal_method_reading_no_state_does_not_provision_code_part(self):
        assert _uses_code_part(_compile(NO_STATE_READ_SRC)) is False
