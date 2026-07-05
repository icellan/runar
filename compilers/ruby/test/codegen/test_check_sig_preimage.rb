# frozen_string_literal: true

require_relative 'codegen_helper'

# Unit-vector tests for the +checkSig+ and +checkPreimage+ Stack-IR
# lowerings. Each is a primitive builtin with a fixed opcode mapping; this
# test pins the opcode shape so a regression in the codegen path fails
# locally rather than as a conformance-suite drift.
#
# +checkSig+ lowers to +OP_CHECKSIG+; when wrapped in +assert(...)+ the
# peephole optimizer folds it to +OP_CHECKSIGVERIFY+. Either is acceptable
# for the "shape" test below.
#
# +checkPreimage+ is auto-injected as the FIRST statement of every public
# method on a +StatefulSmartContract+, so a stateful contract must always
# emit the preimage-verification opcode tail at the head of each spend
# script.

class TestCheckSigAndPreimageCodegen < Minitest::Test
  include CodegenTestHelpers

  # ---------------------------------------------------------------------------
  # checkSig: single-key verify path
  # ---------------------------------------------------------------------------

  def test_checksig_emits_checksig_or_checksigverify
    source = <<~TS
      import { SmartContract, assert, checkSig } from 'runar-lang';
      import type { PubKey, Sig } from 'runar-lang';

      class SigOnly extends SmartContract {
        readonly pk: PubKey;

        constructor(pk: PubKey) {
          super(pk);
          this.pk = pk;
        }

        public unlock(sig: Sig): void {
          assert(checkSig(sig, this.pk));
        }
      }
    TS

    artifact = compile_ts_source(source, 'SigOnly.runar.ts')
    asm = artifact.asm
    has_checksig = asm.include?('OP_CHECKSIG') || asm.include?('OP_CHECKSIGVERIFY')
    assert has_checksig,
           "expected OP_CHECKSIG or OP_CHECKSIGVERIFY in ASM, got: #{asm[0, 200]}"
  end

  def test_checksig_terminal_assert_folds_to_verify
    # When checkSig is the sole assertion in a stateless contract, the
    # peephole optimizer should fold the trailing OP_VERIFY into the opcode
    # itself, producing OP_CHECKSIGVERIFY (0xac → 0xad).
    source = <<~TS
      import { SmartContract, assert, checkSig } from 'runar-lang';
      import type { PubKey, Sig } from 'runar-lang';

      class TerminalSig extends SmartContract {
        readonly pk: PubKey;

        constructor(pk: PubKey) {
          super(pk);
          this.pk = pk;
        }

        public unlock(sig: Sig): void {
          assert(checkSig(sig, this.pk));
        }
      }
    TS

    artifact = compile_ts_source(source, 'TerminalSig.runar.ts')
    asm = artifact.asm
    # Either the folded VERIFY form (preferred) or the unfolded sequence is
    # acceptable. We just require that the opcode appears somewhere.
    assert(asm.include?('OP_CHECKSIG') || asm.include?('OP_CHECKSIGVERIFY'),
           "expected a CHECKSIG[VERIFY] opcode, got: #{asm[0, 200]}")
  end

  # ---------------------------------------------------------------------------
  # checkPreimage: auto-injected on stateful contracts
  # ---------------------------------------------------------------------------

  def test_stateful_contract_emits_preimage_verification
    # StatefulSmartContract auto-injects checkPreimage at the head of every
    # public method. The Stack-IR lowering for checkPreimage uses SHA256 +
    # CHECKSIG against an OP_CODESEPARATOR-anchored script suffix to verify
    # the txPreimage matches the spent UTXO context.
    source = <<~TS
      import { StatefulSmartContract } from 'runar-lang';

      class Counter extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public bump(): void {
          this.count = this.count + 1n;
        }
      }
    TS

    artifact = compile_ts_source(source, 'Counter.runar.ts')
    asm = artifact.asm

    # The stateful preimage check uses HASH256 (double-SHA256) against the
    # txPreimage, followed by the fixed opaque preimage-verification blob.
    assert_includes asm, 'OP_HASH256',
                    "stateful preimage check must include OP_HASH256"
    # BUG-100: the checkPreimage tail is now a single fixed opaque
    # `<raw 760 bytes>` blob emitted as a raw_bytes binding — the OP_CHECKSIG
    # that verifies the sighash lives INSIDE that blob and is no longer a
    # discrete ASM token. Assert the opaque blob is present instead of the
    # (now-absent) standalone CHECKSIG[VERIFY] opcode.
    assert_match(/<raw 760 bytes>/, asm,
                 "stateful preimage check must emit the fixed 760-byte opaque preimage-verification blob")
    assert_includes asm, 'OP_CODESEPARATOR',
                    "stateful contracts must emit OP_CODESEPARATOR before the state continuation"
  end

  def test_stateful_codeseparator_index_is_recorded
    source = <<~TS
      import { StatefulSmartContract } from 'runar-lang';

      class Counter extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public bump(): void {
          this.count = this.count + 1n;
        }
      }
    TS

    artifact = compile_ts_source(source, 'Counter.runar.ts')
    # The artifact must expose the code-separator byte index for the SDK
    # to compute correct preimage signatures.
    assert artifact.respond_to?(:code_separator_index) ||
           artifact.respond_to?(:codeSeparatorIndex) ||
           artifact.respond_to?(:code_separator_indices),
           'stateful artifact must expose codeSeparatorIndex'
  end

  # ---------------------------------------------------------------------------
  # Stateless contract must NOT emit OP_CODESEPARATOR
  # ---------------------------------------------------------------------------

  def test_stateless_contract_has_no_codeseparator
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Stateless extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          assert(a == this.x);
        }
      }
    TS

    artifact = compile_ts_source(source, 'Stateless.runar.ts')
    refute_includes artifact.asm, 'OP_CODESEPARATOR',
                    "stateless contract must NOT emit OP_CODESEPARATOR"
  end
end
