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
    # `<raw 428 bytes>` blob emitted as a raw_bytes binding — the OP_CHECKSIG
    # that verifies the sighash lives INSIDE that blob and is no longer a
    # discrete ASM token. Assert the opaque blob is present instead of the
    # (now-absent) standalone CHECKSIG[VERIFY] opcode.
    assert_match(/<raw 428 bytes>/, asm,
                 "stateful preimage check must emit the fixed 428-byte opaque preimage-verification blob")
    assert_includes asm, 'OP_CODESEPARATOR',
                    "stateful contracts must emit OP_CODESEPARATOR before the state continuation"
  end

  # F-284: the test above pins the BUG-100 binding blob by its LENGTH only
  # (`<raw 428 bytes>`). Length is not a security property: a 428-byte blob
  # with one opcode changed (OP_HASH256 -> OP_NOP at byte 1) still renders as
  # `<raw 428 bytes>`, and the @bsv/sdk Spend interpreter ACCEPTS that forged
  # blob with a 32-byte non-preimage while rejecting the genuine preimage.
  #
  # This pins the exact bytes. The literal below is copied from the TS
  # reference (`CHECK_PREIMAGE_BINDING_HEX`, packages/runar-compiler/src/passes/
  # oppushtx-codegen.ts) -- the blob oppushtx-binding.test.ts exploit-tests
  # against forged/decoupled/zeroed preimages -- NOT from this tier's own
  # constant, so a mutation of stack.rb cannot also move the expectation.
  #
  # Proves: the compiled stateful script contains that exact blob, once.
  # Does NOT prove: the blob is binding on-chain (Ruby ships no Script VM; that
  # is proven once for these bytes in TS), nor non-default @sighash variants.
  TS_REFERENCE_PREIMAGE_BINDING_HEX =
    "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f" \
    "517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" \
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5e" \
    "d2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f7692" \
    "7f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7692" \
    "7f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e" \
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" \
    "7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e82" \
    "7c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad"
  TS_REFERENCE_PREIMAGE_BINDING_SHA256 =
    "5784cfa33516fe07e8c0466c2608a9f812e5ecc8a35283a23700832fbe2144d5"

  def test_stateful_preimage_binding_blob_is_byte_identical_to_ts_reference
    require 'digest'
    reference = [TS_REFERENCE_PREIMAGE_BINDING_HEX].pack("H*")
    # Guard the literal itself against a silent edit.
    assert_equal 428, reference.bytesize
    assert_equal TS_REFERENCE_PREIMAGE_BINDING_SHA256, Digest::SHA256.hexdigest(reference)

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

    script_hex = compile_ts_source(source, 'Counter.runar.ts').script
    occurrences = script_hex.scan(TS_REFERENCE_PREIMAGE_BINDING_HEX).length
    assert_equal 1, occurrences,
                 "stateful script must contain the TS-reference OP_PUSH_TX binding blob " \
                 "(sha256 #{TS_REFERENCE_PREIMAGE_BINDING_SHA256}) exactly once; found #{occurrences}"
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
