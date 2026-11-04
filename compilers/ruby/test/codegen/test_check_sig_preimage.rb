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

  def test_checksig_nonterminal_assert_folds_to_verify
    # F-378: renamed from `test_checksig_terminal_assert_folds_to_verify`.
    # The old name and comment claimed that a checkSig assert, when it is
    # the SOLE/terminal statement in the method, gets its trailing
    # OP_VERIFY folded by the peephole optimizer into OP_CHECKSIGVERIFY.
    # That premise is wrong: a terminal assert's OP_VERIFY is elided
    # entirely by `_lower_assert` in compilers/ruby/lib/runar_compiler/
    # codegen/stack.rb:3156-3167 (TS reference: 05-stack-lower.ts's
    # `terminalAssert` path) BEFORE the peephole optimizer ever runs,
    # because Bitcoin Script's own success rule (truthy top-of-stack at
    # script end) already enforces it. Compiling the OLD single-statement
    # contract produces only `OP_0 OP_CHECKSIG` -- verified byte-identical
    # against the TS reference compiler -- with no OP_VERIFY ever emitted
    # to fold, so the old assertion could never have observed a fold for
    # that contract shape, on top of being vacuous in its own right:
    # `asm.include?('OP_CHECKSIG') || asm.include?('OP_CHECKSIGVERIFY')` is
    # always true regardless of fold state, because
    # 'OP_CHECKSIGVERIFY'.include?('OP_CHECKSIG') is itself true (substring
    # match) -- so the first disjunct alone is satisfied by the folded form.
    #
    # To actually exercise the fold, checkSig's assert must NOT be the
    # method's terminal statement (a second assert follows it), which forces
    # stack-lowering to emit a real, foldable OP_CHECKSIG + OP_VERIFY pair --
    # verified byte-identical to the TS reference compiler
    # (`OP_SWAP OP_0 OP_CHECKSIGVERIFY OP_0 OP_NUMEQUAL`).
    #
    # Proves: for this non-terminal-assert shape, the Ruby peephole
    # optimizer (compilers/ruby/lib/runar_compiler/codegen/optimizer.rb:
    # 128-130) actually folds an adjacent OP_CHECKSIG + OP_VERIFY pair into
    # OP_CHECKSIGVERIFY, and that no bare OP_CHECKSIG token survives the
    # fold -- disabling the fold rule makes this exact test fail (verified
    # during remediation).
    # Does NOT prove: that the fold (or the terminal-assert elision it is
    # distinguished from) is correct on-chain -- Ruby ships no ScriptVM, so
    # on-chain semantic equivalence of OP_CHECKSIG+OP_VERIFY vs.
    # OP_CHECKSIGVERIFY is established once, in TS, not here. Nor does it
    # prove cross-tier byte parity for this shape generically -- that is
    # the conformance suite's job, not this unit test.
    source = <<~TS
      import { SmartContract, assert, checkSig } from 'runar-lang';
      import type { PubKey, Sig } from 'runar-lang';

      class NonTerminalSig extends SmartContract {
        readonly pk: PubKey;
        readonly x: bigint;

        constructor(pk: PubKey, x: bigint) {
          super(pk, x);
          this.pk = pk;
          this.x = x;
        }

        public unlock(sig: Sig, y: bigint): void {
          assert(checkSig(sig, this.pk));
          assert(y == this.x);
        }
      }
    TS

    artifact = compile_ts_source(source, 'NonTerminalSig.runar.ts')
    asm = artifact.asm
    # Tokenize the space-joined ASM and check the exact mnemonic (not a
    # substring) so the test fails if the fold regresses.
    tokens = asm.split(/\s+/)
    assert_includes tokens, 'OP_CHECKSIGVERIFY',
                    "expected the peephole optimizer to fold the non-terminal checkSig's " \
                    "OP_CHECKSIG + OP_VERIFY into OP_CHECKSIGVERIFY, got: #{asm[0, 200]}"
    refute_includes tokens, 'OP_CHECKSIG',
                    "expected no standalone OP_CHECKSIG left after the fold, got: #{asm[0, 200]}"
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
    # `<raw 422 bytes>` blob emitted as a raw_bytes binding — the OP_CHECKSIG
    # that verifies the sighash lives INSIDE that blob and is no longer a
    # discrete ASM token. Assert the opaque blob is present instead of the
    # (now-absent) standalone CHECKSIG[VERIFY] opcode.
    assert_match(/<raw 422 bytes>/, asm,
                 "stateful preimage check must emit the fixed 422-byte opaque preimage-verification blob")
    assert_includes asm, 'OP_CODESEPARATOR',
                    "stateful contracts must emit OP_CODESEPARATOR before the state continuation"
  end

  # F-284: the test above pins the BUG-100 binding blob by its LENGTH only
  # (`<raw 422 bytes>`). Length is not a security property: a 422-byte blob
  # with one opcode changed (OP_HASH256 -> OP_NOP at byte 1) still renders as
  # `<raw 422 bytes>`, and the @bsv/sdk Spend interpreter ACCEPTS that forged
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
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048af" \
    "e6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f8292" \
    "7f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f8292" \
    "7f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e" \
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" \
    "827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e" \
    "01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"
  TS_REFERENCE_PREIMAGE_BINDING_SHA256 =
    "e7210348b5f3a2af7c302a5285d127d00e800e852bf8572a751acc4800bfd406"

  def test_stateful_preimage_binding_blob_is_byte_identical_to_ts_reference
    require 'digest'
    reference = [TS_REFERENCE_PREIMAGE_BINDING_HEX].pack("H*")
    # Guard the literal itself against a silent edit.
    assert_equal 422, reference.bytesize
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

    # F-331: the previous version of this test only asserted
    # `artifact.respond_to?(:code_separator_index) || ...`. `Artifact` is a
    # `Struct`, so every declared member always responds_to? true regardless
    # of its value -- the assertion passed even when `code_separator_index`
    # was hard-coded wrong. It never checked the SDK-relevant thing: the
    # actual byte offset, which the SDK uses to slice `scriptCode` out of the
    # locking script before hashing the BIP-143 preimage. A wrong offset
    # produces a preimage over the wrong bytes, so `checkSig`/`checkPreimage`
    # verify against a signature the spender never actually signed.
    #
    # Pin to the TS reference compiler's value for this exact contract
    # (verified directly against packages/runar-compiler's `compile()`):
    # for a single-public-method stateful contract, codegen emits
    # `OP_NOP OP_CODESEPARATOR ...` so OP_CODESEPARATOR sits at byte
    # offset 1 (see packages/runar-compiler/src/passes/06-emit.ts
    # `codeSeparatorIndex = this.byteLength` right after the OP_NOP, and
    # compilers/ruby/lib/runar_compiler/codegen/emit.rb which mirrors it).
    assert_equal 1, artifact.code_separator_index,
                 'codeSeparatorIndex must be the actual OP_CODESEPARATOR byte offset, ' \
                 'not merely present on the artifact'
    assert_equal [1], artifact.code_separator_indices,
                 'codeSeparatorIndices must list the actual OP_CODESEPARATOR byte offset(s)'

    # Cross-check against the emitted bytes themselves: the byte at
    # code_separator_index must really be OP_CODESEPARATOR (0xab). This is
    # what ties the recorded index to the thing an SDK actually signs with.
    script_bytes = [artifact.script].pack('H*').bytes
    assert_equal 0xab, script_bytes[artifact.code_separator_index],
                 'the byte at codeSeparatorIndex must be OP_CODESEPARATOR (0xab)'
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
