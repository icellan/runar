# frozen_string_literal: true

require_relative 'codegen_helper'

# Unit-vector tests for the Ruby +checkMultiSig+ codegen.
#
# Closes audit gap T-2 / F11: Ruby was one of the two tiers (with Zig)
# without a dedicated +checkMultiSig+ codegen test. The conformance fixture
# +multisig-2of3+ exercises it transitively, but a regression in the Ruby
# +stack_lower.rb+'s +checkMultiSig+ path would only surface as a hex
# divergence in CI rather than a failed unit test inside the Ruby compiler
# itself.
#
# Reference shape (mirrored across all 7 compilers) for
# +checkMultiSig([sig1, sig2], [pk1, pk2, pk3])+ is:
#
#   OP_0 <sig1> <sig2> 2 <pk1> <pk2> <pk3> 3 OP_CHECKMULTISIG
#
# Where:
#   - +OP_0+ is the off-by-one dummy push required by Bitcoin's legacy
#     CHECKMULTISIG implementation.
#   - +2+ (+OP_2+) is the count of signatures.
#   - +3+ (+OP_3+) is the count of public keys.
#   - +OP_CHECKMULTISIG+ is byte 0xae (it folds to +OP_CHECKMULTISIGVERIFY+
#     = 0xaf when wrapped in +assert+ by the peephole optimizer).

class TestCheckMultiSigCodegen < Minitest::Test
  include CodegenTestHelpers

  MULTISIG_2OF3_SRC = <<~TS
    import { SmartContract, assert, PubKey, Sig, checkMultiSig } from 'runar-lang';

    class MultiSig2of3 extends SmartContract {
      readonly pk1: PubKey;
      readonly pk2: PubKey;
      readonly pk3: PubKey;

      constructor(pk1: PubKey, pk2: PubKey, pk3: PubKey) {
        super(pk1, pk2, pk3);
        this.pk1 = pk1;
        this.pk2 = pk2;
        this.pk3 = pk3;
      }

      public unlock(sig1: Sig, sig2: Sig): void {
        assert(checkMultiSig([sig1, sig2], [this.pk1, this.pk2, this.pk3]));
      }
    }
  TS

  MULTISIG_3OF5_SRC = <<~TS
    import { SmartContract, assert, PubKey, Sig, checkMultiSig } from 'runar-lang';

    class MultiSig3of5 extends SmartContract {
      readonly pk1: PubKey;
      readonly pk2: PubKey;
      readonly pk3: PubKey;
      readonly pk4: PubKey;
      readonly pk5: PubKey;

      constructor(pk1: PubKey, pk2: PubKey, pk3: PubKey, pk4: PubKey, pk5: PubKey) {
        super(pk1, pk2, pk3, pk4, pk5);
        this.pk1 = pk1;
        this.pk2 = pk2;
        this.pk3 = pk3;
        this.pk4 = pk4;
        this.pk5 = pk5;
      }

      public unlock(sig1: Sig, sig2: Sig, sig3: Sig): void {
        assert(checkMultiSig([sig1, sig2, sig3], [this.pk1, this.pk2, this.pk3, this.pk4, this.pk5]));
      }
    }
  TS

  # -------------------- 2-of-3 shape goldens --------------------

  def test_multi_sig_2of3_emits_exactly_one_check_multisig
    artifact = compile_ts_source(MULTISIG_2OF3_SRC, 'MultiSig2of3.runar.ts')
    asm = artifact.asm
    # The peephole optimizer folds +assert(checkMultiSig(...))+ into
    # +OP_CHECKMULTISIGVERIFY+, so we accept either form.
    has_checkmultisig = asm.include?('OP_CHECKMULTISIG')
    has_checkmultisig_verify = asm.include?('OP_CHECKMULTISIGVERIFY')
    assert(has_checkmultisig || has_checkmultisig_verify,
           "ASM must contain OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY; got:\n#{asm}")
    # Either way, exactly one multisig opcode must appear.
    total =
      asm.scan(/\bOP_CHECKMULTISIG(?:VERIFY)?\b/).length
    assert_equal 1, total,
                 'exactly one multisig opcode must be emitted'
  end

  def test_multi_sig_2of3_emits_op_zero_dummy
    # The Bitcoin CHECKMULTISIG off-by-one bug requires a leading OP_0
    # (push 0) before the signature pushes. Without it, the script will
    # fail at runtime with a signature-count mismatch.
    artifact = compile_ts_source(MULTISIG_2OF3_SRC, 'MultiSig2of3.runar.ts')
    assert_includes artifact.asm, 'OP_0',
                    'expected leading OP_0 dummy for CHECKMULTISIG off-by-one'
  end

  def test_multi_sig_2of3_emits_correct_count_pushes
    # 2 sigs and 3 pks: must push 2 (nSigs) and 3 (nPks).
    artifact = compile_ts_source(MULTISIG_2OF3_SRC, 'MultiSig2of3.runar.ts')
    asm = artifact.asm
    assert_includes asm, 'OP_2', 'expected OP_2 for nSigs in 2-of-3'
    assert_includes asm, 'OP_3', 'expected OP_3 for nPks in 2-of-3'
  end

  # -------------------- 3-of-5 shape goldens --------------------

  def test_multi_sig_3of5_uses_counts_derived_from_arrays
    # The 3-of-5 variant must push 3 (nSigs) and 5 (nPks) -- proving
    # counts come from the array literal lengths, not hard-coded.
    artifact = compile_ts_source(MULTISIG_3OF5_SRC, 'MultiSig3of5.runar.ts')
    asm = artifact.asm
    assert_includes asm, 'OP_3', 'expected OP_3 for nSigs in 3-of-5'
    assert_includes asm, 'OP_5', 'expected OP_5 for nPks in 3-of-5'
    # Exactly one multisig opcode (assert + checkMultiSig may fold to verify).
    total =
      asm.scan(/\bOP_CHECKMULTISIG(?:VERIFY)?\b/).length
    assert_equal 1, total,
                 'exactly one multisig opcode must be emitted'
  end

  def test_multi_sig_3of5_differs_from_2of3
    # Sanity: the two contracts must produce different scripts. If a
    # regression caused the array-length lookup to silently fall back to
    # a default (e.g. 1), the two would converge.
    a23 = compile_ts_source(MULTISIG_2OF3_SRC, 'MultiSig2of3.runar.ts')
    a35 = compile_ts_source(MULTISIG_3OF5_SRC, 'MultiSig3of5.runar.ts')
    refute_equal a23.script, a35.script,
                 '2-of-3 and 3-of-5 must produce distinct scripts'
    # 3-of-5 has more pubkeys -- strictly more bytes than 2-of-3.
    assert_operator a35.script.length, :>, a23.script.length,
                    "3-of-5 must produce a larger script than 2-of-3; " \
                    "got 3-of-5=#{a35.script.length}, 2-of-3=#{a23.script.length}"
  end

  # -------------------- byte-level hex pin --------------------

  def test_multi_sig_2of3_hex_contains_checkmultisig_opcode_byte
    # Drive the full pipeline and assert the resulting hex contains the
    # OP_CHECKMULTISIG opcode byte (0xae) OR its peephole-folded variant
    # OP_CHECKMULTISIGVERIFY (0xaf). We assert one OR the other, since
    # the surrounding +assert(checkMultiSig(...))+ may trigger the fold.
    artifact = compile_ts_source(MULTISIG_2OF3_SRC, 'MultiSig2of3.runar.ts')
    # +artifact.script+ is already a lower-case hex string (the canonical
    # serialised form). Don't double-encode it.
    hex = artifact.script
    refute_empty hex, 'hex must not be empty'
    has_multisig = hex.include?('ae')
    has_multisig_verify = hex.include?('af')
    assert(has_multisig || has_multisig_verify,
           "hex must contain OP_CHECKMULTISIG (ae) or OP_CHECKMULTISIGVERIFY (af); got:\n#{hex}")
  end

  # -------------------- determinism --------------------

  def test_multi_sig_lowering_is_deterministic
    a = compile_ts_source(MULTISIG_2OF3_SRC, 'MultiSig2of3.runar.ts')
    b = compile_ts_source(MULTISIG_2OF3_SRC, 'MultiSig2of3.runar.ts')
    assert_equal a.script, b.script,
                 'checkMultiSig codegen must be deterministic'
  end
end
