# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/codegen/optimizer"

class TestOptimizer < Minitest::Test
  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  def optimize(ops)
    RunarCompiler::Codegen.optimize_stack_ops(ops)
  end

  def push_bigint(n)
    { op: "push", value: { kind: "bigint", big_int: n } }
  end

  def push_bool(val)
    { op: "push", value: { kind: "bool", bool_val: val } }
  end

  def opcode(code)
    { op: "opcode", code: code }
  end

  # ---------------------------------------------------------------------------
  # 1. OP_DUP + OP_DROP eliminated
  # ---------------------------------------------------------------------------

  def test_dup_drop_eliminated
    ops = [opcode("OP_DUP"), opcode("OP_DROP")]
    result = optimize(ops)
    assert_empty result, "OP_DUP + OP_DROP should be eliminated"
  end

  # ---------------------------------------------------------------------------
  # 2. Push + drop eliminated
  # ---------------------------------------------------------------------------

  def test_push_drop_eliminated
    ops = [push_bigint(42), { op: "drop" }]
    result = optimize(ops)
    assert_empty result, "push + drop should be eliminated"
  end

  # ---------------------------------------------------------------------------
  # 3. dup + drop eliminated (abstract ops)
  # ---------------------------------------------------------------------------

  def test_abstract_dup_drop_eliminated
    ops = [{ op: "dup" }, { op: "drop" }]
    result = optimize(ops)
    assert_empty result, "dup + drop should be eliminated"
  end

  # ---------------------------------------------------------------------------
  # 4. Push 0 + OP_ADD kept (F-001)
  #
  # x + 0 = x over integers, but OP_ADD decodes its operand as a CScriptNum
  # (rejecting a non-minimal encoding under strict rules) and re-encodes it
  # minimally; a witness operand gets no other normalisation, so deleting the
  # pair changes accept/reject and value. Proves the Ruby peephole keeps the
  # pair; does not execute a script.
  # ---------------------------------------------------------------------------

  def test_push_zero_add_kept
    ops = [push_bigint(0), opcode("OP_ADD")]
    result = optimize(ops)
    assert_equal ops, result, "push(0) + OP_ADD must survive (F-001)"
  end

  # ---------------------------------------------------------------------------
  # 5. Push 0 + OP_SUB kept (F-001, as for OP_ADD)
  # ---------------------------------------------------------------------------

  def test_push_zero_sub_kept
    ops = [push_bigint(0), opcode("OP_SUB")]
    result = optimize(ops)
    assert_equal ops, result, "push(0) + OP_SUB must survive (F-001)"
  end

  # ---------------------------------------------------------------------------
  # 6. Push 1 + OP_ADD -> OP_1ADD
  # ---------------------------------------------------------------------------

  def test_push_one_add_becomes_1add
    ops = [push_bigint(1), opcode("OP_ADD")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_1ADD", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 7. Push 1 + OP_SUB -> OP_1SUB
  # ---------------------------------------------------------------------------

  def test_push_one_sub_becomes_1sub
    ops = [push_bigint(1), opcode("OP_SUB")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_1SUB", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 8. Double NOT eliminated ONLY over a provably canonical producer (C17)
  #
  # `OP_NOT OP_NOT` is boolean NORMALISATION, not numeric identity: for a
  # non-canonical operand (say 5) the pair yields 1, while deleting it leaves 5.
  # Truthiness is preserved, the VALUE is not -- and a downstream OP_EQUAL /
  # OP_NUMEQUAL / state serialisation consumes the value, so the optimised and
  # unoptimised programs disagree on accept/reject. The rule therefore matches a
  # 3-op window that includes the PRODUCER of the negated value.
  # ---------------------------------------------------------------------------

  def test_double_not_eliminated_over_canonical_bool_producer
    ops = [opcode("OP_NUMEQUAL"), opcode("OP_NOT"), opcode("OP_NOT")]
    result = optimize(ops)
    assert_equal 1, result.length, "redundant normalisation of a canonical bool should go"
    assert_equal "OP_NUMEQUAL", result[0][:code]
  end

  def test_double_not_eliminated_over_every_canonical_bool_producer
    %w[
      OP_EQUAL OP_NUMEQUAL OP_NUMNOTEQUAL OP_LESSTHAN OP_GREATERTHAN
      OP_LESSTHANOREQUAL OP_GREATERTHANOREQUAL OP_BOOLAND OP_BOOLOR
      OP_WITHIN OP_NOT OP_0NOTEQUAL OP_CHECKSIG OP_CHECKMULTISIG
    ].each do |producer|
      result = optimize([opcode(producer), opcode("OP_NOT"), opcode("OP_NOT")])
      assert_equal 1, result.length, "#{producer} leaves a canonical bool"
      assert_equal producer, result[0][:code]
    end
  end

  def test_double_not_eliminated_over_canonical_literal_pushes
    [push_bigint(0), push_bigint(1), push_bool(true), push_bool(false)].each do |producer|
      result = optimize([producer, opcode("OP_NOT"), opcode("OP_NOT")])
      assert_equal 1, result.length, "#{producer.inspect} is already canonical"
      assert_equal "push", result[0][:op]
    end
  end

  def test_double_not_kept_when_producer_is_not_provably_canonical
    # A rolled value has provenance this local window cannot see.
    ops = [{ op: "roll", depth: 3 }, opcode("OP_NOT"), opcode("OP_NOT")]
    result = optimize(ops)
    assert_equal 3, result.length, "double NOT over an arbitrary value must not be deleted"
    assert_equal "OP_NOT", result[1][:code]
    assert_equal "OP_NOT", result[2][:code]
  end

  def test_double_not_kept_with_no_visible_producer
    ops = [opcode("OP_NOT"), opcode("OP_NOT")]
    result = optimize(ops)
    assert_equal 2, result.length, "a bare NOT pair has no provable producer"
  end

  def test_double_not_kept_over_non_canonical_literal_push
    ops = [push_bigint(5), opcode("OP_NOT"), opcode("OP_NOT")]
    result = optimize(ops)
    assert_equal 3, result.length, "PUSH 5 OP_NOT OP_NOT yields 1, not 5"
  end

  # The exact composition that made this a bug: `push(0) + OP_NUMEQUAL -> OP_NOT`
  # (rule 23 below) manufactures a fresh OP_NOT sitting on an ARBITRARY script
  # number, which the old unguarded 2-op rule then ate together with the
  # lowerer's own OP_NOT -- compiling `x !== 0n` down to plain `x`.
  def test_push_zero_numequal_not_chain_keeps_both_nots
    ops = [{ op: "roll", depth: 3 }, push_bigint(0), opcode("OP_NUMEQUAL"), opcode("OP_NOT")]
    result = optimize(ops)
    assert_equal 3, result.length, "expected roll + OP_NOT + OP_NOT, got #{result.inspect}"
    assert_equal "roll", result[0][:op]
    assert_equal "OP_NOT", result[1][:code]
    assert_equal "OP_NOT", result[2][:code]
  end

  # End-to-end: the boolean is consumed by value (`=== true`), so the collapse
  # changes accept/reject. Peephole OFF the script is
  # `PUSH0 SWAP SWAP NUMEQUAL NOT PUSH1 SWAP SWAP NUMEQUAL`; the unguarded rule
  # optimised that to `519c` (compare the witness against 1 instead of against
  # "x is non-zero"), rejecting the valid spend x = 5.
  def test_not_equals_zero_survives_the_peephole_end_to_end
    require "runar_compiler/compiler"
    require "tmpdir"

    source = <<~TS
      class C17Check extends SmartContract {
        constructor() { super(); }
        public check(x: bigint): void { assert((x !== 0n) === true); }
      }
    TS

    Dir.mktmpdir do |dir|
      path = File.join(dir, "C17Check.runar.ts")
      File.write(path, source)
      artifact = RunarCompiler.compile_from_source(path, disable_constant_folding: true)
      assert_equal "9191519c", artifact.script,
                   "peephole must keep the OP_NOT OP_NOT boolean normalisation (C17)"
    end
  end

  # ---------------------------------------------------------------------------
  # 9. Double NEGATE kept (F-001, as for push(0) + OP_ADD)
  # ---------------------------------------------------------------------------

  def test_double_negate_kept
    ops = [opcode("OP_NEGATE"), opcode("OP_NEGATE")]
    result = optimize(ops)
    assert_equal ops, result, "double NEGATE must survive (F-001)"
  end

  # ---------------------------------------------------------------------------
  # 10. Double SWAP eliminated
  # ---------------------------------------------------------------------------

  def test_double_swap_eliminated
    ops = [{ op: "swap" }, { op: "swap" }]
    result = optimize(ops)
    assert_empty result, "double swap should be eliminated"
  end

  # ---------------------------------------------------------------------------
  # 11. OP_EQUAL + OP_VERIFY -> OP_EQUALVERIFY
  # ---------------------------------------------------------------------------

  def test_equal_verify_fused
    ops = [opcode("OP_EQUAL"), opcode("OP_VERIFY")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_EQUALVERIFY", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 12. OP_CHECKSIG + OP_VERIFY -> OP_CHECKSIGVERIFY
  # ---------------------------------------------------------------------------

  def test_checksig_verify_fused
    ops = [opcode("OP_CHECKSIG"), opcode("OP_VERIFY")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_CHECKSIGVERIFY", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 13. OP_NUMEQUAL + OP_VERIFY -> OP_NUMEQUALVERIFY
  # ---------------------------------------------------------------------------

  def test_numequal_verify_fused
    ops = [opcode("OP_NUMEQUAL"), opcode("OP_VERIFY")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_NUMEQUALVERIFY", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 14. OP_CHECKMULTISIG + OP_VERIFY -> OP_CHECKMULTISIGVERIFY
  # ---------------------------------------------------------------------------

  def test_checkmultisig_verify_fused
    ops = [opcode("OP_CHECKMULTISIG"), opcode("OP_VERIFY")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_CHECKMULTISIGVERIFY", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 15. Double SHA256 -> OP_HASH256
  # ---------------------------------------------------------------------------

  def test_double_sha256_becomes_hash256
    ops = [opcode("OP_SHA256"), opcode("OP_SHA256")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_HASH256", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 16. Constant folding in window-3: push(a) push(b) OP_ADD -> push(a+b)
  # ---------------------------------------------------------------------------

  def test_constant_fold_add
    ops = [push_bigint(3), push_bigint(5), opcode("OP_ADD")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "push", result[0][:op]
    assert_equal 8, result[0][:value][:big_int]
  end

  # ---------------------------------------------------------------------------
  # 17. Constant folding: push(a) push(b) OP_SUB -> push(a-b)
  # ---------------------------------------------------------------------------

  def test_constant_fold_sub
    ops = [push_bigint(10), push_bigint(3), opcode("OP_SUB")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal 7, result[0][:value][:big_int]
  end

  # ---------------------------------------------------------------------------
  # 18. Constant folding: push(a) push(b) OP_MUL -> push(a*b)
  # ---------------------------------------------------------------------------

  def test_constant_fold_mul
    ops = [push_bigint(4), push_bigint(7), opcode("OP_MUL")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal 28, result[0][:value][:big_int]
  end

  # ---------------------------------------------------------------------------
  # 19. Window-4: push(a) OP_ADD push(c) OP_ADD -> push(a+c) OP_ADD
  # ---------------------------------------------------------------------------

  def test_window4_add_add_coalesced
    ops = [push_bigint(2), opcode("OP_ADD"), push_bigint(3), opcode("OP_ADD")]
    result = optimize(ops)
    assert_equal 2, result.length
    assert_equal 5, result[0][:value][:big_int]
    assert_equal "OP_ADD", result[1][:code]
  end

  # ---------------------------------------------------------------------------
  # 20. Multiple passes converge
  # ---------------------------------------------------------------------------

  def test_multiple_passes_converge
    # push(7) + drop first eliminates to nothing,
    # but we add context around it that benefits from a second pass.
    # swap swap dup drop push(7) drop  (was push(0) OP_ADD; F-001 keeps it)
    ops = [
      { op: "swap" }, { op: "swap" },   # eliminate in pass 1
      { op: "dup" }, { op: "drop" },     # eliminate in pass 1
      push_bigint(7), { op: "drop" }     # eliminate in pass 1
    ]
    result = optimize(ops)
    assert_empty result, "all ops should be eliminated through multiple passes"
  end

  # ---------------------------------------------------------------------------
  # 21. Over + over -> OP_2DUP
  # ---------------------------------------------------------------------------

  def test_over_over_becomes_2dup
    ops = [{ op: "over" }, { op: "over" }]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_2DUP", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 22. Drop + drop -> OP_2DROP
  # ---------------------------------------------------------------------------

  def test_drop_drop_becomes_2drop
    ops = [{ op: "drop" }, { op: "drop" }]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_2DROP", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 23. push(0) + OP_NUMEQUAL -> OP_NOT
  # ---------------------------------------------------------------------------

  def test_push_zero_numequal_becomes_not
    ops = [push_bigint(0), opcode("OP_NUMEQUAL")]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "OP_NOT", result[0][:code]
  end

  # ---------------------------------------------------------------------------
  # 24. Nested if ops are optimized
  # ---------------------------------------------------------------------------

  def test_nested_if_optimized
    ops = [
      {
        op: "if",
        then: [opcode("OP_DUP"), opcode("OP_DROP")],
        else_ops: [push_bigint(7), { op: "drop" }]
      }
    ]
    result = optimize(ops)
    assert_equal 1, result.length
    assert_equal "if", result[0][:op]
    # then branch: OP_DUP + OP_DROP should be eliminated
    assert_empty result[0][:then], "then branch should be optimized away"
    # else branch: push(7) + drop should be eliminated (was push(0) + OP_ADD;
    # F-001 keeps that pair)
    assert_empty result[0][:else_ops], "else branch should be optimized away"
  end

  # ---------------------------------------------------------------------------
  # 25. Unrelated ops are preserved
  # ---------------------------------------------------------------------------

  def test_unrelated_ops_preserved
    ops = [opcode("OP_SHA256"), opcode("OP_HASH160"), opcode("OP_VERIFY")]
    result = optimize(ops)
    assert_equal 3, result.length
    assert_equal "OP_SHA256", result[0][:code]
    assert_equal "OP_HASH160", result[1][:code]
    assert_equal "OP_VERIFY", result[2][:code]
  end
end
