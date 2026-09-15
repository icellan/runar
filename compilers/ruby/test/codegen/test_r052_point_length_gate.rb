# frozen_string_literal: true

require_relative 'codegen_helper'
require 'runar_compiler/codegen/ec'
require 'runar_compiler/codegen/p256_p384'

# R-052 / CL-BUG-095 -- the `Point` WIDTH gate.
#
# A `Point` is DEFINED as exactly 2*w bytes (x || y, big-endian, no prefix):
# 64 for secp256k1 and P-256, 96 for P-384. Nothing checked that in any tier,
# and every one of these values arrives as an unlock argument, so the blob is
# attacker-sized. Surplus bytes were silently DISCARDED, because the decompose
# helpers split at the coordinate width and the reversal helpers reverse exactly
# w bytes and drop the remainder. Measured on the real interpreter before the
# fix: `ecOnCurve(G || 0xff)` -> TRUE, `ecPointX(<32-byte blob>)` -> succeeds
# and returns the blob, and `ecEncodeCompressed(G || 0x01)` -> 03||x where
# `ecEncodeCompressed(G)` -> 02||x, i.e. one appended byte FLIPPED THE SIGN of
# the compressed encoding.
#
# These are shape assertions on the emitted op stream rather than a golden
# count: a count says "something moved", this says WHICH ops are there and in
# what order, which is what the fix actually is.
class TestR052PointLengthGate < Minitest::Test
  include CodegenTestHelpers

  def ops_for(emitter)
    ops = []
    emitter.call(->(op) { ops << op })
    ops
  end

  # Render an op the way the assertions below want to read it: opcodes by name,
  # pushes by their bigint value, everything else by its op tag.
  def tag(op)
    case op[:op]
    when 'opcode' then op[:code]
    when 'push'
      v = op[:value]
      v[:kind] == 'bigint' ? "push:#{v[:big_int]}" : "push:bytes(#{v[:bytes_val].bytesize})"
    else op[:op]
    end
  end

  def tags(ops)
    ops.map { |o| tag(o) }
  end

  # The ABORTING gate: OP_SIZE, push <want>, OP_NUMEQUALVERIFY.
  def assert_len_verify_at(ops, index, want, label)
    assert_equal ['OP_SIZE', "push:#{want}", 'OP_NUMEQUALVERIFY'],
                 tags(ops[index, 3]),
                 "#{label}: expected the width gate at op #{index}"
  end

  # ---------------------------------------------------------------------------
  # The aborting gate fires at the head of every direct Point consumer.
  # ---------------------------------------------------------------------------

  def test_ec_point_x_and_y_gate_the_width_first
    %w[emit_ec_point_x emit_ec_point_y].each do |m|
      ops = ops_for(RunarCompiler::Codegen::EC.method(m))
      assert_len_verify_at(ops, 0, 64, m)
    end
  end

  def test_ec_encode_compressed_gates_then_reads_parity_at_a_fixed_offset
    ops = tags(ops_for(RunarCompiler::Codegen::EC.method(:emit_ec_encode_compressed)))
    assert_len_verify_at(ops_for(RunarCompiler::Codegen::EC.method(:emit_ec_encode_compressed)),
                         0, 64, 'ecEncodeCompressed')

    # Parity comes from y[31] at a FIXED offset, never from the blob's last
    # byte. The old sequence computed the offset as OP_SIZE - 1, which is
    # exactly what let an appended byte choose the sign.
    assert_equal ['push:32', 'OP_SPLIT', 'push:31', 'OP_SPLIT', 'OP_NIP',
                  'OP_BIN2NUM', 'push:2', 'OP_MOD'],
                 ops[3, 8],
                 'ecEncodeCompressed: parity must be read at a fixed offset'
    refute_includes ops, 'OP_SUB',
                    'ecEncodeCompressed: OP_SIZE/OP_SUB offset arithmetic must be gone'
  end

  def test_p256_and_p384_encode_compressed_gate_their_own_widths
    [[:emit_p256_encode_compressed, 64, 32, 31],
     [:emit_p384_encode_compressed, 96, 48, 47]].each do |m, want, half, last|
      ops = ops_for(RunarCompiler::Codegen::NISTEC.method(m))
      assert_len_verify_at(ops, 0, want, m.to_s)
      assert_equal ["push:#{half}", 'OP_SPLIT', "push:#{last}", 'OP_SPLIT', 'OP_NIP',
                    'OP_BIN2NUM', 'push:2', 'OP_MOD'],
                   tags(ops)[3, 8],
                   "#{m}: parity must be read at a fixed offset"
    end
  end

  # ecAdd decomposes two points, so the gate appears twice; ecNegate once.
  def test_decompose_consumers_inherit_the_gate
    add = tags(ops_for(RunarCompiler::Codegen::EC.method(:emit_ec_add)))
    assert_equal 2, count_gates(add, 64), 'ecAdd gates both of its Point arguments'

    neg = tags(ops_for(RunarCompiler::Codegen::EC.method(:emit_ec_negate)))
    assert_equal 1, count_gates(neg, 64), 'ecNegate gates its Point argument'

    p384neg = tags(ops_for(RunarCompiler::Codegen::NISTEC.method(:emit_p384_negate)))
    assert_equal 1, count_gates(p384neg, 96), 'p384Negate gates at the P-384 width'
  end

  def count_gates(tag_list, want)
    n = 0
    tag_list.each_index do |i|
      n += 1 if tag_list[i, 3] == ['OP_SIZE', "push:#{want}", 'OP_NUMEQUALVERIFY']
    end
    n
  end

  # ---------------------------------------------------------------------------
  # The on-curve predicates CLAMP instead of aborting -- `if (ecOnCurve(p))`
  # has to keep working, so a wrong-length blob must answer `false`, not kill
  # the script. The flag is ANDed into the result.
  # ---------------------------------------------------------------------------

  def test_on_curve_clamps_and_ands_the_flag_in
    [[RunarCompiler::Codegen::EC.method(:emit_ec_on_curve), 64],
     [RunarCompiler::Codegen::NISTEC.method(:emit_p256_on_curve), 64],
     [RunarCompiler::Codegen::NISTEC.method(:emit_p384_on_curve), 96]].each do |m, want|
      ops = tags(ops_for(m))

      # The clamping gate, emitted first: flag = OP_SIZE == want, then the
      # value is forced to exactly `want` bytes by `v || 00*want` split at
      # `want` with the tail dropped.
      assert_equal ['OP_SIZE', "push:#{want}", 'OP_NUMEQUAL', 'swap',
                    "push:bytes(#{want})", 'OP_CAT', "push:#{want}", 'OP_SPLIT', 'drop'],
                   ops[0, 9],
                   'on-curve must clamp, not abort, on a wrong-length point'

      # The decompose that follows still carries its own ABORTING gate, and
      # that is fine: the clamp above has already forced the value to exactly
      # `want` bytes, so the OP_NUMEQUALVERIFY is provably true and the
      # predicate stays total. It is the same provably-true-ops situation as
      # `ecMulGen` pushing a constant generator into `ecMul`.
      assert_equal 1, count_gates(ops, want),
                   'on-curve decomposes exactly once, after the clamp'

      # ...and the tail folds `_len_ok` into the boolean result: after the
      # curve-equation compare there are exactly two OP_BOOLANDs -- `_canon AND
      # _curve_eq` -> `_eq_ok`, then `_len_ok AND _eq_ok` -> `_result` -- and
      # the emitter ends on one, so the flag cannot be left dangling on the
      # stack while a wrong-length point certifies as on-curve.
      tail = ops[(ops.rindex('OP_EQUAL') + 1)..]
      assert_equal 2, tail.count('OP_BOOLAND'),
                   'on-curve must AND the length flag into its result'
      assert_equal 'OP_BOOLAND', ops.last,
                   'on-curve must finish on the BOOLAND that folds in _len_ok'
    end
  end

  # ---------------------------------------------------------------------------
  # End-to-end: a contract using these builtins still compiles, and the gate
  # opcodes reach the final script.
  # ---------------------------------------------------------------------------

  def test_contract_using_ec_point_x_still_compiles_with_the_gate
    source = <<~TS
      import { SmartContract, assert, ecPointX, Point } from 'runar-lang';

      export class PointXGate extends SmartContract {
        constructor() {
          super();
        }

        public check(p: Point, x: bigint): void {
          assert(ecPointX(p) === x);
        }
      }
    TS

    artifact = compile_ts_source(source, 'PointXGate.runar.ts')
    assert_includes artifact.asm, 'OP_NUMEQUALVERIFY'
    refute_empty artifact.script
  end
end
