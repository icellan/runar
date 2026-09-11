# frozen_string_literal: true

require_relative 'codegen_helper'
require 'digest'
require 'runar_compiler/codegen/bn254'
require 'runar_compiler/codegen/emit'

# Cross-tier pin for the `bn254G1ScalarMul` ladder.
#
# `bn254G1ScalarMul` is a contract-callable builtin in every tier (see
# frontend/typecheck.rb), and until this pin existed nothing outside the Go
# tier had ever compared its emitted script against the reference. What the
# comparison found: the scalar was never reduced mod r.
#
# The ladder builds k' = k + 3r, seeds the accumulator at bit 255 rather than
# stepping it, and iterates bits 254..0. That is sound ONLY while
# 2^255 <= k' < 2^256, i.e. while 2^255 - 3r <= k < 2^256 - 3r (about
# -0.3549*r to 2.2902*r). Outside that window the ladder does not fail -- it
# applies the multiplier 2^255 + ((k + 3r) mod 2^255), which is not congruent
# to k mod r.
#
# Reducing also makes k = 0 mod r reachable, and there the final ladder step is
# handed accumulator == -base. The mixed-add's H == 0 test cannot tell -base
# from +base, so the last step additionally needs R == 0 (`strict`) or it
# returns -2P where the answer is the point at infinity. Both halves are pinned
# here.
class TestBn254ScalarDomain < Minitest::Test
  include CodegenTestHelpers

  # SHA-256 of the hex string of the raw (pre-peephole) ladder, taken from the
  # Go reference compiler (codegen.EmitBN254G1ScalarMul -> codegen.Emit) and
  # independently reproduced by the TypeScript tier. 42_910 ops, 134_245 bytes.
  LADDER_SHA256 = "0730fd206a234d76e6fe8079b3238cc58a10be6b487e76fa8193578ea0bc589f"

  # r, spelled out so this file compares against the reference rather than
  # against whatever the module currently believes.
  CURVE_R =
    21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617

  def ladder_ops
    ops = []
    RunarCompiler::Codegen::BN254.emit_bn254_g1_scalar_mul(->(op) { ops.push(op) })
    ops
  end

  def op_name(op)
    case op[:op]
    when "opcode" then op[:code]
    when "rot", "drop", "over", "swap" then "OP_#{op[:op].upcase}"
    when "push"
      v = op[:value]
      big = v.is_a?(Hash) ? (v[:big_int] || v[:bigint]) : v
      big == CURVE_R ? "PUSH_R" : "_"
    else "_"
    end
  end

  def test_scalar_mul_matches_the_cross_tier_pin
    hex = RunarCompiler::Codegen.emit_method({ name: "t", ops: ladder_ops }).script_hex
    assert_equal LADDER_SHA256, Digest::SHA256.hexdigest(hex),
                 "bn254G1ScalarMul diverged from the six-tier reference ladder " \
                 "(#{hex.length / 2} bytes emitted)"
  end

  # ((k mod r) + r) mod r, emitted exactly once, before the +3r offset.
  # OP_MOD takes the sign of the DIVIDEND, so `k mod r` alone lands in (-r, r);
  # the `+ r, mod r` normalises the negative half.
  def test_scalar_is_reduced_mod_r_before_the_ladder
    names = ladder_ops.map { |op| op_name(op) }
    want = %w[PUSH_R OP_2DUP OP_MOD OP_ROT OP_DROP OP_OVER OP_ADD OP_SWAP OP_MOD]
    hits = names.each_cons(want.length).count { |w| w == want }
    assert_equal 1, hits, "expected exactly one mod-r scalar reduce, found #{hits}"
  end

  # The extra R == 0 test is paid at the final step and nowhere else: two field
  # multiplications plus an OP_BOOLAND (+23 bytes) at one step, where paying it
  # at all 255 would be ~5.8 KB re-deciding a branch that cannot fire earlier.
  def test_only_the_last_ladder_step_is_strict
    branches = ladder_ops.select { |op| op[:op] == "if" }.map { |op| op[:then] }
    assert_equal 255, branches.length, "expected 255 conditional additions"

    boolands = lambda do |ops|
      ops.count { |o| o[:op] == "opcode" && o[:code] == "OP_BOOLAND" }
    end

    assert_equal boolands.call(branches[253]) + 1, boolands.call(branches[254]),
                 "the final step must combine H == 0 with R == 0"
    branches[0...254].each_with_index do |b, i|
      assert_equal boolands.call(branches[0]), boolands.call(b),
                   "step #{i} must not pay the strict test"
    end
  end
end
