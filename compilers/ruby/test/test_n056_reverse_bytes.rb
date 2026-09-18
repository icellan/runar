# frozen_string_literal: true

require_relative "test_helper"

require "tmpdir"
require "digest"
require "runar_compiler/compiler"

# N-056 -- `reverseBytes` could not be compiled by the Ruby tier at all.
#
# The other six tiers compile
#
#     public check(data: ByteString, expected: ByteString): void {
#       assert(reverseBytes(data) == expected);
#       assert(this.tag > 0n);
#     }
#
# to a script whose SHA-256 is SIX_TIER_SCRIPT_SHA256 below (identical in both
# fold modes). Ruby aborted the compile with
#
#     Stack lowering: method parameter 'expected' is not on the stack at a
#     post-consumption reference (stack: [, t1]).
#
# The opcodes `_lower_reverse_bytes` emitted were already right; its SYMBOLIC
# stack bookkeeping was not. After consuming its argument it pushed a nil slot
# for the OP_0 accumulator, called `@sm.swap`, and later popped -- so the swap
# permuted the nil with whatever real name sat underneath (here the method
# parameter `expected`) and the pop then discarded that name instead of the
# placeholder. Every peer tier (go/codegen/stack.go#lowerReverseBytes,
# 05-stack-lower.ts#lowerReverseBytes) leaves the model alone across the
# emitted sequence: pop the argument, emit, push the binding.
#
# Two independent guards, deliberately not redundant:
#
#   1. Byte identity with the peer tiers (pinned SHA-256 + the literal 520x
#      unrolled reversal sequence). A different-but-correct reversal still
#      fails conformance, so "some reversal" is not the bar.
#
#   2. A miniature stack machine executes the emitted reversal on 0x0102 and
#      asserts 0x0201. This is the guard R-022 (ff4a19b7) added for the Zig
#      tier, which had shipped an emit-nothing stub: `reverseBytes` has the
#      failure mode where `assert(reverseBytes(a) === b)` passes exactly when
#      `a === b`, so a no-op implementation must be caught by semantics, not
#      by shape.
class TestN056ReverseBytes < Minitest::Test
  SOURCE = <<~TS
    import { SmartContract, assert, reverseBytes } from 'runar-lang';

    class RevProbe extends SmartContract {
      readonly tag: bigint;

      constructor(tag: bigint) {
        super(tag);
        this.tag = tag;
      }

      public check(data: ByteString, expected: ByteString): void {
        assert(reverseBytes(data) == expected);
        assert(this.tag > 0n);
      }
    }
  TS

  # SHA-256 of the script hex emitted by go / rust / zig / python / java / ts
  # for SOURCE, in BOTH fold modes (constant folding cannot reach a reversal of
  # a runtime parameter, so the two modes coincide).
  SIX_TIER_SCRIPT_SHA256 =
    "74999840f6f0d8114ddee5edb4b9f0f1c6d4418f4c5568fc242c87ac84ab35bf"

  # One unrolled iteration, as emitted by every tier:
  # OP_DUP OP_SIZE OP_NIP OP_IF OP_1 OP_SPLIT OP_SWAP OP_ROT OP_CAT OP_SWAP OP_ENDIF
  ITERATION_HEX = "76827763517f7c7b7e7c68"

  # 520 = the maximum BSV stack-element size, so the unrolled loop reverses any
  # legal ByteString.
  ITERATIONS = 520

  # OP_0 OP_SWAP, 520 unrolled iterations, OP_DROP.
  REVERSAL_HEX = "007c" + (ITERATION_HEX * ITERATIONS) + "75"

  def compile_script_hex(disable_constant_folding)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "RevProbe.runar.ts")
      File.write(path, SOURCE)
      RunarCompiler.compile_from_source(
        path, disable_constant_folding: disable_constant_folding
      ).script
    end
  end

  # --- guard 1: byte identity with the peer tiers ---------------------------

  def test_compiles_and_matches_the_six_tier_script
    [true, false].each do |disable|
      got = compile_script_hex(disable)
      assert_equal SIX_TIER_SCRIPT_SHA256, Digest::SHA256.hexdigest(got),
                   "reverseBytes script diverged from the six-tier agreed " \
                   "output (disable_constant_folding=#{disable})"
    end
  end

  def test_emits_the_full_unrolled_reversal
    [true, false].each do |disable|
      got = compile_script_hex(disable)
      assert_includes got, REVERSAL_HEX,
                      "the 520-iteration unrolled reversal is missing from " \
                      "the script (disable_constant_folding=#{disable})"
      assert_equal ITERATIONS, got.scan(ITERATION_HEX).length,
                   "expected exactly #{ITERATIONS} unrolled iterations " \
                   "(disable_constant_folding=#{disable})"
    end
  end

  # --- guard 2: the emitted sequence actually reverses ----------------------

  # A miniature Bitcoin-Script stack machine covering exactly the opcodes the
  # reversal uses. Stack elements are byte strings; "" is both the empty
  # element and false.
  def run_script(hex, initial_stack)
    stack = initial_stack.dup
    bytes = [hex].pack("H*").bytes
    i = 0
    # Skip-depth for untaken OP_IF branches (the reversal nests no ifs).
    skipping = false
    while i < bytes.length
      op = bytes[i]
      i += 1
      if skipping
        # Only OP_ENDIF ends the skipped branch; OP_1 (0x51) and the data-free
        # opcodes inside carry no operands, so a plain scan is sufficient.
        skipping = false if op == 0x68
        next
      end
      case op
      when 0x00 then stack.push("")                       # OP_0
      when 0x51 then stack.push("\x01".b)                 # OP_1
      when 0x75 then stack.pop                            # OP_DROP
      when 0x76 then stack.push(stack.last.dup)           # OP_DUP
      when 0x77 then stack.delete_at(-2)                  # OP_NIP
      when 0x7c                                           # OP_SWAP
        stack[-1], stack[-2] = stack[-2], stack[-1]
      when 0x7b                                           # OP_ROT
        stack.push(stack.delete_at(-3))
      when 0x7e                                           # OP_CAT
        b = stack.pop
        a = stack.pop
        stack.push(a + b)
      when 0x7f                                           # OP_SPLIT
        n = stack.pop
        num = n.empty? ? 0 : n.bytes.reverse.inject(0) { |acc, x| (acc << 8) | x }
        data = stack.pop
        stack.push(data[0, num].b)
        stack.push(data[num..].b)
      when 0x82                                           # OP_SIZE
        stack.push(encode_num(stack.last.bytesize))
      when 0x63                                           # OP_IF
        cond = stack.pop
        skipping = cond.bytes.all?(&:zero?)
      when 0x68 then nil                                  # OP_ENDIF
      else
        raise "unsupported opcode 0x#{op.to_s(16)} in reversal sequence"
      end
    end
    stack
  end

  def encode_num(n)
    return "" if n.zero?

    out = +""
    v = n
    while v.positive?
      out << (v & 0xff).chr
      v >>= 8
    end
    out << "\x00" if (out.bytes.last & 0x80) != 0
    out.b
  end

  # Pull the reversal out of what THIS tier actually emitted, so the semantics
  # below are checked against Ruby's own bytes and not against the constant.
  def emitted_reversal(disable_constant_folding)
    script = compile_script_hex(disable_constant_folding)
    start = script.index("007c" + ITERATION_HEX)
    refute_nil start,
               "no reversal sequence found in the emitted script " \
               "(disable_constant_folding=#{disable_constant_folding})"
    script[start, REVERSAL_HEX.length]
  end

  def test_reversal_sequence_reverses_a_value_unequal_to_itself
    # 0x0102 reverses to 0x0201, so a no-op ("leave the value as-is")
    # implementation cannot pass -- unlike a palindromic probe.
    [true, false].each do |disable|
      stack = run_script(emitted_reversal(disable), ["\x01\x02".b])
      assert_equal 1, stack.length, "reversal must leave exactly one element"
      assert_equal "\x02\x01".b, stack[0],
                   "the emitted sequence did not reverse 0x0102 " \
                   "(disable_constant_folding=#{disable})"
    end
  end

  def test_reversal_sequence_handles_a_longer_value
    assert_equal ["\xef\xbe\xad\xde".b],
                 run_script(emitted_reversal(true), ["\xde\xad\xbe\xef".b])
  end
end
