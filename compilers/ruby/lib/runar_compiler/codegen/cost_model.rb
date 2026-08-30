# frozen_string_literal: true

# Script-byte cost model for Stack IR.
#
# Port of packages/runar-compiler/src/metrics/cost-model.ts. Optimizer passes
# need to compare two candidate lowerings by the metric that actually matters --
# serialized locking-script bytes -- before either one is emitted. OP_DUP and a
# 33-byte constant push are one instruction each and 1 vs 34 bytes; an
# instruction count cannot tell them apart.
#
# This is deliberately NOT an approximation: every push routes through the same
# encoders emit.rb uses, so
#
#   estimate_script_bytes(ops) == emit_method(...).script_hex.length / 2
#
# holds exactly. test_cost_model.rb asserts that over every crypto emitter.

module RunarCompiler
  module Codegen
    module CostModel
      # Serialized byte cost of a single push value.
      #
      # Mirrors encode_push_value in emit.rb: booleans are the 1-byte OP_TRUE /
      # OP_FALSE, integers go through the small-int opcodes where possible, and
      # byte strings are MINIMALDATA-aware before falling back to a
      # length-prefixed push.
      #
      # @param value [Hash] PushValue hash
      # @return [Integer]
      def self.size_of_push_value(value)
        hex, _asm = Codegen.encode_push_value(value)
        hex.length / 2
      end

      # size_of_push_value for a bare integer -- what the constant pool and the
      # comb width search compare against.
      #
      # @param n [Integer]
      # @return [Integer]
      def self.size_of_push_int(n)
        size_of_push_value({ kind: "bigint", big_int: n })
      end

      # Serialized byte cost of one Stack IR operation, including nested arms.
      #
      # Note on pick / roll: they cost ONE byte here. The depth operand is a
      # separate push op that the tracker emits immediately before, so charging
      # the depth here would double-count it.
      #
      # Raises on an unknown opcode mnemonic rather than costing it zero -- a
      # typo in a codegen module should surface loudly, not as a cost model that
      # quietly under-reports.
      #
      # @param op [Hash] StackOp hash
      # @return [Integer]
      def self.size_of_stack_op(op)
        kind = op[:op]
        case kind
        when "push"
          size_of_push_value(op[:value])
        when "dup", "swap", "roll", "pick", "drop", "nip", "over", "rot", "tuck"
          1
        when "opcode"
          raise "cost-model: unknown opcode '#{op[:code]}'" if Codegen::OPCODES[op[:code]].nil?

          1
        when "if"
          # OP_IF + then + [OP_ELSE + else] + OP_ENDIF. The emitter writes
          # OP_ELSE only for a NON-EMPTY else arm.
          total = 2
          total += estimate_script_bytes(op[:then] || [])
          else_ops = op[:else_ops] || []
          total += 1 + estimate_script_bytes(else_ops) unless else_ops.empty?
          total
        when "placeholder", "push_codesep_index"
          # Both emit a single 0x00 byte that the SDK rewrites later.
          1
        when "raw_bytes"
          (op[:raw_bytes] || "").bytesize
        else
          raise "cost-model: unknown stack op kind '#{kind}'"
        end
      end

      # Serialized byte cost of a Stack IR sequence.
      #
      # @param ops [Array<Hash>]
      # @return [Integer]
      def self.estimate_script_bytes(ops)
        ops.sum { |op| size_of_stack_op(op) }
      end
    end
  end
end
