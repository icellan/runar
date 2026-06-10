# frozen_string_literal: true

require_relative 'types'

module Runar
  module Analyzer
    # Linear stack analysis for a single execution path (a list of opcode
    # records with IF/ELSE/ENDIF already filtered out).
    module StackAnalyzer
      # Static (pops, pushes) for one opcode record. Push operations
      # are (0, 1). RAW_SPAN uses op[:raw_span_arity].
      def self.stack_effect(op)
        return op[:raw_span_arity] if op[:opcode] == -1 # RAW_SPAN
        # Any push (direct, OP_0, OP_1NEGATE, OP_1..OP_16, pushdata1/2/4): (0,1)
        b = op[:opcode]
        return [0, 1] if b >= 0x01 && b <= 0x4b
        return [0, 1] if b == 0x00
        return [0, 1] if b == 0x4c || b == 0x4d || b == 0x4e
        return [0, 1] if b == 0x4f
        return [0, 1] if b >= 0x51 && b <= 0x60
        STACK_EFFECTS[b] || [0, 0]
      end

      # Analyze a sequence of (control-flow-filtered) opcodes. Returns
      # {findings:, depth:, max_depth:}.
      # - initial_depth: depth at start (default 0). For locking-script
      #   isolation, underflow is suppressed when initial_depth == 0.
      def self.analyze(ops, initial_depth: 0)
        depth = initial_depth
        max_depth = initial_depth
        after_return = false
        findings = []

        ops.each do |op|
          if after_return
            findings << {
              severity: 'warning',
              code: 'UNREACHABLE_AFTER_RETURN',
              message: "Unreachable opcode #{op[:name]} after OP_RETURN",
              offset: op[:offset],
              opcode: op[:name]
            }
            next
          end

          if op[:opcode] == 0x6a # OP_RETURN
            after_return = true
            next
          end

          pops, pushes = stack_effect(op)

          # Underflow check: only when initial_depth > 0 (spec §8.2 step 4).
          if initial_depth > 0 && depth < pops
            findings << {
              severity: 'error',
              code: 'STACK_UNDERFLOW',
              message: "#{op[:name]} requires #{pops} stack item(s) but only #{depth} available",
              offset: op[:offset],
              opcode: op[:name]
            }
          end

          depth = depth - pops + pushes
          max_depth = depth if depth > max_depth
        end

        { findings: findings, depth: depth, max_depth: max_depth }
      end

      # Flat delta sum over a range [from, to) of opcode records.
      # If any nested OP_IF/OP_NOTIF is present, returns nil (undefined).
      def self.flat_delta(ops, from, to)
        delta = 0
        (from...to).each do |i|
          op = ops[i]
          b = op[:opcode]
          return nil if b == 0x63 || b == 0x64
          next if b == 0x67 || b == 0x68
          pops, pushes = stack_effect(op)
          delta += (pushes - pops)
        end
        delta
      end
    end
  end
end
