# frozen_string_literal: true

# Peephole optimizer -- runs on Stack IR before emission.
#
# Scans for short sequences of stack operations that can be replaced with
# fewer or cheaper opcodes. Applies rules iteratively until a fixed point
# is reached (no more changes).
#
# Port of compilers/python/runar_compiler/codegen/optimizer.py

module RunarCompiler
  module Codegen
    MAX_OPTIMIZATION_ITERATIONS = 100

    def self.optimize_stack_ops(ops)
      current = ops.map { |op| _optimize_nested_if(op) }

      MAX_OPTIMIZATION_ITERATIONS.times do
        result, changed = _apply_one_pass(current)
        break unless changed
        current = result
      end

      current
    end

    def self._optimize_nested_if(op)
      if op[:op] == "if"
        optimized_then = optimize_stack_ops(op[:then] || op[:then_ops] || [])
        optimized_else = optimize_stack_ops(op[:else_ops] || [])
        return { op: "if", then: optimized_then, else_ops: optimized_else, source_loc: op[:source_loc] }
      end
      op
    end
    private_class_method :_optimize_nested_if

    def self._propagate_source_loc(original, replacements)
      sl = original[:source_loc]
      return if sl.nil?
      replacements.each { |r| r[:source_loc] = sl if r[:source_loc].nil? }
    end
    private_class_method :_propagate_source_loc

    def self._apply_one_pass(ops)
      result = []
      changed = false
      i = 0

      while i < ops.length
        if i + 3 < ops.length
          replacement = _match_window4(ops[i], ops[i + 1], ops[i + 2], ops[i + 3])
          unless replacement.nil?
            _propagate_source_loc(ops[i], replacement)
            result.concat(replacement)
            i += 4
            changed = true
            next
          end
        end

        if i + 2 < ops.length
          replacement = _match_window3(ops[i], ops[i + 1], ops[i + 2])
          unless replacement.nil?
            _propagate_source_loc(ops[i], replacement)
            result.concat(replacement)
            i += 3
            changed = true
            next
          end
        end

        if i + 1 < ops.length
          replacement = _match_window2(ops[i], ops[i + 1])
          unless replacement.nil?
            _propagate_source_loc(ops[i], replacement)
            result.concat(replacement)
            i += 2
            changed = true
            next
          end
        end

        result << ops[i]
        i += 1
      end

      [result, changed]
    end
    private_class_method :_apply_one_pass

    # --- Raw-bytes barrier ---

    # raw_bytes is a hard peephole barrier -- no optimization window may span
    # or rewrite across it, because the bytes are opaque and not guaranteed
    # to form a well-formed opcode stream.
    def self._raw_bytes?(op)
      op[:op] == "raw_bytes"
    end
    private_class_method :_raw_bytes?

    # --- Window-2 rules ---

    def self._match_window2(a, b)
      return nil if _raw_bytes?(a) || _raw_bytes?(b)

      if a[:op] == "push" && b[:op] == "drop" then return [] end
      if a[:op] == "dup" && b[:op] == "drop" then return [] end
      if a[:op] == "swap" && b[:op] == "swap" then return [] end

      if _is_push_bigint(a, 1) && _is_opcode(b, "OP_ADD")
        return [{ op: "opcode", code: "OP_1ADD" }]
      end
      if _is_push_bigint(a, 1) && _is_opcode(b, "OP_SUB")
        return [{ op: "opcode", code: "OP_1SUB" }]
      end
      if _is_push_bigint(a, 0) && _is_opcode(b, "OP_ADD") then return [] end
      if _is_push_bigint(a, 0) && _is_opcode(b, "OP_SUB") then return [] end

      if _is_opcode(a, "OP_NOT") && _is_opcode(b, "OP_NOT") then return [] end
      if _is_opcode(a, "OP_NEGATE") && _is_opcode(b, "OP_NEGATE") then return [] end

      if _is_opcode(a, "OP_EQUAL") && _is_opcode(b, "OP_VERIFY")
        return [{ op: "opcode", code: "OP_EQUALVERIFY" }]
      end
      if _is_opcode(a, "OP_CHECKSIG") && _is_opcode(b, "OP_VERIFY")
        return [{ op: "opcode", code: "OP_CHECKSIGVERIFY" }]
      end
      if _is_opcode(a, "OP_NUMEQUAL") && _is_opcode(b, "OP_VERIFY")
        return [{ op: "opcode", code: "OP_NUMEQUALVERIFY" }]
      end
      if _is_opcode(a, "OP_CHECKMULTISIG") && _is_opcode(b, "OP_VERIFY")
        return [{ op: "opcode", code: "OP_CHECKMULTISIGVERIFY" }]
      end

      if _is_opcode(a, "OP_DUP") && _is_opcode(b, "OP_DROP") then return [] end
      if a[:op] == "over" && b[:op] == "over"
        return [{ op: "opcode", code: "OP_2DUP" }]
      end
      if a[:op] == "drop" && b[:op] == "drop"
        return [{ op: "opcode", code: "OP_2DROP" }]
      end

      # PUSH(0) + Roll(0) -> remove both
      if _is_push_bigint(a, 0) && ((b[:op] == "roll" && (b[:depth] || 0) == 0) || _is_opcode(b, "OP_ROLL"))
        return []
      end
      # PUSH(1) + Roll(1) -> Swap
      if _is_push_bigint(a, 1) && ((b[:op] == "roll" && (b[:depth] || 0) == 1) || _is_opcode(b, "OP_ROLL"))
        return [{ op: "swap" }]
      end
      # PUSH(2) + Roll(2) -> Rot
      if _is_push_bigint(a, 2) && ((b[:op] == "roll" && (b[:depth] || 0) == 2) || _is_opcode(b, "OP_ROLL"))
        return [{ op: "rot" }]
      end
      # PUSH(0) + Pick(0) -> Dup
      if _is_push_bigint(a, 0) && ((b[:op] == "pick" && (b[:depth] || 0) == 0) || _is_opcode(b, "OP_PICK"))
        return [{ op: "dup" }]
      end
      # PUSH(1) + Pick(1) -> Over
      if _is_push_bigint(a, 1) && ((b[:op] == "pick" && (b[:depth] || 0) == 1) || _is_opcode(b, "OP_PICK"))
        return [{ op: "over" }]
      end

      if _is_opcode(a, "OP_SHA256") && _is_opcode(b, "OP_SHA256")
        return [{ op: "opcode", code: "OP_HASH256" }]
      end
      if _is_push_bigint(a, 0) && _is_opcode(b, "OP_NUMEQUAL")
        return [{ op: "opcode", code: "OP_NOT" }]
      end

      nil
    end
    private_class_method :_match_window2

    # --- Window-3 rules ---

    def self._match_window3(a, b, c)
      return nil if _raw_bytes?(a) || _raw_bytes?(b) || _raw_bytes?(c)

      a_val = _push_bigint_value(a)
      b_val = _push_bigint_value(b)

      if !a_val.nil? && !b_val.nil?
        if _is_opcode(c, "OP_ADD")
          return [{ op: "push", value: { kind: "bigint", big_int: a_val + b_val } }]
        end
        if _is_opcode(c, "OP_SUB")
          return [{ op: "push", value: { kind: "bigint", big_int: a_val - b_val } }]
        end
        if _is_opcode(c, "OP_MUL")
          return [{ op: "push", value: { kind: "bigint", big_int: a_val * b_val } }]
        end
      end

      nil
    end
    private_class_method :_match_window3

    # --- Window-4 rules ---

    def self._match_window4(a, b, c, d)
      return nil if _raw_bytes?(a) || _raw_bytes?(b) || _raw_bytes?(c) || _raw_bytes?(d)

      a_val = _push_bigint_value(a)
      c_val = _push_bigint_value(c)

      if !a_val.nil? && !c_val.nil?
        if _is_opcode(b, "OP_ADD") && _is_opcode(d, "OP_ADD")
          return [
            { op: "push", value: { kind: "bigint", big_int: a_val + c_val } },
            { op: "opcode", code: "OP_ADD" }
          ]
        end
        if _is_opcode(b, "OP_SUB") && _is_opcode(d, "OP_SUB")
          return [
            { op: "push", value: { kind: "bigint", big_int: a_val + c_val } },
            { op: "opcode", code: "OP_SUB" }
          ]
        end
      end

      nil
    end
    private_class_method :_match_window4

    # --- Helpers ---

    def self._push_bigint_value(op)
      return nil unless op[:op] == "push"
      v = op[:value]
      return nil if v.nil?
      return nil unless v[:kind] == "bigint"
      v[:big_int]
    end
    private_class_method :_push_bigint_value

    def self._is_push_bigint(op, n)
      _push_bigint_value(op) == n
    end
    private_class_method :_is_push_bigint

    def self._is_opcode(op, code)
      op[:op] == "opcode" && op[:code] == code
    end
    private_class_method :_is_opcode
  end
end
