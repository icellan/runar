# frozen_string_literal: true

# Standalone WOTS+ (Winternitz One-Time Signature, w=16, n=32) Bitcoin Script
# codegen for the Runar Ruby stack lowerer.
#
# emit_verify_wots: [msg, sig, pubkey] -> [bool]
#   pubkey = 64B: pubSeed(32) || pkRoot(32)
#   sig    = 67 * 32B chain elements (64 message chains + 3 checksum chains)
#
# Direct port of compilers/python/runar_compiler/codegen/wots.py

module RunarCompiler
  module Codegen
    module WOTS
      # -----------------------------------------------------------------
      # Lazy StackOp / PushValue constructors
      # -----------------------------------------------------------------

      def self._make_stack_op(op:, **kwargs)
        if kwargs.key?(:else_)
          kwargs[:else_ops] = kwargs.delete(:else_)
        end
        result = { op: op }
        kwargs.each { |k, v| result[k] = v }
        result
      end
      private_class_method :_make_stack_op

      def self._make_push_value(kind:, **kwargs)
        if kwargs.key?(:bytes_)
          kwargs[:bytes_val] = kwargs.delete(:bytes_)
        end
        result = { kind: kind }
        kwargs.each { |k, v| result[k] = v }
        result
      end
      private_class_method :_make_push_value

      def self._big_int_push(n)
        { kind: "bigint", big_int: n }
      end
      private_class_method :_big_int_push

      # Emit one standalone WOTS+ chain verification.
      #
      # W=16, n=32. Entry stack: pubSeed(bottom) sigElem steps digit(top).
      # Uses simpler ADRS (2-byte: [chainIndex, hashStep]).
      #
      # @param emit [Proc] callback that receives a StackOp
      # @param chain_index [Integer] chain index (0..66)
      def self._emit_wots_one_chain(emit, chain_index)
        # Save steps_copy = 15 - digit to alt
        emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(15)))
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_SUB"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # push#1: steps_copy

        # Save endpt, csum to alt
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # push#2: endpt
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # push#3: csum

        # Split 32B sig element
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(32)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # push#4: sigRest
        emit.call(_make_stack_op(op: "swap"))

        # 15 unrolled conditional hash iterations
        15.times do |j|
          adrs_bytes = [chain_index & 0xFF, j & 0xFF].pack("C*")
          emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_0NOTEQUAL"))
          then_ops = [
            _make_stack_op(op: "opcode", code: "OP_1SUB"), # skip: digit--
          ]
          else_ops = [
            _make_stack_op(op: "swap"),
            _make_stack_op(op: "push", value: _big_int_push(2)),
            _make_stack_op(op: "opcode", code: "OP_PICK"),        # copy pubSeed
            _make_stack_op(op: "push", value: _make_push_value(kind: "bytes", bytes_: adrs_bytes)),
            _make_stack_op(op: "opcode", code: "OP_CAT"),          # pubSeed || adrs
            _make_stack_op(op: "swap"),                             # bring X to top
            _make_stack_op(op: "opcode", code: "OP_CAT"),          # pubSeed || adrs || X
            _make_stack_op(op: "opcode", code: "OP_SHA256"),       # F result
            _make_stack_op(op: "swap"),                             # pubSeed new_X digit(=0)
          ]
          emit.call(_make_stack_op(op: "if", then_ops: then_ops, else_: else_ops))
        end
        emit.call(_make_stack_op(op: "drop")) # drop digit

        # Restore: sigRest, csum, endpt_acc, steps_copy
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))

        # csum += steps_copy
        emit.call(_make_stack_op(op: "rot"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_ADD"))

        # Concat endpoint to endpt_acc
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(3)))
        emit.call(_make_stack_op(op: "roll", depth: 3))
        emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
      end
      private_class_method :_emit_wots_one_chain

      # Emit standalone WOTS+ signature verification.
      #
      # W=16, n=32 (SHA-256), len=67 chains (64 message + 3 checksum).
      # Input:  msg(2) sig(1) pubkey(0)  [pubkey=64B: pubSeed||pkRoot]
      # Output: boolean
      #
      # @param emit [Proc] callback that receives a StackOp
      def self.emit_verify_wots(emit)
        # Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
        emit.call(_make_stack_op(op: "push", value: _big_int_push(32)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # pkRoot -> alt

        # Rearrange: put pubSeed at bottom, hash msg
        emit.call(_make_stack_op(op: "opcode", code: "OP_ROT"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_ROT"))
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_SHA256"))

        # Canonical layout: pubSeed(bottom) sig csum=0 endptAcc=empty hashRem(top)
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(0)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_0"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(3)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_ROLL"))

        # Process 32 bytes -> 64 message chains
        32.times do |byte_idx|
          if byte_idx < 31
            emit.call(_make_stack_op(op: "push", value: _big_int_push(1)))
            emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
            emit.call(_make_stack_op(op: "swap"))
          end
          # Unsigned byte conversion
          emit.call(_make_stack_op(op: "push", value: _big_int_push(0)))
          emit.call(_make_stack_op(op: "push", value: _big_int_push(1)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
          # Extract nibbles
          emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
          emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
          emit.call(_make_stack_op(op: "swap"))
          emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))

          if byte_idx < 31
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
            emit.call(_make_stack_op(op: "swap"))
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          else
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          end

          _emit_wots_one_chain(emit, byte_idx * 2) # high nibble chain

          if byte_idx < 31
            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
            emit.call(_make_stack_op(op: "swap"))
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          else
            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          end

          _emit_wots_one_chain(emit, byte_idx * 2 + 1) # low nibble chain

          if byte_idx < 31
            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          end
        end

        # Checksum digits
        emit.call(_make_stack_op(op: "swap"))
        # d66
        emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
        # d65
        emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
        # d64
        emit.call(_make_stack_op(op: "push", value: _big_int_push(256)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

        # 3 checksum chains (indices 64, 65, 66)
        3.times do |ci|
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          emit.call(_make_stack_op(op: "push", value: _big_int_push(0)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          _emit_wots_one_chain(emit, 64 + ci)
          emit.call(_make_stack_op(op: "swap"))
          emit.call(_make_stack_op(op: "drop"))
        end

        # Final comparison
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "drop"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_SHA256"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # pkRoot
        emit.call(_make_stack_op(op: "opcode", code: "OP_EQUAL"))
        # Clean up pubSeed
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "drop"))
      end
    end
  end
end
