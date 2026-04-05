# frozen_string_literal: true

# Merkle proof codegen -- Merkle root computation for Bitcoin Script.
#
# Follows the ec.rb / babybear.rb pattern: self-contained module imported
# by stack.rb.
#
# Provides two variants:
# - merkleRootSha256: uses OP_SHA256 (single SHA-256, used by FRI/STARK)
# - merkleRootHash256: uses OP_HASH256 (double SHA-256, standard Bitcoin Merkle)
#
# The depth parameter must be a compile-time constant because the loop is
# unrolled at compile time (Bitcoin Script has no loops).
#
# Stack convention:
#   Input:  [..., leaf(32B), proof(depth*32 bytes), index(bigint)]
#   Output: [..., root(32B)]
#
# Algorithm per level i (0 to depth-1):
#   1. Extract sibling_i from proof (split first 32 bytes)
#   2. Compute direction: (index >> i) & 1
#   3. If direction=1: hash(sibling || current), else hash(current || sibling)
#   4. Result becomes current for next level
#
# Direct port of packages/runar-compiler/src/passes/merkle-codegen.ts

module RunarCompiler
  module Codegen
    module Merkle
      # Build a StackOp hash.
      #
      # @param op [String] operation type
      # @param kwargs [Hash] additional fields
      # @return [Hash] StackOp hash
      def self.make_stack_op(op:, **kwargs)
        result = { op: op }
        kwargs.each { |k, v| result[k] = v }
        result
      end

      # Build a PushValue hash for a big integer.
      #
      # @param n [Integer]
      # @return [Hash] PushValue hash
      def self.big_int_push(n)
        { kind: "bigint", big_int: n }
      end

      # Compute Merkle root using SHA-256.
      # Stack in: [..., leaf(32B), proof(depth*32B), index(bigint)]
      # Stack out: [..., root(32B)]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      # @param depth [Integer] compile-time constant: number of levels
      def self.emit_merkle_root_sha256(emit, depth)
        _emit_merkle_root(emit, depth, "OP_SHA256")
      end

      # Compute Merkle root using Hash256 (double SHA-256).
      # Stack in: [..., leaf(32B), proof(depth*32B), index(bigint)]
      # Stack out: [..., root(32B)]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      # @param depth [Integer] compile-time constant: number of levels
      def self.emit_merkle_root_hash256(emit, depth)
        _emit_merkle_root(emit, depth, "OP_HASH256")
      end

      # Core Merkle root computation.
      #
      # Stack layout at entry: [leaf, proof, index]
      #
      # For each level i from 0 to depth-1:
      #   Stack before iteration: [current, remaining_proof, index]
      #
      #   1. Get sibling: split remaining_proof at offset 32
      #   2. Get direction bit: (index >> i) & 1
      #   3. OP_IF (direction=1): swap current and sibling before concatenating
      #   4. OP_CAT + hash -> new current
      #
      # After all levels: [root, empty_proof, index]
      # Clean up: drop empty proof and index, leave root.
      #
      # @param emit [Proc] callback receiving a StackOp hash
      # @param depth [Integer] number of levels (compile-time constant)
      # @param hash_op [String] "OP_SHA256" or "OP_HASH256"
      def self._emit_merkle_root(emit, depth, hash_op)
        # Stack: [leaf, proof, index]

        depth.times do |i|
          # Stack: [current, proof, index]

          # --- Step 1: Extract sibling from proof ---
          # Roll proof to top: swap index and proof
          # Stack: [current, proof, index]
          # After roll(1): [current, index, proof]
          emit.call(make_stack_op(op: "swap"))

          # Split proof at 32 to get sibling
          # Stack: [current, index, proof]
          emit.call(make_stack_op(op: "push", value: big_int_push(32)))
          emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          # Stack: [current, index, sibling(32B), rest_proof]

          # Move rest_proof out of the way (to alt stack)
          emit.call(make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          # Stack: [current, index, sibling]  Alt: [rest_proof]

          # --- Step 2: Get direction bit ---
          # Bring index to top (it's at depth 1)
          emit.call(make_stack_op(op: "swap"))
          # Stack: [current, sibling, index]

          # Compute (index >> i) & 1
          emit.call(make_stack_op(op: "opcode", code: "OP_DUP"))
          # Stack: [current, sibling, index, index]
          if i > 0
            emit.call(make_stack_op(op: "push", value: big_int_push(i)))
            emit.call(make_stack_op(op: "opcode", code: "OP_RSHIFT"))
          end
          emit.call(make_stack_op(op: "push", value: big_int_push(1)))
          emit.call(make_stack_op(op: "opcode", code: "OP_AND"))
          # Stack: [current, sibling, index, direction_bit]

          # Move index below for safekeeping
          # Current stack: [current, sibling, index, direction_bit]
          emit.call(make_stack_op(op: "swap"))
          # Stack: [current, sibling, direction_bit, index]
          emit.call(make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          # Stack: [current, sibling, direction_bit]  Alt: [rest_proof, index]

          # --- Step 3: Conditional swap + concatenate + hash ---
          # Rearrange to get current and sibling adjacent:
          emit.call(make_stack_op(op: "rot"))
          # Stack: [sibling, direction_bit, current]
          emit.call(make_stack_op(op: "rot"))
          # Stack: [direction_bit, current, sibling]

          # Now: if direction_bit=1, swap current and sibling before CAT
          emit.call(make_stack_op(op: "rot"))
          # Stack: [current, sibling, direction_bit]

          emit.call(make_stack_op(
            op: "if",
            then: [
              # direction = 1: want hash(sibling || current), so swap
              make_stack_op(op: "swap"),
            ]
            # direction = 0: want hash(current || sibling), already in order
          ))
          # Stack: [a, b] where a||b is the correct concatenation order

          emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          emit.call(make_stack_op(op: "opcode", code: hash_op))
          # Stack: [new_current]

          # Restore index and rest_proof from alt stack
          emit.call(make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          # Stack: [new_current, index]
          emit.call(make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          # Stack: [new_current, index, rest_proof]

          # Reorder to [new_current, rest_proof, index]
          emit.call(make_stack_op(op: "swap"))
          # Stack: [new_current, rest_proof, index]
        end

        # Final stack: [root, empty_proof, index]
        # Clean up: drop index and empty proof
        emit.call(make_stack_op(op: "drop"))          # drop index
        emit.call(make_stack_op(op: "drop"))          # drop empty proof
        # Stack: [root]
      end

      # Merkle builtin function names.
      MERKLE_BUILTIN_NAMES = Set.new(%w[
        merkleRootSha256 merkleRootHash256
      ]).freeze

      # Return true if +name+ is a Merkle builtin.
      #
      # @param name [String]
      # @return [Boolean]
      def self.merkle_builtin?(name)
        MERKLE_BUILTIN_NAMES.include?(name)
      end

      private_class_method :_emit_merkle_root
    end
  end
end
