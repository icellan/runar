# frozen_string_literal: true

# Poseidon2 Merkle proof codegen — Merkle root computation for Bitcoin Script
# using Poseidon2 KoalaBear compression.
#
# Follows the merkle.rb pattern: self-contained module imported by stack.rb.
#
# Unlike the SHA-256 Merkle variants (which use 32-byte hash digests),
# Poseidon2 KoalaBear Merkle trees represent each node as 8 KoalaBear field
# elements. Compression feeds two 8-element digests (16 elements total) into
# the Poseidon2 permutation and takes the first 8 elements of the output.
#
# The depth parameter must be a compile-time constant because the loop is
# unrolled at compile time (Bitcoin Script has no loops).
#
# Stack convention:
#   Input:  [..., leaf_0..leaf_7, sib0_0..sib0_7, ..., sib(D-1)_0..sib(D-1)_7, index]
#   Output: [..., root_0..root_7]
#
# Where D = depth. The leaf is 8 field elements, each sibling is 8 field
# elements, and index is a bigint whose bits determine left/right ordering at
# each tree level.
#
# Direct port of compilers/go/codegen/poseidon2_merkle.go

require_relative "poseidon2_koalabear"

module RunarCompiler
  module Codegen
    module Poseidon2Merkle
      # Helper: emit a ROLL operation for a given depth using raw StackOp hashes.
      #
      # @param emit [Proc] callback receiving a StackOp hash
      # @param d [Integer] roll depth
      def self.emit_roll(emit, d)
        return if d == 0
        if d == 1
          emit.call({ op: "swap" })
          return
        end
        if d == 2
          emit.call({ op: "rot" })
          return
        end
        emit.call({ op: "push", value: { kind: "bigint", big_int: d } })
        emit.call({ op: "roll", depth: d })
      end

      # Emit Poseidon2 Merkle root computation.
      #
      # Stack in:  [..., leaf(8 elems), proof(depth*8 elems), index]
      # Stack out: [..., root(8 elems)]
      #
      # depth is a compile-time constant (unrolled loop). Must be in [1, 32].
      # Higher depths produce quadratically larger scripts due to roll operations.
      #
      # @param emit [Proc] callback receiving a StackOp hash
      # @param depth [Integer] Merkle tree depth
      def self.emit_poseidon2_merkle_root(emit, depth)
        if depth < 1 || depth > 32
          raise "emit_poseidon2_merkle_root: depth must be in [1, 32], got #{depth}"
        end

        # Strategy overview:
        #
        # At each level i, the stack is:
        #   [..., current(8), sib_i(8), future_sibs((depth-i-1)*8), index]
        #
        # 1. Save index to alt-stack (it stays there for the whole level).
        # 2. Compute direction bit from index (DUP before saving).
        # 3. Roll current(8)+sib_i(8) above future_sibs so they become the top 16.
        # 4. Retrieve bit from alt, do conditional swap.
        # 5. Poseidon2 compress (top 16 → top 8).
        # 6. Roll new_current(8) back below future_sibs.
        # 7. Restore index from alt.
        #
        # At the end, drop index and leave root(8) on the stack.

        depth.times do |i|
          # Stack: [..., current(8), sib_i(8), future_sibs(F*8), index]
          # where F = depth - i - 1 (number of future sibling groups)
          future_elems = (depth - i - 1) * 8

          # ----- Compute direction bit and save index + bit to alt -----
          emit.call({ op: "opcode", code: "OP_DUP" }) # dup index
          if i == 1
            emit.call({ op: "opcode", code: "OP_2DIV" })
          elsif i > 1
            emit.call({ op: "push", value: { kind: "bigint", big_int: i } })
            emit.call({ op: "opcode", code: "OP_RSHIFTNUM" })
          end
          emit.call({ op: "push", value: { kind: "bigint", big_int: 2 } })
          emit.call({ op: "opcode", code: "OP_MOD" })
          # Stack: [..., current(8), sib_i(8), future_sibs, index, bit]

          # Save bit then index to alt-stack.
          emit.call({ op: "opcode", code: "OP_TOALTSTACK" }) # save bit
          emit.call({ op: "opcode", code: "OP_TOALTSTACK" }) # save index
          # Stack: [..., current(8), sib_i(8), future_sibs]
          # Alt (top→bottom): [index, bit]

          # ----- Roll current+sib_i above future_sibs -----
          if future_elems > 0
            roll_depth = future_elems + 15
            16.times do
              emit_roll(emit, roll_depth)
            end
          end
          # Stack: [..., future_sibs, current(8), sib_i(8)]

          # ----- Retrieve bit and conditional swap -----
          emit.call({ op: "opcode", code: "OP_FROMALTSTACK" }) # get index
          emit.call({ op: "opcode", code: "OP_FROMALTSTACK" }) # get bit
          # Stack: [..., future_sibs, current(8), sib_i(8), index, bit]

          # Save index back to alt
          emit.call({ op: "swap" })
          emit.call({ op: "opcode", code: "OP_TOALTSTACK" }) # save index
          # Stack: [..., future_sibs, current(8), sib_i(8), bit]
          # Alt: [index]

          # OP_IF consumes bit. If bit==1, swap current and sibling groups.
          emit.call({
            op: "if",
            then: [
              # bit==1: swap the two groups of 8 elements.
              # 8x roll(15) moves each element of the bottom group (current)
              # above the top group (sibling).
              { op: "push", value: { kind: "bigint", big_int: 15 } },
              { op: "roll", depth: 15 },
              { op: "push", value: { kind: "bigint", big_int: 15 } },
              { op: "roll", depth: 15 },
              { op: "push", value: { kind: "bigint", big_int: 15 } },
              { op: "roll", depth: 15 },
              { op: "push", value: { kind: "bigint", big_int: 15 } },
              { op: "roll", depth: 15 },
              { op: "push", value: { kind: "bigint", big_int: 15 } },
              { op: "roll", depth: 15 },
              { op: "push", value: { kind: "bigint", big_int: 15 } },
              { op: "roll", depth: 15 },
              { op: "push", value: { kind: "bigint", big_int: 15 } },
              { op: "roll", depth: 15 },
              { op: "push", value: { kind: "bigint", big_int: 15 } },
              { op: "roll", depth: 15 },
            ],
            # bit==0: already in correct order [current(8), sibling(8)]
          })
          # Stack: [..., future_sibs, left(8), right(8)]

          # ----- Poseidon2 compress -----
          Poseidon2KoalaBear.emit_poseidon2_kb_compress(emit)
          # Stack: [..., future_sibs, new_current(8)]

          # ----- Roll new_current back below future_sibs -----
          if future_elems > 0
            roll_depth = 7 + future_elems
            future_elems.times do
              emit_roll(emit, roll_depth)
            end
          end
          # Stack: [..., new_current(8), future_sibs]

          # ----- Restore index from alt -----
          emit.call({ op: "opcode", code: "OP_FROMALTSTACK" })
          # Stack: [..., new_current(8), future_sibs, index]
        end

        # After all levels: [..., root(8), index]
        emit.call({ op: "drop" })
        # Stack: [..., root_0..root_7]
      end
    end
  end
end
