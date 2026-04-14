# frozen_string_literal: true

# Fiat-Shamir duplex sponge (DuplexChallenger) over KoalaBear — codegen for Bitcoin Script.
#
# Implements the Fiat-Shamir challenge derivation used by SP1's StackedBasefold
# verifier. The sponge uses Poseidon2 as the permutation primitive.
#
# Parameters (SP1 v6, DuplexChallenger<KoalaBear, KoalaPerm, 16, 8>):
#   - State width: 16 KoalaBear field elements
#   - Rate: 8 elements (positions 0-7)
#   - Capacity: 8 elements (positions 8-15)
#
# Key design property: the sponge position is tracked at codegen time (in Ruby),
# not at runtime (in Bitcoin Script). Because the verifier's transcript structure
# is fully deterministic, we always know exactly when to permute without runtime
# conditionals.
#
# Matches Plonky3 DuplexChallenger behavior:
#   - Observations write directly into the sponge state and invalidate cached
#     squeeze outputs. When the rate is filled, the state is permuted.
#   - Squeezing reads consecutive elements from the permuted state. A single
#     permutation provides up to RATE (8) squeeze outputs. Only when all cached
#     outputs are consumed does the next squeeze trigger a fresh permutation.
#   - Any observation after squeezing invalidates the cached outputs.
#
# Direct port of compilers/go/codegen/fiat_shamir_kb.go

require_relative "koalabear"
require_relative "poseidon2_koalabear"

module RunarCompiler
  module Codegen
    module FiatShamirKB
      # Full Poseidon2 state width (rate + capacity)
      FS_SPONGE_WIDTH = 16

      # Number of rate elements in the duplex sponge
      FS_SPONGE_RATE = 8

      # Return the canonical name for sponge state element i.
      #
      # @param i [Integer]
      # @return [String]
      def self.fs_sponge_state_name(i)
        "fs#{i}"
      end

      # ===================================================================
      # FiatShamirState — codegen-time duplex sponge state machine
      # ===================================================================

      # FiatShamirState tracks the duplex sponge position at codegen time, matching
      # Plonky3's DuplexChallenger semantics. The 16-element KoalaBear state lives
      # on the Bitcoin Script stack as fs0 (deepest) through fs15 (top).
      #
      # Two independent positions are tracked:
      #   - absorb_pos: where the next observation will be written (0..RATE-1)
      #   - squeeze_pos: where the next squeeze will read from (0..RATE-1)
      #   - output_valid: whether the current state has been permuted and is safe
      #     to squeeze from (invalidated by any observation)
      class FiatShamirState
        attr_reader :absorb_pos, :squeeze_pos, :output_valid

        def initialize
          @absorb_pos   = 0
          @squeeze_pos  = 0
          @output_valid = false
        end

        # EmitInit pushes 16 zero-valued KoalaBear field elements onto the stack as
        # the initial sponge state. After this call the stack contains:
        #   [..., fs0=0, fs1=0, ..., fs15=0]  (fs15 on top)
        #
        # @param t [KoalaBear::KBTracker]
        def emit_init(t)
          FS_SPONGE_WIDTH.times do |i|
            t.push_int(FiatShamirKB.fs_sponge_state_name(i), 0)
          end
          @absorb_pos   = 0
          @squeeze_pos  = 0
          @output_valid = false
        end

        # EmitObserve absorbs one KoalaBear field element from the top of the stack
        # into the sponge state. The element replaces the current rate slot and the
        # absorption position advances. When the rate is filled (absorb_pos reaches
        # FS_SPONGE_RATE), a Poseidon2 permutation is emitted, the position resets,
        # and the squeeze output becomes valid.
        #
        # Any observation invalidates cached squeeze outputs, matching DuplexChallenger
        # behavior where observation clears the output buffer.
        #
        # Stack in:  [..., fs0, ..., fs15, element]
        # Stack out: [..., fs0', ..., fs15']   (element consumed)
        #
        # @param t [KoalaBear::KBTracker]
        def emit_observe(t)
          target_name = FiatShamirKB.fs_sponge_state_name(@absorb_pos)

          # The element to absorb is on top of the stack. Rename it to a temp name
          # to avoid collision with the target sponge slot.
          t.rename("_fs_absorb_elem")

          # Bring the target sponge slot to the top and drop it.
          t.to_top(target_name)
          t.drop

          # Move the absorbed element to the top and rename it to the sponge slot.
          t.to_top("_fs_absorb_elem")
          t.rename(target_name)

          # Invalidate cached squeeze outputs — any observation means the state has
          # been modified and cannot be squeezed from without a fresh permutation.
          @output_valid = false

          @absorb_pos += 1
          if @absorb_pos == FS_SPONGE_RATE
            # Rate full — permute. After permutation, squeeze output is valid.
            emit_permute(t)
            @absorb_pos   = 0
            @squeeze_pos  = 0
            @output_valid = true
          end
        end

        # EmitSqueeze samples one KoalaBear field element from the sponge, matching
        # Plonky3's DuplexChallenger behavior:
        #
        #  1. If the output is not valid (observations have been made since last
        #     permutation) or all rate elements have been consumed (squeeze_pos >= RATE),
        #     a permutation is emitted to produce fresh output.
        #  2. The element at the current squeeze position is copied to the top of
        #     the stack as "_fs_squeezed".
        #  3. The squeeze position advances.
        #
        # Stack in:  [..., fs0, ..., fs15]
        # Stack out: [..., fs0', ..., fs15', sampled]
        #
        # @param t [KoalaBear::KBTracker]
        def emit_squeeze(t)
          if !@output_valid || @squeeze_pos >= FS_SPONGE_RATE
            # No valid output available — permute to produce fresh output.
            emit_permute(t)
            @absorb_pos   = 0
            @squeeze_pos  = 0
            @output_valid = true
          end

          # Copy the current rate element to the top.
          source_name = FiatShamirKB.fs_sponge_state_name(@squeeze_pos)
          t.copy_to_top(source_name, "_fs_squeezed")

          @squeeze_pos += 1
        end

        # EmitSqueezeExt4 samples 4 consecutive KoalaBear field elements from the
        # sponge, forming a quartic extension field element. This is equivalent to 4
        # sequential squeezes. With DuplexChallenger semantics, at most one permutation
        # is needed (since 4 < RATE = 8).
        #
        # Stack in:  [..., fs0, ..., fs15]
        # Stack out: [..., fs0', ..., fs15', e0, e1, e2, e3]
        #
        # @param t [KoalaBear::KBTracker]
        def emit_squeeze_ext4(t)
          4.times do |i|
            emit_squeeze(t)
            # Rename from _fs_squeezed to a numbered output name.
            t.rename("_fs_ext4_#{i}")
          end
        end

        # EmitSampleBits squeezes one field element and extracts its low n bits.
        # The result is an integer in [0, 2^n).
        #
        # Stack in:  [..., fs0, ..., fs15]
        # Stack out: [..., fs0', ..., fs15', bits]
        #
        # @param t [KoalaBear::KBTracker]
        # @param n [Integer] number of bits (must be in [1, 20])
        def emit_sample_bits(t, n)
          if n < 1 || n > 20
            raise "emit_sample_bits: n must be in [1, 20], got #{n} " \
                  "(n>20 has non-negligible bias over KoalaBear)"
          end
          emit_squeeze(t)
          # _fs_squeezed is on top. Mask to low n bits: val % (2^n).
          mask = 1 << n
          t.raw_block(["_fs_squeezed"], "_fs_bits") do |e|
            e.call(KoalaBear.make_stack_op(op: "push", value: KoalaBear.big_int_push(mask)))
            e.call(KoalaBear.make_stack_op(op: "opcode", code: "OP_MOD"))
          end
        end

        # EmitCheckWitness absorbs a witness element from the top of the stack,
        # squeezes a challenge, and verifies that the low `bits` bits of the
        # challenge are all zero (proof-of-work check).
        #
        # Stack in:  [..., fs0, ..., fs15, witness]
        # Stack out: [..., fs0', ..., fs15']   (witness consumed, assert on failure)
        #
        # @param t [KoalaBear::KBTracker]
        # @param bits [Integer] number of bits to check (must be in [1, 30])
        def emit_check_witness(t, bits)
          if bits < 1 || bits > 30
            raise "emit_check_witness: bits must be in [1, 30] (KoalaBear field is 31-bit), " \
                  "got #{bits}"
          end

          # Absorb the witness.
          emit_observe(t)

          # Squeeze a challenge element.
          emit_squeeze(t)

          # Extract low `bits` bits and assert they are zero.
          mask = 1 << bits
          t.raw_block(["_fs_squeezed"], "_fs_pow_check") do |e|
            e.call(KoalaBear.make_stack_op(op: "push", value: KoalaBear.big_int_push(mask)))
            e.call(KoalaBear.make_stack_op(op: "opcode", code: "OP_MOD"))
          end
          # Assert _fs_pow_check == 0: push 0, check equal, assert.
          t.push_int("_fs_pow_zero", 0)
          t.raw_block(["_fs_pow_check", "_fs_pow_zero"], nil) do |e|
            e.call(KoalaBear.make_stack_op(op: "opcode", code: "OP_NUMEQUAL"))
            e.call(KoalaBear.make_stack_op(op: "opcode", code: "OP_VERIFY"))
          end
        end

        private

        # Emit a full Poseidon2 permutation on the 16-element sponge state.
        # The sponge elements fs0..fs15 are renamed to the Poseidon2 canonical
        # names _p2s0.._p2s15, the permutation is applied, and the results are
        # renamed back to fs0..fs15.
        #
        # @param t [KoalaBear::KBTracker]
        def emit_permute(t)
          # Rename fs0..fs15 → _p2s0.._p2s15 and reorder for Poseidon2.
          FS_SPONGE_WIDTH.times do |i|
            t.to_top(FiatShamirKB.fs_sponge_state_name(i))
            t.rename(Poseidon2KoalaBear.p2kb_state_name(i))
          end

          # Cache the KoalaBear prime on the alt-stack for the duration of the permutation.
          t.push_prime_cache

          # Run the permutation.
          names = Poseidon2KoalaBear.p2kb_state_names
          Poseidon2KoalaBear.p2kb_permute(t, names)

          t.pop_prime_cache

          # Reorder post-permutation elements and rename back to fs0..fs15.
          FS_SPONGE_WIDTH.times do |i|
            t.to_top(Poseidon2KoalaBear.p2kb_state_name(i))
            t.rename(FiatShamirKB.fs_sponge_state_name(i))
          end
        end
      end
    end
  end
end
