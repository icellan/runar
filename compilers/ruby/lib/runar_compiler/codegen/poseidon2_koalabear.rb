# frozen_string_literal: true

# Poseidon2 permutation over KoalaBear field — codegen for Bitcoin Script.
#
# Implements the Poseidon2 hash function used by SP1 v6 for Merkle commitments
# and Fiat-Shamir challenges. All operations use the KoalaBear prime field
# (p = 2^31 - 2^24 + 1 = 2,130,706,433).
#
# Parameters (SP1 v6.0.2):
#   - State width: 16 KoalaBear field elements
#   - Sbox: x^3 (cube)
#   - External rounds: 8 (4 before internal, 4 after)
#   - Internal rounds: 20
#   - Total rounds: 28
#   - Digest: first 8 elements of the output state
#
# Direct port of compilers/go/codegen/poseidon2_koalabear.go

require_relative "koalabear"

module RunarCompiler
  module Codegen
    module Poseidon2KoalaBear
      include KoalaBear

      # =================================================================
      # Constants
      # =================================================================

      P2KB_WIDTH          = 16
      P2KB_EXTERNAL_ROUNDS = 8
      P2KB_INTERNAL_ROUNDS = 20
      P2KB_TOTAL_ROUNDS    = P2KB_EXTERNAL_ROUNDS + P2KB_INTERNAL_ROUNDS

      # Internal diagonal M-1 entries for the internal diffusion layer.
      # From Plonky3 p3-koala-bear DiffusionMatrixKoalaBear.
      #
      # V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24,
      #       -1/2^8, -1/8, -1/16, -1/2^24]  (all mod p)
      POSEIDON2_KB_INTERNAL_DIAG_M1 = [
        2_130_706_431, # V[0]  = -2 mod p
        1,             # V[1]  = 1
        2,             # V[2]  = 2
        1_065_353_217, # V[3]  = 1/2 mod p
        3,             # V[4]  = 3
        4,             # V[5]  = 4
        1_065_353_216, # V[6]  = -1/2 mod p
        2_130_706_430, # V[7]  = -3 mod p
        2_130_706_429, # V[8]  = -4 mod p
        2_122_383_361, # V[9]  = 1/2^8 mod p
        1_864_368_129, # V[10] = 1/8 mod p
        2_130_706_306, # V[11] = 1/2^24 mod p
        8_323_072,     # V[12] = -1/2^8 mod p
        266_338_304,   # V[13] = -1/8 mod p
        133_169_152,   # V[14] = -1/16 mod p
        127,           # V[15] = -1/2^24 mod p
      ].freeze

      # Round constants for all 28 rounds.
      # For external rounds, all 16 are used. For internal rounds (4-23), only [0].
      POSEIDON2_KB_ROUND_CONSTANTS = [
        # External initial rounds (0-3)
        [2_128_964_168, 288_780_357, 316_938_561, 2_126_233_899, 426_817_493, 1_714_118_888, 1_045_008_582, 1_738_510_837, 889_721_787, 8_866_516, 681_576_474, 419_059_826, 1_596_305_521, 1_583_176_088, 1_584_387_047, 1_529_751_136],
        [1_863_858_111, 1_072_044_075, 517_831_365, 1_464_274_176, 1_138_001_621, 428_001_039, 245_709_561, 1_641_420_379, 1_365_482_496, 770_454_828, 693_167_409, 757_905_735, 136_670_447, 436_275_702, 525_466_355, 1_559_174_242],
        [1_030_087_950, 869_864_998, 322_787_870, 267_688_717, 948_964_561, 740_478_015, 679_816_114, 113_662_466, 2_066_544_572, 1_744_924_186, 367_094_720, 1_380_455_578, 1_842_483_872, 416_711_434, 1_342_291_586, 1_692_058_446],
        [1_493_348_999, 1_113_949_088, 210_900_530, 1_071_655_077, 610_242_121, 1_136_339_326, 2_020_858_841, 1_019_840_479, 678_147_278, 1_678_413_261, 1_361_743_414, 61_132_629, 1_209_546_658, 64_412_292, 1_936_878_279, 1_980_661_727],
        # Internal rounds (4-23) — only element [0] is used
        [1_423_960_925, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [2_101_391_318, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_915_532_054, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [275_400_051, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_168_624_859, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_141_248_885, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [356_546_469, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_165_250_474, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_320_543_726, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [932_505_663, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_204_226_364, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_452_576_828, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_774_936_729, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [926_808_140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_184_948_056, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1_186_493_834, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [843_181_003, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [185_193_011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [452_207_447, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [510_054_082, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        # External final rounds (24-27)
        [1_139_268_644, 630_873_441, 669_538_875, 462_500_858, 876_500_520, 1_214_043_330, 383_937_013, 375_087_302, 636_912_601, 307_200_505, 390_279_673, 1_999_916_485, 1_518_476_730, 1_606_686_591, 1_410_677_749, 1_581_191_572],
        [1_004_269_969, 143_426_723, 1_747_283_099, 1_016_118_214, 1_749_423_722, 66_331_533, 1_177_761_275, 1_581_069_649, 1_851_371_119, 852_520_128, 1_499_632_627, 1_820_847_538, 150_757_557, 884_787_840, 619_710_451, 1_651_711_087],
        [505_263_814, 212_076_987, 1_482_432_120, 1_458_130_652, 382_871_348, 417_404_007, 2_066_495_280, 1_996_518_884, 902_934_924, 582_892_981, 1_337_064_375, 1_199_354_861, 2_102_596_038, 1_533_193_853, 1_436_311_464, 2_012_303_432],
        [839_997_195, 1_225_781_098, 2_011_967_775, 575_084_315, 1_309_329_169, 786_393_545, 995_788_880, 1_702_925_345, 1_444_525_226, 908_073_383, 1_811_535_085, 1_531_002_367, 1_635_653_662, 1_585_100_155, 867_006_515, 879_151_050],
      ].freeze

      # =================================================================
      # State naming helpers
      # =================================================================

      # Return the canonical name for state element i.
      #
      # @param i [Integer]
      # @return [String]
      def self.p2kb_state_name(i)
        "_p2s#{i}"
      end

      # Return an array of all 16 canonical state element names.
      #
      # @return [Array<String>]
      def self.p2kb_state_names
        Array.new(P2KB_WIDTH) { |i| p2kb_state_name(i) }
      end

      # =================================================================
      # Sbox: x^3 (cube) over KoalaBear field
      # =================================================================

      # poseidon2KBSbox: state[name] = state[name]^3 mod p.
      # Uses x^3 = x * x^2: two multiplications, one squaring copy.
      #
      # @param t [KoalaBear::KBTracker]
      # @param name [String]
      # @param round [Integer]
      # @param idx [Integer]
      def self.p2kb_sbox(t, name, round, idx)
        tmp = "_p2sbox_r#{round}_#{idx}"
        # x^2
        t.copy_to_top(name, "#{tmp}_sq_copy")
        KoalaBear.kb_field_sqr(t, "#{tmp}_sq_copy", "#{tmp}_sq")
        # x^3 = x * x^2
        KoalaBear.kb_field_mul(t, name, "#{tmp}_sq", "#{tmp}_cube")
        t.rename(name)
      end

      # =================================================================
      # External MDS: circ(2, 3, 1, 1) applied blockwise to 4 groups of 4
      # =================================================================

      # Apply the circulant matrix circ(2,3,1,1) to a 4-element block [a, b, c, d]:
      #   sum = a + b + c + d
      #   out0 = sum + a + 2*b  (= 2a + 3b + c + d)
      #   out1 = sum + b + 2*c  (= a + 2b + 3c + d)
      #   out2 = sum + c + 2*d  (= a + b + 2c + 3d)
      #   out3 = sum + d + 2*a  (= 3a + b + c + 2d)
      #
      # @param t [KoalaBear::KBTracker]
      # @param names [Array<String>] 4-element array, mutated in-place
      # @param round [Integer]
      # @param group [Integer]
      def self.p2kb_external_mds4(t, names, round, group)
        prefix = "_p2mds_r#{round}_g#{group}"

        # Compute sum = a + b + c + d (unreduced — intermediates consumed by mul)
        t.copy_to_top(names[0], "#{prefix}_ca")
        t.copy_to_top(names[1], "#{prefix}_cb")
        KoalaBear.kb_field_add_unreduced(t, "#{prefix}_ca", "#{prefix}_cb", "#{prefix}_ab")
        t.copy_to_top(names[2], "#{prefix}_cc")
        KoalaBear.kb_field_add_unreduced(t, "#{prefix}_ab", "#{prefix}_cc", "#{prefix}_abc")
        t.copy_to_top(names[3], "#{prefix}_cd")
        KoalaBear.kb_field_add_unreduced(t, "#{prefix}_abc", "#{prefix}_cd", "#{prefix}_sum")

        # out0 = sum + a + 2*b
        t.copy_to_top("#{prefix}_sum", "#{prefix}_s0")
        t.copy_to_top(names[0], "#{prefix}_a0")
        KoalaBear.kb_field_add_unreduced(t, "#{prefix}_s0", "#{prefix}_a0", "#{prefix}_sa0")
        t.copy_to_top(names[1], "#{prefix}_b0")
        KoalaBear.kb_field_mul_const(t, "#{prefix}_b0", 2, "#{prefix}_2b0")
        KoalaBear.kb_field_add(t, "#{prefix}_sa0", "#{prefix}_2b0", "#{prefix}_out0")

        # out1 = sum + b + 2*c
        t.copy_to_top("#{prefix}_sum", "#{prefix}_s1")
        t.copy_to_top(names[1], "#{prefix}_b1")
        KoalaBear.kb_field_add_unreduced(t, "#{prefix}_s1", "#{prefix}_b1", "#{prefix}_sb1")
        t.copy_to_top(names[2], "#{prefix}_c1")
        KoalaBear.kb_field_mul_const(t, "#{prefix}_c1", 2, "#{prefix}_2c1")
        KoalaBear.kb_field_add(t, "#{prefix}_sb1", "#{prefix}_2c1", "#{prefix}_out1")

        # out2 = sum + c + 2*d
        t.copy_to_top("#{prefix}_sum", "#{prefix}_s2")
        t.copy_to_top(names[2], "#{prefix}_c2")
        KoalaBear.kb_field_add_unreduced(t, "#{prefix}_s2", "#{prefix}_c2", "#{prefix}_sc2")
        t.copy_to_top(names[3], "#{prefix}_d2")
        KoalaBear.kb_field_mul_const(t, "#{prefix}_d2", 2, "#{prefix}_2d2")
        KoalaBear.kb_field_add(t, "#{prefix}_sc2", "#{prefix}_2d2", "#{prefix}_out2")

        # out3 = sum + d + 2*a
        t.copy_to_top("#{prefix}_sum", "#{prefix}_s3")
        t.copy_to_top(names[3], "#{prefix}_d3")
        KoalaBear.kb_field_add_unreduced(t, "#{prefix}_s3", "#{prefix}_d3", "#{prefix}_sd3")
        t.copy_to_top(names[0], "#{prefix}_a3")
        KoalaBear.kb_field_mul_const(t, "#{prefix}_a3", 2, "#{prefix}_2a3")
        KoalaBear.kb_field_add(t, "#{prefix}_sd3", "#{prefix}_2a3", "#{prefix}_out3")

        # Drop old state elements and sum
        t.to_top(names[0]); t.drop
        t.to_top(names[1]); t.drop
        t.to_top(names[2]); t.drop
        t.to_top(names[3]); t.drop
        t.to_top("#{prefix}_sum"); t.drop

        # Rename outputs to the original state names
        t.to_top("#{prefix}_out0"); t.rename(names[0])
        t.to_top("#{prefix}_out1"); t.rename(names[1])
        t.to_top("#{prefix}_out2"); t.rename(names[2])
        t.to_top("#{prefix}_out3"); t.rename(names[3])
      end

      # Apply the external MDS to all 16 state elements:
      #   1. Apply circ(2,3,1,1) to each group of 4 (via p2kb_external_mds4)
      #   2. Cross-group mixing: add sum of position-equivalent elements to each element
      #
      # @param t [KoalaBear::KBTracker]
      # @param names [Array<String>] 16-element array, mutated in-place
      # @param round [Integer]
      def self.p2kb_external_mds_full(t, names, round)
        # Step 1: Apply 4x4 MDS blockwise
        4.times do |g|
          group = [names[g * 4], names[g * 4 + 1], names[g * 4 + 2], names[g * 4 + 3]]
          p2kb_external_mds4(t, group, round, g)
          # Update names in-place (p2kb_external_mds4 mutates via rename, not the group array)
          # The tracker has renamed them, but our local names array still points to the originals.
          # Since names are strings (not modified), the tracker tracks them correctly via the same
          # string values. No update needed to names array — it still holds the correct keys.
        end

        # Step 2: Cross-group mixing
        # For each position k (0..3), sums[k] = state[k] + state[k+4] + state[k+8] + state[k+12]
        # Then add sums[k] to each state[i] where i % 4 == k
        prefix = "_p2xg_r#{round}"
        4.times do |k|
          sum_name = "#{prefix}_s#{k}"
          t.copy_to_top(names[k], sum_name)
          (1..3).each do |j|
            idx = k + j * 4
            add_name = "#{prefix}_a#{k}_#{j}"
            t.copy_to_top(names[idx], add_name)
            KoalaBear.kb_field_add(t, sum_name, add_name, "#{sum_name}_n")
            t.rename(sum_name)
          end
        end

        # Add sums[i%4] to each element
        P2KB_WIDTH.times do |i|
          k = i % 4
          sum_name = "#{prefix}_s#{k}"
          copy_name = "#{prefix}_sc#{i}"
          t.copy_to_top(sum_name, copy_name)
          KoalaBear.kb_field_add(t, names[i], copy_name, names[i])
        end

        # Clean up: drop the 4 sum accumulators
        4.times do |k|
          t.to_top("#{prefix}_s#{k}")
          t.drop
        end
      end

      # =================================================================
      # Internal diffusion: diagonal matrix + sum
      # =================================================================

      # Apply the internal linear layer:
      #   sum = sum(state[i])
      #   state[i] = state[i] * diag_m_1[i] + sum   for each i
      #
      # @param t [KoalaBear::KBTracker]
      # @param names [Array<String>] 16-element array
      # @param round [Integer]
      def self.p2kb_internal_diffusion(t, names, round)
        prefix = "_p2id_r#{round}"

        # Step 1: Compute sum of all state elements
        t.copy_to_top(names[0], "#{prefix}_acc")
        (1...P2KB_WIDTH).each do |i|
          t.copy_to_top(names[i], "#{prefix}_add#{i}")
          KoalaBear.kb_field_add(t, "#{prefix}_acc", "#{prefix}_add#{i}", "#{prefix}_acc_new")
          t.rename("#{prefix}_acc")
        end
        t.rename("#{prefix}_sum")

        # Step 2: For each element, compute state[i] = state[i] * diag_m_1[i] + sum
        P2KB_WIDTH.times do |i|
          diag = POSEIDON2_KB_INTERNAL_DIAG_M1[i]
          prod_name = "#{prefix}_prod#{i}"

          if diag == 1
            # Multiplication by 1 is identity — just copy
            t.copy_to_top(names[i], prod_name)
          else
            t.copy_to_top(names[i], "#{prefix}_si#{i}")
            KoalaBear.kb_field_mul_const(t, "#{prefix}_si#{i}", diag, prod_name)
          end

          # Add sum
          t.copy_to_top("#{prefix}_sum", "#{prefix}_sc#{i}")
          KoalaBear.kb_field_add(t, prod_name, "#{prefix}_sc#{i}", "#{prefix}_out#{i}")
        end

        # Step 3: Drop old state elements and sum, rename outputs
        P2KB_WIDTH.times do |i|
          t.to_top(names[i])
          t.drop
        end
        t.to_top("#{prefix}_sum")
        t.drop

        P2KB_WIDTH.times do |i|
          t.to_top("#{prefix}_out#{i}")
          t.rename(names[i])
        end
      end

      # =================================================================
      # Add round constants
      # =================================================================

      # Add round constants to all 16 state elements (external rounds).
      #
      # @param t [KoalaBear::KBTracker]
      # @param names [Array<String>]
      # @param round [Integer]
      def self.p2kb_add_round_constants(t, names, round)
        P2KB_WIDTH.times do |i|
          rc = POSEIDON2_KB_ROUND_CONSTANTS[round][i]
          next if rc == 0 # Skip zero round constants (no-op addition)

          prefix = "_p2rc_r#{round}_#{i}"
          t.push_int("#{prefix}_c", rc)
          KoalaBear.kb_field_add(t, names[i], "#{prefix}_c", "#{prefix}_sum")
          t.rename(names[i])
        end
      end

      # Add round constant to element 0 only (internal rounds).
      #
      # @param t [KoalaBear::KBTracker]
      # @param names [Array<String>]
      # @param round [Integer]
      def self.p2kb_add_round_constant_elem0(t, names, round)
        rc = POSEIDON2_KB_ROUND_CONSTANTS[round][0]
        return if rc == 0 # Skip zero round constants

        prefix = "_p2rc_r#{round}_0"
        t.push_int("#{prefix}_c", rc)
        KoalaBear.kb_field_add(t, names[0], "#{prefix}_c", "#{prefix}_sum")
        t.rename(names[0])
      end

      # =================================================================
      # Full Poseidon2 permutation
      # =================================================================

      # Apply the full Poseidon2 permutation to 16 state elements on the tracker stack.
      # The names array is used to track element names (not mutated as a Ruby object,
      # but the tracker tracks renames internally).
      #
      # Algorithm:
      #   Initial — external MDS (Plonky3's external_initial_permute_state)
      #   Phase 1 — 4 external rounds (rounds 0-3)
      #   Phase 2 — 20 internal rounds (rounds 4-23)
      #   Phase 3 — 4 external rounds (rounds 24-27)
      #
      # @param t [KoalaBear::KBTracker]
      # @param names [Array<String>] 16 state element names
      def self.p2kb_permute(t, names)
        # Initial MDS before external rounds
        p2kb_external_mds_full(t, names, -1)

        # Phase 1: 4 external rounds (rounds 0-3)
        4.times do |r|
          p2kb_add_round_constants(t, names, r)
          P2KB_WIDTH.times do |i|
            p2kb_sbox(t, names[i], r, i)
          end
          p2kb_external_mds_full(t, names, r)
        end

        # Phase 2: 20 internal rounds (rounds 4-23)
        (4...(4 + P2KB_INTERNAL_ROUNDS)).each do |r|
          p2kb_add_round_constant_elem0(t, names, r)
          p2kb_sbox(t, names[0], r, 0)
          p2kb_internal_diffusion(t, names, r)
        end

        # Phase 3: 4 external rounds (rounds 24-27)
        ((4 + P2KB_INTERNAL_ROUNDS)...P2KB_TOTAL_ROUNDS).each do |r|
          p2kb_add_round_constants(t, names, r)
          P2KB_WIDTH.times do |i|
            p2kb_sbox(t, names[i], r, i)
          end
          p2kb_external_mds_full(t, names, r)
        end
      end

      # =================================================================
      # Public emit functions
      # =================================================================

      # Emit the full Poseidon2 permutation over KoalaBear.
      #
      # Stack in:  [..., s0, s1, ..., s15] (s15 on top)
      # Stack out: [..., s0', s1', ..., s15'] (s15' on top)
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_poseidon2_kb_permute(emit)
        init_names = Array.new(P2KB_WIDTH) { |i| p2kb_state_name(i) }
        t = KoalaBear::KBTracker.new(init_names, emit)
        t.push_prime_cache # Cache the KoalaBear prime on alt-stack

        names = p2kb_state_names
        p2kb_permute(t, names)

        t.pop_prime_cache # Clean up cached prime

        # Reorder so that _p2s0 is deepest and _p2s15 is on top
        P2KB_WIDTH.times do |i|
          t.to_top(p2kb_state_name(i))
        end
      end

      # Emit Poseidon2 compression (permute + truncate to 8 elements).
      #
      # Stack in:  [..., s0, s1, ..., s15] (s15 on top)
      # Stack out: [..., h0, h1, ..., h7] (h7 on top)
      #
      # The digest is the first 8 elements of the permuted state.
      # Elements s8'..s15' are dropped after permutation.
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_poseidon2_kb_compress(emit)
        init_names = Array.new(P2KB_WIDTH) { |i| p2kb_state_name(i) }
        t = KoalaBear::KBTracker.new(init_names, emit)
        t.push_prime_cache # Cache the KoalaBear prime on alt-stack

        names = p2kb_state_names
        p2kb_permute(t, names)

        t.pop_prime_cache # Clean up cached prime

        # Drop elements 8-15 (the non-digest portion)
        (8...P2KB_WIDTH).each do |i|
          t.to_top(p2kb_state_name(i))
          t.drop
        end

        # Reorder digest elements so _p2s0 is deepest, _p2s7 on top
        8.times do |i|
          t.to_top(p2kb_state_name(i))
        end
      end
    end
  end
end
