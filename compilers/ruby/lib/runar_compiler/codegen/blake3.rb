# frozen_string_literal: true

# BLAKE3 compression codegen for Bitcoin Script.
#
# emit_blake3_compress: [chainingValue(32 BE), block(64 BE)] -> [hash(32 BE)]
# emit_blake3_hash:     [message(<=64 BE)]                   -> [hash(32 BE)]
#
# Architecture (same as sha256.rb):
#   - All 32-bit words stored as 4-byte little-endian during computation.
#   - LE additions via BIN2NUM/NUM2BIN (13 ops per add32).
#   - Byte-aligned rotations (16, 8) via SPLIT/SWAP/CAT on LE (4 ops).
#   - Non-byte-aligned rotations (12, 7) via LE->BE->rotrBE->BE->LE (31 ops).
#   - BE<->LE conversion only at input unpack and output pack.
#
# Stack layout during rounds:
#   [m0..m15, v0..v15]  (all LE 4-byte values)
#   v15 at TOS (depth 0), v0 at depth 15, m15 at depth 16, m0 at depth 31.
#
# Direct port of compilers/python/runar_compiler/codegen/blake3.py

module RunarCompiler
  module Codegen
    module Blake3
      # -----------------------------------------------------------------
      # BLAKE3 constants
      # -----------------------------------------------------------------

      BLAKE3_IV = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
      ].freeze

      MSG_PERMUTATION = [
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
      ].freeze

      # Flags
      CHUNK_START = 1
      CHUNK_END = 2
      ROOT = 8

      # @param n [Integer] uint32
      # @return [String] 4-byte little-endian binary string
      def self._u32_to_le(n)
        [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff].pack("C*")
      end
      private_class_method :_u32_to_le

      # @param n [Integer] uint32
      # @return [String] 4-byte big-endian binary string
      def self._u32_to_be(n)
        [(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff].pack("C*")
      end
      private_class_method :_u32_to_be

      # -----------------------------------------------------------------
      # Precompute message schedule for all 7 rounds
      # -----------------------------------------------------------------

      def self._compute_msg_schedule
        schedule = []
        current = (0...16).to_a
        7.times do
          schedule << current.dup
          nxt = Array.new(16, 0)
          16.times { |i| nxt[i] = current[MSG_PERMUTATION[i]] }
          current = nxt
        end
        schedule
      end
      private_class_method :_compute_msg_schedule

      MSG_SCHEDULE = _compute_msg_schedule.freeze

      # -----------------------------------------------------------------
      # Lazy StackOp / PushValue constructors
      # -----------------------------------------------------------------

      def self._make_stack_op(op:, **kwargs)
        result = { op: op }
        kwargs.each { |k, v| result[k] = v }
        result
      end
      private_class_method :_make_stack_op

      def self._make_push_value(kind:, **kwargs)
        result = { kind: kind }
        kwargs.each { |k, v| result[k] = v }
        result
      end
      private_class_method :_make_push_value

      # -----------------------------------------------------------------
      # State word position tracker
      # -----------------------------------------------------------------

      class StateTracker
        attr_accessor :positions

        def initialize
          # Initial: v0 at depth 15 (deepest state word), v15 at depth 0 (TOS)
          @positions = Array.new(16) { |i| 15 - i }
        end

        def depth(word_idx)
          @positions[word_idx]
        end

        def on_roll_to_top(word_idx)
          d = @positions[word_idx]
          16.times do |j|
            next if j == word_idx
            if @positions[j] >= 0 && @positions[j] < d
              @positions[j] += 1
            end
          end
          @positions[word_idx] = 0
        end
      end

      # -----------------------------------------------------------------
      # Emitter with depth tracking
      # -----------------------------------------------------------------

      class Emitter
        attr_accessor :ops, :depth, :alt_depth

        def initialize(initial_depth)
          @ops = []
          @depth = initial_depth
          @alt_depth = 0
        end

        def _e(sop)
          @ops << sop
        end

        def e_raw(sop)
          @ops << sop
        end

        def oc(code)
          _e(Blake3.send(:_make_stack_op, op: "opcode", code: code))
        end

        def push_i(v)
          _e(Blake3.send(:_make_stack_op, op: "push",
            value: Blake3.send(:_make_push_value, kind: "bigint", big_int: v)))
          @depth += 1
        end

        def push_b(v)
          _e(Blake3.send(:_make_stack_op, op: "push",
            value: Blake3.send(:_make_push_value, kind: "bytes", bytes_val: v)))
          @depth += 1
        end

        def dup
          _e(Blake3.send(:_make_stack_op, op: "dup"))
          @depth += 1
        end

        def drop
          _e(Blake3.send(:_make_stack_op, op: "drop"))
          @depth -= 1
        end

        def swap
          _e(Blake3.send(:_make_stack_op, op: "swap"))
        end

        def over
          _e(Blake3.send(:_make_stack_op, op: "over"))
          @depth += 1
        end

        def nip
          _e(Blake3.send(:_make_stack_op, op: "nip"))
          @depth -= 1
        end

        def rot
          _e(Blake3.send(:_make_stack_op, op: "rot"))
        end

        def pick(d)
          if d == 0
            self.dup
            return
          end
          if d == 1
            self.over
            return
          end
          push_i(d)
          _e(Blake3.send(:_make_stack_op, op: "pick", depth: d))
        end

        def roll(d)
          return if d == 0
          if d == 1
            swap
            return
          end
          if d == 2
            rot
            return
          end
          push_i(d)
          _e(Blake3.send(:_make_stack_op, op: "roll", depth: d))
          @depth -= 1
        end

        def to_alt
          oc("OP_TOALTSTACK")
          @depth -= 1
          @alt_depth += 1
        end

        def from_alt
          oc("OP_FROMALTSTACK")
          @depth += 1
          @alt_depth -= 1
        end

        def bin_op(code)
          oc(code)
          @depth -= 1
        end

        def uni_op(code)
          oc(code)
        end

        def dup2
          oc("OP_2DUP")
          @depth += 2
        end

        def split
          oc("OP_SPLIT")
        end

        def split4
          push_i(4)
          self.split
        end

        def assert_depth(expected, msg)
          if @depth != expected
            raise RuntimeError,
              "BLAKE3 codegen: #{msg}. Expected depth #{expected}, got #{@depth}"
          end
        end

        # --- Byte reversal ---

        def reverse_bytes4
          push_i(1); self.split
          push_i(1); self.split
          push_i(1); self.split
          swap; bin_op("OP_CAT")
          swap; bin_op("OP_CAT")
          swap; bin_op("OP_CAT")
        end

        # --- LE <-> Numeric conversions ---

        def le2num
          push_b("\x00".b)
          bin_op("OP_CAT")
          uni_op("OP_BIN2NUM")
        end

        def num2le
          push_i(5)
          bin_op("OP_NUM2BIN")
          push_i(4)
          self.split
          self.drop
        end

        # --- LE arithmetic ---

        def add32
          le2num
          swap
          le2num
          bin_op("OP_ADD")
          num2le
        end

        def add_n(n)
          return if n < 2
          le2num
          (1...n).each do
            swap
            le2num
            bin_op("OP_ADD")
          end
          num2le
        end

        # --- ROTR/SHR using OP_LSHIFT/OP_RSHIFT ---

        def rotr_be(n)
          self.dup
          push_i(n)
          bin_op("OP_RSHIFT")
          swap
          push_i(32 - n)
          bin_op("OP_LSHIFT")
          bin_op("OP_OR")
        end

        # --- ROTR on LE values ---

        def rotr16_le
          push_i(2)
          self.split
          swap
          bin_op("OP_CAT")
        end

        def rotr8_le
          push_i(1)
          self.split
          swap
          bin_op("OP_CAT")
        end

        def rotr_le_general(n)
          reverse_bytes4   # LE -> BE (12 ops)
          rotr_be(n)       # rotate on BE (7 ops)
          reverse_bytes4   # BE -> LE (12 ops)
        end

        def be_words_to_le(n)
          n.times do
            reverse_bytes4
            to_alt
          end
          n.times do
            from_alt
          end
        end
      end

      # -----------------------------------------------------------------
      # G function (quarter-round)
      # -----------------------------------------------------------------

      def self._emit_half_g(em, rot_d, rot_b)
        d0 = em.depth

        # Save original b for step 4 (b is at depth 3)
        em.pick(3)
        em.to_alt

        # Step 1: a' = a + b + m
        # Stack: [a, b, c, d, m] -- a=4, b=3, c=2, d=1, m=0
        em.roll(3)    # [a, c, d, m, b]
        em.roll(4)    # [c, d, m, b, a]
        em.add_n(3)   # [c, d, a']
        em.assert_depth(d0 - 2, "halfG step1")

        # Step 2: d' = (d ^ a') >>> rotD
        # Stack: [c, d, a'] -- c=2, d=1, a'=0
        em.dup             # [c, d, a', a']
        em.rot             # [c, a', a', d]
        em.bin_op("OP_XOR") # [c, a', (d^a')]
        if rot_d == 16
          em.rotr16_le
        elsif rot_d == 8
          em.rotr8_le
        else
          em.rotr_le_general(rot_d)
        end
        em.assert_depth(d0 - 2, "halfG step2")

        # Step 3: c' = c + d'
        # Stack: [c, a', d']
        em.dup             # [c, a', d', d']
        em.roll(3)         # [a', d', d', c]
        em.add32           # [a', d', c']
        em.assert_depth(d0 - 2, "halfG step3")

        # Step 4: b' = (original_b ^ c') >>> rotB
        # Stack: [a', d', c']
        em.from_alt         # [a', d', c', b]
        em.over             # [a', d', c', b, c']
        em.bin_op("OP_XOR") # [a', d', c', (b^c')]
        em.rotr_le_general(rot_b)
        # Stack: [a', d', c', b']
        em.assert_depth(d0 - 1, "halfG step4")

        # Rearrange: [a', d', c', b'] -> [a', b', c', d']
        em.swap            # [a', d', b', c']
        em.rot             # [a', b', c', d']
        em.assert_depth(d0 - 1, "halfG done")
      end
      private_class_method :_emit_half_g

      def self._emit_g(em)
        d0 = em.depth

        # Save my to alt for phase 2
        em.to_alt         # [a, b, c, d, mx]

        # Phase 1: first half with mx, ROTR(16) and ROTR(12)
        _emit_half_g(em, 16, 12)
        em.assert_depth(d0 - 2, "G phase1")

        # Restore my for phase 2
        em.from_alt       # [a', b', c', d', my]
        em.assert_depth(d0 - 1, "G before phase2")

        # Phase 2: second half with my, ROTR(8) and ROTR(7)
        _emit_half_g(em, 8, 7)
        em.assert_depth(d0 - 2, "G done")
      end
      private_class_method :_emit_g

      # -----------------------------------------------------------------
      # G call with state management
      # -----------------------------------------------------------------

      def self._emit_g_call(em, tracker, ai, bi, ci, di, mx_orig_idx, my_orig_idx)
        d0 = em.depth

        # Roll 4 state words to top: a, b, c, d (d ends up as TOS)
        [ai, bi, ci, di].each do |idx|
          em.roll(tracker.depth(idx))
          tracker.on_roll_to_top(idx)
        end

        # Pick message words from below the 16 state word area
        em.pick(16 + (15 - mx_orig_idx))
        em.pick(16 + (15 - my_orig_idx) + 1) # +1 for mx just pushed
        em.assert_depth(d0 + 2, "before G")

        # Run G: consumes 6, produces 4
        _emit_g(em)
        em.assert_depth(d0, "after G")

        # Update tracker: result words at depths 0-3
        tracker.positions[ai] = 3
        tracker.positions[bi] = 2
        tracker.positions[ci] = 1
        tracker.positions[di] = 0
      end
      private_class_method :_emit_g_call

      # -----------------------------------------------------------------
      # Full compression ops generator
      # -----------------------------------------------------------------

      # BLAKE3 is little-endian: the message and chaining value are loaded as
      # little-endian 32-bit words and the digest is output as little-endian
      # bytes. A 4-byte Bitcoin Script byte-string IS a little-endian value, so
      # the raw 4-byte chunks are already the LE words — no per-word byte
      # reversal. (The previous impl applied a BE->LE per-word reversal here and
      # reverse_bytes4 on output, treating I/O as big-endian, which — together
      # with a hardcoded block_len — was BUG-101.)
      #
      # block_len_from_alt: when true, v[14] (block_len) is popped from the alt
      # stack (blake3Hash provides the real message length); otherwise it is the
      # constant 64 (blake3Compress operates on a full 64-byte block).
      def self._generate_compress_ops(block_len_from_alt: false)
        em = Emitter.new(2)

        # Phase 1: Unpack block into 16 LE message words (raw chunks are LE words)
        15.times { em.split4 }
        em.assert_depth(17, "after block unpack") # 16 block words + 1 chainingValue

        # Phase 2: Initialize 16-word state on top of message words
        em.roll(16)
        em.to_alt
        em.assert_depth(16, "after CV to alt")

        em.from_alt
        em.assert_depth(17, "after CV from alt")
        7.times { em.split4 }
        em.assert_depth(24, "after cv unpack")

        # v[8..11] = IV[0..3]
        4.times { |i| em.push_b(_u32_to_le(BLAKE3_IV[i])) }
        em.assert_depth(28, "after IV push")

        # v[12] = counter_low = 0, v[13] = counter_high = 0
        em.push_b(_u32_to_le(0))
        em.push_b(_u32_to_le(0))
        # v[14] = block_len — the real message length for blake3Hash (from alt),
        # or the constant 64 for a full-block blake3Compress.
        if block_len_from_alt
          em.from_alt
        else
          em.push_b(_u32_to_le(64))
        end
        # v[15] = flags = CHUNK_START | CHUNK_END | ROOT = 11
        em.push_b(_u32_to_le(CHUNK_START | CHUNK_END | ROOT))
        em.assert_depth(32, "after state init")

        # Phase 3: 7 rounds of G function calls
        tracker = StateTracker.new

        7.times do |round_idx|
          s = MSG_SCHEDULE[round_idx]

          # Column mixing
          _emit_g_call(em, tracker, 0, 4, 8, 12, s[0], s[1])
          _emit_g_call(em, tracker, 1, 5, 9, 13, s[2], s[3])
          _emit_g_call(em, tracker, 2, 6, 10, 14, s[4], s[5])
          _emit_g_call(em, tracker, 3, 7, 11, 15, s[6], s[7])

          # Diagonal mixing
          _emit_g_call(em, tracker, 0, 5, 10, 15, s[8], s[9])
          _emit_g_call(em, tracker, 1, 6, 11, 12, s[10], s[11])
          _emit_g_call(em, tracker, 2, 7, 8, 13, s[12], s[13])
          _emit_g_call(em, tracker, 3, 4, 9, 14, s[14], s[15])
        end

        em.assert_depth(32, "after all rounds")

        # Phase 4: Output -- hash[i] = state[i] XOR state[i+8], for i=0..7
        # Reorder state words to canonical positions using alt stack
        (15).downto(0) do |i|
          d = tracker.depth(i)
          em.roll(d)
          tracker.on_roll_to_top(i)
          em.to_alt
          16.times do |j|
            next if j == i
            if tracker.positions[j] >= 0
              tracker.positions[j] -= 1
            end
          end
          tracker.positions[i] = -1
        end

        # Pop to get canonical order: [v0(bottom)..v15(TOS)]
        16.times { em.from_alt }
        em.assert_depth(32, "after canonical reorder")

        # XOR pairs: h[7-k] = v[7-k] ^ v[15-k] for k=0..7
        8.times do |k|
          em.roll(8 - k)
          em.bin_op("OP_XOR")
          em.to_alt
        end
        em.assert_depth(16, "after XOR pairs")

        # Pop results to main
        8.times { em.from_alt }
        em.assert_depth(24, "after XOR results restored")

        # Pack into 32-byte little-endian digest: h0_LE || h1_LE || ... || h7_LE.
        # The words are already little-endian (BLAKE3 output is LE bytes), so no
        # per-word reversal — just concatenate the top two 7 times.
        (1...8).each { em.bin_op("OP_CAT") }
        em.assert_depth(17, "after hash pack")

        # Drop 16 message words
        16.times do
          em.swap
          em.drop
        end
        em.assert_depth(1, "compress final")

        em.ops
      end
      private_class_method :_generate_compress_ops

      # Cache the ops
      @blake3_compress_ops_cache = nil

      def self._get_compress_ops
        @blake3_compress_ops_cache ||= _generate_compress_ops
      end
      private_class_method :_get_compress_ops

      # -----------------------------------------------------------------
      # Public entry points
      # -----------------------------------------------------------------

      # Emit BLAKE3 single-block compression in Bitcoin Script.
      # Stack on entry: [..., chainingValue(32 BE), block(64 BE)]
      # Stack on exit:  [..., hash(32 BE)]
      # Net depth: -1
      #
      # @param emit [Proc] callback that receives a StackOp
      def self.emit_blake3_compress(emit)
        _get_compress_ops.each { |op| emit.call(op) }
      end

      # Emit BLAKE3 hash for a message up to 64 bytes.
      # Stack on entry: [..., message(<=64 BE)]
      # Stack on exit:  [..., hash(32 BE)]
      # Net depth: 0
      #
      # @param emit [Proc] callback that receives a StackOp
      def self.emit_blake3_hash(emit)
        em = Emitter.new(1)

        # Capture block_len = message length as a 4-byte little-endian value on
        # the alt stack (consumed as v[14] inside the compression).
        em.oc("OP_SIZE"); em.depth += 1 # [message, len]
        em.oc("OP_DUP"); em.depth += 1  # [message, len, len]
        em.push_i(4)
        em.bin_op("OP_NUM2BIN")         # [message, len, blockLenLE(4)]
        em.to_alt                        # [message, len]; alt: [blockLenLE]

        # Pad message to 64 bytes
        em.push_i(64)
        em.swap
        em.bin_op("OP_SUB")     # [message, 64-len]
        em.push_i(0)
        em.swap
        em.bin_op("OP_NUM2BIN") # [message, zeros]
        em.bin_op("OP_CAT")     # [paddedMessage(64)]

        # Push IV as 32-byte little-endian chaining value
        iv_bytes = "\x00".b * 32
        8.times do |i|
          le = _u32_to_le(BLAKE3_IV[i])
          iv_bytes[i * 4, 4] = le
        end
        em.push_b(iv_bytes)
        em.swap # [IV(32 LE), paddedMessage(64 LE)]

        # Splice compression ops; block_len taken from the alt stack.
        compress_ops = _generate_compress_ops(block_len_from_alt: true)
        compress_ops.each { |op| em.e_raw(op) }
        em.depth = 1

        em.assert_depth(1, "blake3Hash final")
        em.ops.each { |op| emit.call(op) }
      end
    end
  end
end
