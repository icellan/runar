# frozen_string_literal: true

# SHA-256 compression codegen for Bitcoin Script.
#
# emit_sha256_compress: [state(32), block(64)] -> [newState(32)]
#
# Optimized architecture (inspired by twostack/tstokenlib):
#   - All 32-bit words stored as **4-byte little-endian** during computation.
#     LE->num conversion is just push(0x00)+CAT+BIN2NUM (3 ops) vs 15 ops for BE.
#   - Bitwise ops (AND, OR, XOR, INVERT) are endian-agnostic on equal-length arrays.
#   - ROTR uses OP_LSHIFT/OP_RSHIFT on BE byte arrays (native BSV shifts).
#   - Batched addN for T1 (5 addends) converts all to numeric once, adds, converts back.
#   - BE->LE conversion only at input unpack; LE->BE only at output pack.
#
# Stack layout during rounds:
#   [W0..W63, a, b, c, d, e, f, g, h]  (all LE 4-byte values)
#   a at depth 0 (TOS), h at depth 7. W[t] at depth 8+(63-t).
#   Alt: [initState(32 bytes BE)]
#
# Direct port of compilers/python/runar_compiler/codegen/sha256.py

module RunarCompiler
  module Codegen
    module SHA256Codegen
      # -----------------------------------------------------------------
      # SHA-256 round constants
      # -----------------------------------------------------------------

      K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
      ].freeze

      # @param n [Integer] uint32
      # @return [String] 4-byte little-endian binary string
      def self._u32_to_le(n)
        [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff].pack("C*")
      end
      private_class_method :_u32_to_le

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

      # =================================================================
      # Emitter with depth tracking
      # =================================================================

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
          _e(SHA256Codegen.send(:_make_stack_op, op: "opcode", code: code))
        end

        def push_i(v)
          _e(SHA256Codegen.send(:_make_stack_op, op: "push",
            value: SHA256Codegen.send(:_make_push_value, kind: "bigint", big_int: v)))
          @depth += 1
        end

        def push_b(v)
          _e(SHA256Codegen.send(:_make_stack_op, op: "push",
            value: SHA256Codegen.send(:_make_push_value, kind: "bytes", bytes_val: v)))
          @depth += 1
        end

        def dup
          _e(SHA256Codegen.send(:_make_stack_op, op: "dup"))
          @depth += 1
        end

        def drop
          _e(SHA256Codegen.send(:_make_stack_op, op: "drop"))
          @depth -= 1
        end

        def swap
          _e(SHA256Codegen.send(:_make_stack_op, op: "swap"))
        end

        def over
          _e(SHA256Codegen.send(:_make_stack_op, op: "over"))
          @depth += 1
        end

        def nip
          _e(SHA256Codegen.send(:_make_stack_op, op: "nip"))
          @depth -= 1
        end

        def rot
          _e(SHA256Codegen.send(:_make_stack_op, op: "rot"))
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
          _e(SHA256Codegen.send(:_make_stack_op, op: "pick", depth: d))
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
          _e(SHA256Codegen.send(:_make_stack_op, op: "roll", depth: d))
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
              "SHA256 codegen: #{msg}. Expected depth #{expected}, got #{@depth}"
          end
        end

        # --- Byte reversal (only for BE<->LE conversion at boundaries) ---

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

        def shr_be(n)
          push_i(n)
          bin_op("OP_RSHIFT")
        end

        # --- SHA-256 sigma functions ---

        def big_sigma0
          reverse_bytes4
          self.dup; self.dup
          rotr_be(2); swap; rotr_be(13)
          bin_op("OP_XOR")
          swap; rotr_be(22)
          bin_op("OP_XOR")
          reverse_bytes4
        end

        def big_sigma1
          reverse_bytes4
          self.dup; self.dup
          rotr_be(6); swap; rotr_be(11)
          bin_op("OP_XOR")
          swap; rotr_be(25)
          bin_op("OP_XOR")
          reverse_bytes4
        end

        def small_sigma0
          reverse_bytes4
          self.dup; self.dup
          rotr_be(7); swap; rotr_be(18)
          bin_op("OP_XOR")
          swap; shr_be(3)
          bin_op("OP_XOR")
          reverse_bytes4
        end

        def small_sigma1
          reverse_bytes4
          self.dup; self.dup
          rotr_be(17); swap; rotr_be(19)
          bin_op("OP_XOR")
          swap; shr_be(10)
          bin_op("OP_XOR")
          reverse_bytes4
        end

        def ch
          rot
          self.dup
          uni_op("OP_INVERT")
          rot
          bin_op("OP_AND")
          to_alt
          bin_op("OP_AND")
          from_alt
          bin_op("OP_XOR")
        end

        def maj
          to_alt
          dup2
          bin_op("OP_AND")
          to_alt
          bin_op("OP_XOR")
          from_alt
          swap
          from_alt
          bin_op("OP_AND")
          bin_op("OP_OR")
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

        def be_words_to_le_reversed8
          (7).downto(0) do |i|
            roll(i)
            reverse_bytes4
            to_alt
          end
          8.times do
            from_alt
          end
        end
      end

      # =================================================================
      # Reusable compress ops generator
      # =================================================================

      # Emit one compression round.
      def self._emit_round(em, t)
        # --- T1 = S1(e) + Ch(e,f,g) + h + K[t] + W[t] ---
        em.pick(4)
        em.big_sigma1

        em.pick(5); em.pick(7); em.pick(9)
        em.ch

        em.pick(9)
        em.push_b(_u32_to_le(K[t]))
        em.pick(75 - t)

        em.add_n(5)

        # --- T2 = S0(a) + Maj(a,b,c) ---
        em.dup; em.to_alt

        em.pick(1)
        em.big_sigma0

        em.pick(2); em.pick(4); em.pick(6)
        em.maj
        em.add32

        # --- Register update ---
        em.from_alt

        em.swap
        em.add32

        em.swap
        em.roll(5)
        em.add32

        em.roll(8); em.drop

        # Rotate: [ne,na,a,b,c,e,f,g] -> [na,a,b,c,ne,e,f,g]
        em.swap; em.roll(4); em.roll(4); em.roll(4); em.roll(3)
      end
      private_class_method :_emit_round

      # guard_operands (F-114): abort unless the block is exactly 64 bytes and
      # the state exactly 32 bytes. Without it a mis-sized operand (a 5-byte or
      # short last word) is truncated / zero-extended by the 32-bit word
      # arithmetic and yields the same digest as a different 64-byte block.
      # sha256Finalize builds its blocks itself and checks its state once at
      # entry, so its compressions run unguarded.
      def self._generate_compress_ops(guard_operands)
        em = Emitter.new(2)

        if guard_operands
          # [state, block] -> abort unless len(block) == 64
          em.oc("OP_SIZE"); em.depth += 1
          em.push_i(64)
          em.oc("OP_EQUALVERIFY"); em.depth -= 2
        end

        # Phase 1: Save init state to alt, unpack block into 16 LE words
        em.swap
        if guard_operands
          # [block, state] -> abort unless len(state) == 32
          em.oc("OP_SIZE"); em.depth += 1
          em.push_i(32)
          em.oc("OP_EQUALVERIFY"); em.depth -= 2
        end
        em.dup; em.to_alt
        em.to_alt
        em.assert_depth(1, "compress: after state save")

        15.times { em.split4 }
        em.assert_depth(16, "compress: after block unpack")
        em.be_words_to_le(16)
        em.assert_depth(16, "compress: after block LE convert")

        # Phase 2: W expansion
        (16...64).each do
          em.over; em.small_sigma1
          em.pick(6 + 1)
          em.pick(14 + 2); em.small_sigma0
          em.pick(15 + 3)
          em.add_n(4)
        end
        em.assert_depth(64, "compress: after W expansion")

        # Phase 3: Unpack state into 8 LE working vars
        em.from_alt
        7.times { em.split4 }
        em.assert_depth(72, "compress: after state unpack")
        em.be_words_to_le_reversed8
        em.assert_depth(72, "compress: after state LE convert")

        # Phase 4: 64 compression rounds
        64.times do |t|
          d0 = em.depth
          _emit_round(em, t)
          em.assert_depth(d0, "compress: after round #{t}")
        end

        # Phase 5: Add initial state, pack result
        em.from_alt
        em.assert_depth(73, "compress: before final add")

        7.times { em.split4 }
        em.be_words_to_le_reversed8
        em.assert_depth(80, "compress: after init unpack")

        8.times do |i|
          em.roll(8 - i)
          em.add32
          em.to_alt
        end
        em.assert_depth(64, "compress: after final add")

        em.from_alt
        em.reverse_bytes4
        (1...8).each do
          em.from_alt
          em.reverse_bytes4
          em.swap
          em.bin_op("OP_CAT")
        end
        em.assert_depth(65, "compress: after pack")

        64.times do
          em.swap; em.drop
        end
        em.assert_depth(1, "compress: final")

        em.ops
      end
      private_class_method :_generate_compress_ops

      # Cache the ops since they're identical every time
      @compress_ops_cache = nil
      @guarded_compress_ops_cache = nil

      def self._get_compress_ops
        @compress_ops_cache ||= _generate_compress_ops(false)
      end
      private_class_method :_get_compress_ops

      def self._get_guarded_compress_ops
        @guarded_compress_ops_cache ||= _generate_compress_ops(true)
      end
      private_class_method :_get_guarded_compress_ops

      # =================================================================
      # Public entry points
      # =================================================================

      # Emit SHA-256 compression in Bitcoin Script.
      # Stack on entry: [..., state(32 BE), block(64 BE)]
      # Stack on exit:  [..., newState(32 BE)]
      # Aborts unless the state is 32 bytes and the block 64 bytes (F-114).
      #
      # @param emit [Proc] callback that receives a StackOp
      def self.emit_sha256_compress(emit)
        _get_guarded_compress_ops.each { |op| emit.call(op) }
      end

      # Emit SHA-256 finalization in Bitcoin Script.
      # Stack on entry: [..., state(32 BE), remaining(var len BE), msgBitLen(bigint)]
      # Stack on exit:  [..., hash(32 BE)]
      #
      # @param emit [Proc] callback that receives a StackOp
      def self.emit_sha256_finalize(emit)
        em = Emitter.new(3) # state + remaining + msgBitLen

        # ---- Step 1: Convert msgBitLen to 8-byte BE ----
        em.push_i(9)
        em.bin_op("OP_NUM2BIN")    # 9-byte LE
        em.push_i(8)
        em.split                    # [8-byte LE, sign byte]
        em.drop                     # [8-byte LE]
        # Reverse 8 bytes to BE: split(4), reverse each half, cat
        em.push_i(4); em.split     # [lo4_LE, hi4_LE]
        em.reverse_bytes4           # [lo4_LE, hi4_rev]
        em.swap
        em.reverse_bytes4           # [hi4_rev, lo4_rev]
        em.bin_op("OP_CAT")        # [bitLenBE(8)]
        em.to_alt                   # save bitLenBE to alt
        em.assert_depth(2, "finalize: after bitLen conversion")

        # F-114: abort unless len(state) == 32 (remaining is variable-length; a
        # remaining past 119 bytes already aborts on the negative OP_NUM2BIN below).
        em.swap                     # [remaining, state]
        em.oc("OP_SIZE"); em.depth += 1
        em.push_i(32)
        em.oc("OP_EQUALVERIFY"); em.depth -= 2
        em.swap                     # [state, remaining]

        # ---- Step 2: Pad remaining ----
        em.push_b("\x80".b)
        em.bin_op("OP_CAT")        # [state, remaining||0x80]

        # Get padded length
        em.oc("OP_SIZE"); em.depth += 1 # [state, padded, paddedLen]

        # Branch: 1 block (paddedLen <= 56) or 2 blocks (paddedLen > 56)
        em.dup
        em.push_i(57)
        em.bin_op("OP_LESSTHAN")   # paddedLen < 57?

        em.oc("OP_IF"); em.depth -= 1 # consume flag
        # ---- 1-block path: pad to 56 bytes ----
        em.push_i(56)
        em.swap
        em.bin_op("OP_SUB")        # zeroCount = 56 - paddedLen
        em.push_i(0)
        em.swap
        em.bin_op("OP_NUM2BIN")    # zero bytes
        em.bin_op("OP_CAT")        # [state, padded(56 bytes)]
        em.from_alt                 # bitLenBE from alt
        em.bin_op("OP_CAT")        # [state, block1(64 bytes)]
        # Splice sha256Compress ops
        compress_ops = _get_compress_ops
        compress_ops.each { |op| em.e_raw(op) }
        em.depth = 1 # after compress: 1 result

        em.oc("OP_ELSE")
        em.depth = 3 # reset to branch entry: [state, padded, paddedLen]

        # ---- 2-block path: pad to 120 bytes ----
        em.push_i(120)
        em.swap
        em.bin_op("OP_SUB")        # zeroCount = 120 - paddedLen
        em.push_i(0)
        em.swap
        em.bin_op("OP_NUM2BIN")    # zero bytes
        em.bin_op("OP_CAT")        # [state, padded(120 bytes)]
        em.from_alt                 # bitLenBE from alt
        em.bin_op("OP_CAT")        # [state, fullPadded(128 bytes)]

        # Split into 2 blocks
        em.push_i(64)
        em.split                    # [state, block1(64), block2(64)]
        em.to_alt                   # save block2

        # First compress: [state, block1]
        compress_ops.each { |op| em.e_raw(op) }
        em.depth = 1 # after first compress: [midState]

        # Second compress: [midState, block2]
        em.from_alt                 # [midState, block2]
        compress_ops.each { |op| em.e_raw(op) }
        em.depth = 1 # after second compress: [result]

        em.oc("OP_ENDIF")
        # Both paths leave 1 item (result) on stack
        em.assert_depth(1, "finalize: final")

        em.ops.each { |op| emit.call(op) }
      end
    end
  end
end
