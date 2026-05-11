# frozen_string_literal: true

# SLH-DSA (FIPS 205) Bitcoin Script codegen for the Runar Ruby stack lowerer.
#
# Splice into LoweringContext in stack.rb. All helpers self-contained.
# Entry: emit_verify_slh_dsa() -> calls emit_verify_slh_dsa().
#
# Main-stack convention: pkSeedPad (64 bytes) tracked as '_pkSeedPad' on the
# main stack, accessed via PICK at known depth. Never placed on alt.
#
# Runtime ADRS: treeAddr (8-byte BE) and keypair (4-byte BE) are tracked on
# the main stack as 'treeAddr8' and 'keypair4', threaded into rawBlocks.
# ADRS is built at runtime using emit_build_adrs / emit_build_adrs18 helpers.
#
# Direct port of compilers/python/runar_compiler/codegen/slh_dsa.py

module RunarCompiler
  module Codegen
    module SLHDSA
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

      # =================================================================
      # 1. Parameter Sets (FIPS 205 Table 1, SHA2)
      # =================================================================

      class SLHCodegenParams
        attr_reader :n, :h, :d, :hp, :a, :k, :w, :len_, :len1, :len2

        def initialize(n:, h:, d:, hp:, a:, k:, w:, len_:, len1:, len2:)
          @n = n
          @h = h
          @d = d
          @hp = hp
          @a = a
          @k = k
          @w = w
          @len_ = len_
          @len1 = len1
          @len2 = len2
        end
      end

      def self._slh_mk(n, h, d, a, k)
        len1 = 2 * n
        len2 = (Math.log2(len1 * 15) / Math.log2(16)).floor + 1
        SLHCodegenParams.new(
          n: n, h: h, d: d, hp: h / d, a: a, k: k, w: 16,
          len_: len1 + len2, len1: len1, len2: len2
        )
      end
      private_class_method :_slh_mk

      SLH_PARAMS = {
        "SHA2_128s" => _slh_mk(16, 63, 7, 12, 14),
        "SHA2_128f" => _slh_mk(16, 66, 22, 6, 33),
        "SHA2_192s" => _slh_mk(24, 63, 7, 14, 17),
        "SHA2_192f" => _slh_mk(24, 66, 22, 8, 33),
        "SHA2_256s" => _slh_mk(32, 64, 8, 14, 22),
        "SHA2_256f" => _slh_mk(32, 68, 17, 8, 35),
      }.freeze

      # =================================================================
      # 1b. Fixed-length byte reversal helper
      # =================================================================

      def self._emit_reverse_n(n)
        return [] if n <= 1
        ops = []
        # Phase 1: split into n individual bytes
        (n - 1).times do
          ops << _make_stack_op(op: "push", value: _big_int_push(1))
          ops << _make_stack_op(op: "opcode", code: "OP_SPLIT")
        end
        # Phase 2: concatenate in reverse order
        (n - 1).times do
          ops << _make_stack_op(op: "swap")
          ops << _make_stack_op(op: "opcode", code: "OP_CAT")
        end
        ops
      end
      private_class_method :_emit_reverse_n

      # =================================================================
      # 1c. Collect ops into array helper
      # =================================================================

      def self._collect_ops(&blk)
        ops = []
        blk.call(->(op) { ops << op })
        ops
      end
      private_class_method :_collect_ops

      # =================================================================
      # 2. Compressed ADRS (22 bytes)
      # =================================================================
      # [0] layer  [1..8] tree  [9] type  [10..13] keypair
      # [14..17] chain/treeHeight  [18..21] hash/treeIndex

      SLH_WOTS_HASH = 0
      SLH_WOTS_PK = 1
      SLH_TREE = 2
      SLH_FORS_TREE = 3
      SLH_FORS_ROOTS = 4

      def self._slh_adrs(layer: 0, tree: 0, adrs_typ: 0, keypair: 0, chain: 0, hash_: 0)
        c = "\x00".b * 22
        c.setbyte(0, layer & 0xFF)
        tr = tree
        8.times do |i|
          c.setbyte(1 + 7 - i, (tr >> (8 * i)) & 0xFF)
        end
        c.setbyte(9, adrs_typ & 0xFF)
        kp = keypair
        c.setbyte(10, (kp >> 24) & 0xFF)
        c.setbyte(11, (kp >> 16) & 0xFF)
        c.setbyte(12, (kp >> 8) & 0xFF)
        c.setbyte(13, kp & 0xFF)
        ch = chain
        c.setbyte(14, (ch >> 24) & 0xFF)
        c.setbyte(15, (ch >> 16) & 0xFF)
        c.setbyte(16, (ch >> 8) & 0xFF)
        c.setbyte(17, ch & 0xFF)
        ha = hash_
        c.setbyte(18, (ha >> 24) & 0xFF)
        c.setbyte(19, (ha >> 16) & 0xFF)
        c.setbyte(20, (ha >> 8) & 0xFF)
        c.setbyte(21, ha & 0xFF)
        c
      end
      private_class_method :_slh_adrs

      def self._slh_adrs18(layer: 0, tree: 0, adrs_typ: 0, keypair: 0, chain: 0)
        full = _slh_adrs(layer: layer, tree: tree, adrs_typ: adrs_typ,
                         keypair: keypair, chain: chain, hash_: 0)
        full[0, 18]
      end
      private_class_method :_slh_adrs18

      # =================================================================
      # 2b. Runtime ADRS builders
      # =================================================================

      def self._int4be(v)
        [(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF].pack("C*")
      end
      private_class_method :_int4be

      def self._emit_build_adrs18(emit, layer, adrs_type, chain, ta8_depth, kp4_depth)
        # Push layer byte (1B)
        emit.call(_make_stack_op(op: "push", value: _make_push_value(kind: "bytes", bytes_: [layer & 0xFF].pack("C"))))
        # PICK ta8: depth = ta8_depth + 1
        emit.call(_make_stack_op(op: "push", value: _big_int_push(ta8_depth + 1)))
        emit.call(_make_stack_op(op: "pick", depth: ta8_depth + 1))
        emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))

        # Push type byte (1B)
        emit.call(_make_stack_op(op: "push", value: _make_push_value(kind: "bytes", bytes_: [adrs_type & 0xFF].pack("C"))))
        emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))

        # keypair4
        if kp4_depth < 0
          emit.call(_make_stack_op(op: "push", value: _make_push_value(kind: "bytes", bytes_: "\x00\x00\x00\x00".b)))
        else
          emit.call(_make_stack_op(op: "push", value: _big_int_push(kp4_depth + 1)))
          emit.call(_make_stack_op(op: "pick", depth: kp4_depth + 1))
        end
        emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))

        # Push chain (4B BE)
        emit.call(_make_stack_op(op: "push", value: _make_push_value(kind: "bytes", bytes_: _int4be(chain))))
        emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
      end
      private_class_method :_emit_build_adrs18

      def self._emit_build_adrs(emit, layer, adrs_type, chain, ta8_depth, kp4_depth, hash_mode)
        if hash_mode == "stack"
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          adj_kp4 = kp4_depth >= 0 ? kp4_depth - 1 : kp4_depth
          _emit_build_adrs18(emit, layer, adrs_type, chain, ta8_depth - 1, adj_kp4)
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
        else
          # "zero"
          _emit_build_adrs18(emit, layer, adrs_type, chain, ta8_depth, kp4_depth)
          emit.call(_make_stack_op(op: "push", value: _make_push_value(kind: "bytes", bytes_: "\x00\x00\x00\x00".b)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
        end
      end
      private_class_method :_emit_build_adrs

      # =================================================================
      # 3. SLH Stack Tracker
      # =================================================================

      class SLHTracker
        attr_accessor :nm

        # @param init [Array<String>] initial stack names (bottom to top)
        # @param emit [Proc] callback for emitting StackOps
        def initialize(init, emit)
          @nm = init.dup
          @e = emit
        end

        def depth
          @nm.length
        end

        def find_depth(name)
          (@nm.length - 1).downto(0) do |i|
            return @nm.length - 1 - i if @nm[i] == name
          end
          raise RuntimeError, "SLHTracker: '#{name}' not on stack #{@nm}"
        end

        def has(name)
          @nm.include?(name)
        end

        def push_bytes(n, v)
          @e.call(SLHDSA.send(:_make_stack_op, op: "push",
            value: SLHDSA.send(:_make_push_value, kind: "bytes", bytes_: v)))
          @nm << n
        end

        def push_int(n, v)
          @e.call(SLHDSA.send(:_make_stack_op, op: "push", value: SLHDSA.send(:_big_int_push, v)))
          @nm << n
        end

        def push_empty(n)
          @e.call(SLHDSA.send(:_make_stack_op, op: "opcode", code: "OP_0"))
          @nm << n
        end

        def dup(n)
          @e.call(SLHDSA.send(:_make_stack_op, op: "dup"))
          @nm << n
        end

        def drop
          @e.call(SLHDSA.send(:_make_stack_op, op: "drop"))
          @nm.pop if @nm.any?
        end

        def nip
          @e.call(SLHDSA.send(:_make_stack_op, op: "nip"))
          l = @nm.length
          @nm[l - 2..l - 1] = [@nm[l - 1]] if l >= 2
        end

        def over(n)
          @e.call(SLHDSA.send(:_make_stack_op, op: "over"))
          @nm << n
        end

        def swap
          @e.call(SLHDSA.send(:_make_stack_op, op: "swap"))
          l = @nm.length
          if l >= 2
            @nm[l - 1], @nm[l - 2] = @nm[l - 2], @nm[l - 1]
          end
        end

        def rot
          @e.call(SLHDSA.send(:_make_stack_op, op: "rot"))
          l = @nm.length
          if l >= 3
            r = @nm[l - 3]
            @nm.delete_at(l - 3)
            @nm << r
          end
        end

        def op(code)
          @e.call(SLHDSA.send(:_make_stack_op, op: "opcode", code: code))
        end

        def roll(d)
          return if d == 0
          if d == 1
            self.swap
            return
          end
          if d == 2
            self.rot
            return
          end
          @e.call(SLHDSA.send(:_make_stack_op, op: "push", value: SLHDSA.send(:_big_int_push, d)))
          @nm << ""
          @e.call(SLHDSA.send(:_make_stack_op, op: "opcode", code: "OP_ROLL"))
          @nm.pop # pop the push
          idx = @nm.length - 1 - d
          r = @nm[idx]
          @nm.delete_at(idx)
          @nm << r
        end

        def pick(d, n)
          if d == 0
            self.dup(n)
            return
          end
          if d == 1
            self.over(n)
            return
          end
          @e.call(SLHDSA.send(:_make_stack_op, op: "push", value: SLHDSA.send(:_big_int_push, d)))
          @nm << ""
          @e.call(SLHDSA.send(:_make_stack_op, op: "opcode", code: "OP_PICK"))
          @nm.pop # pop the push
          @nm << n
        end

        def to_top(name)
          roll(find_depth(name))
        end

        def copy_to_top(name, n)
          pick(find_depth(name), n)
        end

        def to_alt
          op("OP_TOALTSTACK")
          @nm.pop if @nm.any?
        end

        def from_alt(n)
          op("OP_FROMALTSTACK")
          @nm << n
        end

        def split_op(left, right)
          op("OP_SPLIT")
          @nm.pop if @nm.length >= 1
          @nm.pop if @nm.length >= 1
          @nm << left
          @nm << right
        end

        def cat(n)
          op("OP_CAT")
          @nm[-2..] = [] if @nm.length >= 2
          @nm << n
        end

        def sha256(n)
          op("OP_SHA256")
          @nm.pop if @nm.length >= 1
          @nm << n
        end

        def equal(n)
          op("OP_EQUAL")
          @nm[-2..] = [] if @nm.length >= 2
          @nm << n
        end

        def rename(n)
          @nm[-1] = n if @nm.any?
        end

        def raw_block(consume, produce, &blk)
          consume.reverse_each do
            @nm.pop if @nm.any?
          end
          blk.call(@e)
          @nm << produce if produce && !produce.empty?
        end
      end

      # =================================================================
      # 4. Tweakable Hash T(pkSeed, ADRS, M)
      # =================================================================

      def self._emit_slh_t(t, n, adrs, msg, result)
        t.to_top(adrs)
        t.to_top(msg)
        t.cat("_am")
        t.copy_to_top("_pkSeedPad", "_psp")
        t.swap
        t.cat("_pre")
        t.sha256("_h32")
        if n < 32
          t.push_int("", n)
          t.split_op(result, "_tr")
          t.drop
        else
          t.rename(result)
        end
      end
      private_class_method :_emit_slh_t

      def self._emit_slh_t_raw(e, n, pk_seed_pad_depth)
        e.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
        pick_depth = pk_seed_pad_depth - 1
        e.call(_make_stack_op(op: "push", value: _big_int_push(pick_depth)))
        e.call(_make_stack_op(op: "pick", depth: pick_depth))
        e.call(_make_stack_op(op: "swap"))
        e.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
        e.call(_make_stack_op(op: "opcode", code: "OP_SHA256"))
        if n < 32
          e.call(_make_stack_op(op: "push", value: _big_int_push(n)))
          e.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(_make_stack_op(op: "drop"))
        end
      end
      private_class_method :_emit_slh_t_raw

      # =================================================================
      # 5. WOTS+ One Chain (tweakable hash, dynamic hashAddress)
      # =================================================================

      def self._slh_chain_step_then(n, pk_seed_pad_depth)
        ops = []
        # DUP hashAddr before consuming it in ADRS construction
        ops << _make_stack_op(op: "dup")
        # Convert copy to 4-byte big-endian
        ops << _make_stack_op(op: "push", value: _big_int_push(4))
        ops << _make_stack_op(op: "opcode", code: "OP_NUM2BIN")
        ops.concat(_emit_reverse_n(4))

        # Get prefix from alt: FROMALT; DUP; TOALT
        ops << _make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")
        ops << _make_stack_op(op: "opcode", code: "OP_DUP")
        ops << _make_stack_op(op: "opcode", code: "OP_TOALTSTACK")
        ops << _make_stack_op(op: "swap")
        ops << _make_stack_op(op: "opcode", code: "OP_CAT")

        # Move sigElem to top: ROLL 3
        ops << _make_stack_op(op: "push", value: _big_int_push(3))
        ops << _make_stack_op(op: "roll", depth: 3)
        ops << _make_stack_op(op: "opcode", code: "OP_CAT")

        # pkSeedPad via PICK
        ops << _make_stack_op(op: "push", value: _big_int_push(pk_seed_pad_depth))
        ops << _make_stack_op(op: "pick", depth: pk_seed_pad_depth)
        ops << _make_stack_op(op: "swap")
        ops << _make_stack_op(op: "opcode", code: "OP_CAT")
        ops << _make_stack_op(op: "opcode", code: "OP_SHA256")
        if n < 32
          ops << _make_stack_op(op: "push", value: _big_int_push(n))
          ops << _make_stack_op(op: "opcode", code: "OP_SPLIT")
          ops << _make_stack_op(op: "drop")
        end
        # Rearrange
        ops << _make_stack_op(op: "rot")
        ops << _make_stack_op(op: "opcode", code: "OP_1SUB")
        ops << _make_stack_op(op: "rot")
        ops << _make_stack_op(op: "opcode", code: "OP_1ADD")
        ops
      end
      private_class_method :_slh_chain_step_then

      def self._emit_slh_one_chain(emit, n, layer, chain_idx, pk_seed_pad_depth, ta8_depth, kp4_depth)
        # steps = 15 - digit
        emit.call(_make_stack_op(op: "push", value: _big_int_push(15)))
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_SUB"))

        # Save steps_copy, endptAcc, csum to alt
        emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

        # Split n-byte sig element
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(n)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
        emit.call(_make_stack_op(op: "swap"))

        # Compute hashAddr = 15 - steps (= digit)
        emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(15)))
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_SUB"))

        psp_d_chain = pk_seed_pad_depth - 1
        ta8_d_chain = ta8_depth - 1
        kp4_d_chain = kp4_depth - 1

        # Build 18-byte ADRS prefix
        _emit_build_adrs18(emit, layer, SLH_WOTS_HASH, chain_idx, ta8_d_chain, kp4_d_chain)
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

        # Build then-ops for chain step
        then_ops = _slh_chain_step_then(n, psp_d_chain)

        # 15 unrolled conditional hash iterations
        15.times do
          emit.call(_make_stack_op(op: "over"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_0NOTEQUAL"))
          emit.call(_make_stack_op(op: "if", then_ops: then_ops))
        end

        emit.call(_make_stack_op(op: "drop"))
        emit.call(_make_stack_op(op: "drop"))

        # Drop prefix from alt
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
        emit.call(_make_stack_op(op: "drop"))

        # Restore from alt (LIFO)
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # sigRest
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # csum
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # endptAcc
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # steps_copy

        # csum += steps_copy
        emit.call(_make_stack_op(op: "rot"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_ADD"))

        # Cat endpoint to endptAcc
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(3)))
        emit.call(_make_stack_op(op: "roll", depth: 3))
        emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
      end
      private_class_method :_emit_slh_one_chain

      # =================================================================
      # Full WOTS+ Processing (all len chains)
      # =================================================================

      def self._emit_slh_wots_all(emit, p, layer)
        n = p.n
        len1 = p.len1
        len2 = p.len2

        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(0)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_0"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(3)))
        emit.call(_make_stack_op(op: "roll", depth: 3))

        n.times do |byte_idx|
          if byte_idx < n - 1
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
          # High/low nibbles
          emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
          emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
          emit.call(_make_stack_op(op: "swap"))
          emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))

          if byte_idx < n - 1
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # loNib -> alt
            emit.call(_make_stack_op(op: "swap"))
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # msgRest -> alt
          else
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # loNib -> alt
          end

          # First chain call (hiNib)
          _emit_slh_one_chain(emit, n, layer, byte_idx * 2, 6, 5, 4)

          if byte_idx < n - 1
            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # msgRest
            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # loNib
            emit.call(_make_stack_op(op: "swap"))
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))   # msgRest -> alt
          else
            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # loNib
          end

          # Second chain call (loNib)
          _emit_slh_one_chain(emit, n, layer, byte_idx * 2 + 1, 6, 5, 4)

          if byte_idx < n - 1
            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # msgRest
          end
        end

        # Checksum digits
        emit.call(_make_stack_op(op: "swap"))

        emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

        emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

        emit.call(_make_stack_op(op: "push", value: _big_int_push(256)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
        emit.call(_make_stack_op(op: "push", value: _big_int_push(16)))
        emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

        len2.times do |ci|
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))  # endptAcc -> alt
          emit.call(_make_stack_op(op: "push", value: _big_int_push(0)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # endptAcc
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # digit

          _emit_slh_one_chain(emit, n, layer, len1 + ci, 6, 5, 4)

          emit.call(_make_stack_op(op: "swap"))
          emit.call(_make_stack_op(op: "drop"))
        end

        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "drop"))

        # Compress -> wotsPk
        _emit_build_adrs(emit, layer, SLH_WOTS_PK, 0, 2, -1, "zero")
        emit.call(_make_stack_op(op: "swap"))
        _emit_slh_t_raw(emit, n, 4)
      end
      private_class_method :_emit_slh_wots_all

      # =================================================================
      # 6. Merkle Auth Path Verification
      # =================================================================

      def self._emit_slh_merkle(emit, p, layer)
        n = p.n
        hp = p.hp

        emit.call(_make_stack_op(op: "push", value: _big_int_push(2)))
        emit.call(_make_stack_op(op: "roll", depth: 2))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

        hp.times do |j|
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # node -> alt
          emit.call(_make_stack_op(op: "push", value: _big_int_push(n)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
          emit.call(_make_stack_op(op: "swap"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # node

          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

          if j > 0
            emit.call(_make_stack_op(op: "push", value: _big_int_push(1 << j)))
            emit.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
          end
          emit.call(_make_stack_op(op: "push", value: _big_int_push(2)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))

          mk_tweak_ops = _collect_ops do |e|
            e.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
            e.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
            e.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
            if j + 1 > 0
              e.call(_make_stack_op(op: "push", value: _big_int_push(1 << (j + 1))))
              e.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
            end
            e.call(_make_stack_op(op: "push", value: _big_int_push(4)))
            e.call(_make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
            _emit_reverse_n(4).each { |op_| e.call(op_) }
            _emit_build_adrs(e, layer, SLH_TREE, j + 1, 4, -1, "stack")
            e.call(_make_stack_op(op: "swap"))
            _emit_slh_t_raw(e, n, 5)
          end

          then_branch = [_make_stack_op(op: "opcode", code: "OP_CAT")] + mk_tweak_ops
          else_branch = [_make_stack_op(op: "swap"), _make_stack_op(op: "opcode", code: "OP_CAT")] + mk_tweak_ops

          emit.call(_make_stack_op(op: "if", then_ops: then_branch, else_: else_branch))
        end

        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
        emit.call(_make_stack_op(op: "drop"))
        emit.call(_make_stack_op(op: "swap"))
        emit.call(_make_stack_op(op: "drop"))
      end
      private_class_method :_emit_slh_merkle

      # =================================================================
      # 7. FORS Verification
      # =================================================================

      def self._emit_slh_fors(emit, p)
        n = p.n
        a = p.a
        k = p.k

        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # md -> alt
        emit.call(_make_stack_op(op: "opcode", code: "OP_0"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # rootAcc -> alt

        k.times do |i|
          # Get md
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # rootAcc
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # md
          emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))    # md back
          emit.call(_make_stack_op(op: "swap"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))    # rootAcc back

          # Extract idx
          bit_start = i * a
          byte_start = bit_start / 8
          bit_offset = bit_start % 8
          bits_in_first = [8 - bit_offset, a].min
          take = a <= bits_in_first ? 1 : 2

          if byte_start > 0
            emit.call(_make_stack_op(op: "push", value: _big_int_push(byte_start)))
            emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
            emit.call(_make_stack_op(op: "nip"))
          end
          emit.call(_make_stack_op(op: "push", value: _big_int_push(take)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
          emit.call(_make_stack_op(op: "drop"))
          if take > 1
            _emit_reverse_n(take).each { |op_| emit.call(op_) }
          end
          emit.call(_make_stack_op(op: "push", value: _big_int_push(0)))
          emit.call(_make_stack_op(op: "push", value: _big_int_push(1)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
          total_bits = take * 8
          right_shift = total_bits - bit_offset - a
          if right_shift > 0
            emit.call(_make_stack_op(op: "push", value: _big_int_push(1 << right_shift)))
            emit.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
          end
          emit.call(_make_stack_op(op: "push", value: _big_int_push(1 << a)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))

          # Save idx to alt
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

          # Split sk(n) from sigRem
          emit.call(_make_stack_op(op: "push", value: _big_int_push(n)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
          emit.call(_make_stack_op(op: "swap"))

          # Leaf hash
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

          if i > 0
            emit.call(_make_stack_op(op: "push", value: _big_int_push(i * (1 << a))))
            emit.call(_make_stack_op(op: "opcode", code: "OP_ADD"))
          end
          emit.call(_make_stack_op(op: "push", value: _big_int_push(4)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          _emit_reverse_n(4).each { |op_| emit.call(op_) }

          _emit_build_adrs(emit, 0, SLH_FORS_TREE, 0, 4, 3, "stack")
          emit.call(_make_stack_op(op: "swap"))
          _emit_slh_t_raw(emit, n, 5)

          # Auth path walk: a levels
          a.times do |j|
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # node -> alt
            emit.call(_make_stack_op(op: "push", value: _big_int_push(n)))
            emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
            emit.call(_make_stack_op(op: "swap"))
            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # node

            emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
            emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
            emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))

            if j > 0
              emit.call(_make_stack_op(op: "push", value: _big_int_push(1 << j)))
              emit.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
            end
            emit.call(_make_stack_op(op: "push", value: _big_int_push(2)))
            emit.call(_make_stack_op(op: "opcode", code: "OP_MOD"))

            # Capture i and j for the closure
            i_val = i
            j_val = j

            mk_fors_ops = _collect_ops do |e|
              e.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
              e.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
              e.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
              if j_val + 1 > 0
                e.call(_make_stack_op(op: "push", value: _big_int_push(1 << (j_val + 1))))
                e.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
              end
              base = i_val * (1 << (a - j_val - 1))
              if base > 0
                e.call(_make_stack_op(op: "push", value: _big_int_push(base)))
                e.call(_make_stack_op(op: "opcode", code: "OP_ADD"))
              end
              e.call(_make_stack_op(op: "push", value: _big_int_push(4)))
              e.call(_make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
              _emit_reverse_n(4).each { |op_| e.call(op_) }
              _emit_build_adrs(e, 0, SLH_FORS_TREE, j_val + 1, 4, 3, "stack")
              e.call(_make_stack_op(op: "swap"))
              _emit_slh_t_raw(e, n, 5)
            end

            then_branch = [_make_stack_op(op: "opcode", code: "OP_CAT")] + mk_fors_ops
            else_branch = [_make_stack_op(op: "swap"), _make_stack_op(op: "opcode", code: "OP_CAT")] + mk_fors_ops

            emit.call(_make_stack_op(op: "if", then_ops: then_branch, else_: else_branch))
          end

          # Drop idx from alt
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          emit.call(_make_stack_op(op: "drop"))

          # Append treeRoot to rootAcc
          emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # rootAcc
          emit.call(_make_stack_op(op: "swap"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK")) # rootAcc -> alt
        end

        # Drop empty sigRest
        emit.call(_make_stack_op(op: "drop"))

        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # rootAcc
        emit.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK")) # md
        emit.call(_make_stack_op(op: "drop"))

        # Compress
        _emit_build_adrs(emit, 0, SLH_FORS_ROOTS, 0, 2, 1, "zero")
        emit.call(_make_stack_op(op: "swap"))
        _emit_slh_t_raw(emit, n, 4)
      end
      private_class_method :_emit_slh_fors

      # =================================================================
      # 8. Hmsg -- Message Digest (SHA-256 MGF1)
      # =================================================================

      def self._emit_slh_hmsg(emit, n, out_len)
        emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
        emit.call(_make_stack_op(op: "opcode", code: "OP_SHA256"))

        blocks = (out_len + 31) / 32
        if blocks == 1
          emit.call(_make_stack_op(op: "push", value: _make_push_value(kind: "bytes", bytes_: "\x00\x00\x00\x00".b)))
          emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
          emit.call(_make_stack_op(op: "opcode", code: "OP_SHA256"))
          if out_len < 32
            emit.call(_make_stack_op(op: "push", value: _big_int_push(out_len)))
            emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
            emit.call(_make_stack_op(op: "drop"))
          end
        else
          emit.call(_make_stack_op(op: "opcode", code: "OP_0")) # resultAcc
          emit.call(_make_stack_op(op: "swap"))                   # resultAcc seed

          blocks.times do |ctr|
            if ctr < blocks - 1
              emit.call(_make_stack_op(op: "opcode", code: "OP_DUP"))
            end
            ctr_bytes = [
              (ctr >> 24) & 0xFF,
              (ctr >> 16) & 0xFF,
              (ctr >> 8) & 0xFF,
              ctr & 0xFF,
            ].pack("C*")
            emit.call(_make_stack_op(op: "push", value: _make_push_value(kind: "bytes", bytes_: ctr_bytes)))
            emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
            emit.call(_make_stack_op(op: "opcode", code: "OP_SHA256"))

            if ctr == blocks - 1
              rem = out_len - ctr * 32
              if rem < 32
                emit.call(_make_stack_op(op: "push", value: _big_int_push(rem)))
                emit.call(_make_stack_op(op: "opcode", code: "OP_SPLIT"))
                emit.call(_make_stack_op(op: "drop"))
              end
            end

            if ctr < blocks - 1
              emit.call(_make_stack_op(op: "rot"))
              emit.call(_make_stack_op(op: "swap"))
              emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
              emit.call(_make_stack_op(op: "swap"))
            else
              emit.call(_make_stack_op(op: "swap"))
              emit.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
            end
          end
        end
      end
      private_class_method :_emit_slh_hmsg

      # =================================================================
      # 9. Main Entry -- emit_verify_slh_dsa
      # =================================================================

      # Emit the full SLH-DSA verification script.
      #
      # Input:  msg(2) sig(1) pubkey(0)  [pubkey on top]
      # Output: boolean
      #
      # @param emit [Proc] callback that receives a StackOp
      # @param param_key [String] one of the 6 parameter set names
      def self.emit_verify_slh_dsa(emit, param_key)
        p = SLH_PARAMS[param_key]
        raise RuntimeError, "Unknown SLH-DSA params: #{param_key}" if p.nil?

        n = p.n
        d = p.d
        hp = p.hp
        k = p.k
        a = p.a
        ln = p.len_
        fors_sig_len = k * (1 + a) * n
        xmss_sig_len = (ln + hp) * n
        md_len = (k * a + 7) / 8
        tree_idx_len = (p.h - hp + 7) / 8
        leaf_idx_len = (hp + 7) / 8
        digest_len = md_len + tree_idx_len + leaf_idx_len

        t = SLHTracker.new(["msg", "sig", "pubkey"], emit)

        # ---- 1. Parse pubkey -> pkSeed, pkRoot ----
        t.to_top("pubkey")
        t.push_int("", n)
        t.split_op("pkSeed", "pkRoot")

        # Build pkSeedPad
        t.copy_to_top("pkSeed", "_psp")
        if 64 - n > 0
          t.push_bytes("", "\x00".b * (64 - n))
          t.cat("_pkSeedPad")
        else
          t.rename("_pkSeedPad")
        end

        # ---- 2. Parse R from sig ----
        t.to_top("sig")
        t.push_int("", n)
        t.split_op("R", "sigRest")

        # ---- 3. Compute Hmsg(R, pkSeed, pkRoot, msg) ----
        t.copy_to_top("R", "_R")
        t.copy_to_top("pkSeed", "_pks")
        t.copy_to_top("pkRoot", "_pkr")
        t.copy_to_top("msg", "_msg")
        t.raw_block(["_R", "_pks", "_pkr", "_msg"], "digest") do |e|
          _emit_slh_hmsg(e, n, digest_len)
        end

        # ---- 4. Extract md, treeIdx, leafIdx ----
        t.to_top("digest")
        t.push_int("", md_len)
        t.split_op("md", "_drest")

        t.to_top("_drest")
        t.push_int("", tree_idx_len)
        t.split_op("_treeBytes", "_leafBytes")

        # Convert _treeBytes -> treeIdx
        t.to_top("_treeBytes")
        t.raw_block(["_treeBytes"], "treeIdx") do |e|
          if tree_idx_len > 1
            _emit_reverse_n(tree_idx_len).each { |op_| e.call(op_) }
          end
          e.call(_make_stack_op(op: "push", value: _big_int_push(0)))
          e.call(_make_stack_op(op: "push", value: _big_int_push(1)))
          e.call(_make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          e.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(_make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
          modulus = 1 << (p.h - hp)
          e.call(_make_stack_op(op: "push", value: _make_push_value(kind: "bigint", big_int: modulus)))
          e.call(_make_stack_op(op: "opcode", code: "OP_MOD"))
        end

        # Convert _leafBytes -> leafIdx
        t.to_top("_leafBytes")
        t.raw_block(["_leafBytes"], "leafIdx") do |e|
          if leaf_idx_len > 1
            _emit_reverse_n(leaf_idx_len).each { |op_| e.call(op_) }
          end
          e.call(_make_stack_op(op: "push", value: _big_int_push(0)))
          e.call(_make_stack_op(op: "push", value: _big_int_push(1)))
          e.call(_make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          e.call(_make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(_make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
          e.call(_make_stack_op(op: "push", value: _big_int_push(1 << hp)))
          e.call(_make_stack_op(op: "opcode", code: "OP_MOD"))
        end

        # ---- 4b. Compute treeAddr8 and keypair4 ----
        tree_addr_proc = lambda do |e|
          e.call(_make_stack_op(op: "push", value: _big_int_push(8)))
          e.call(_make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          _emit_reverse_n(8).each { |op_| e.call(op_) }
        end

        keypair_addr_proc = lambda do |e|
          e.call(_make_stack_op(op: "push", value: _big_int_push(4)))
          e.call(_make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          _emit_reverse_n(4).each { |op_| e.call(op_) }
        end

        t.copy_to_top("treeIdx", "_ti8")
        t.raw_block(["_ti8"], "treeAddr8", &tree_addr_proc)

        t.copy_to_top("leafIdx", "_li4")
        t.raw_block(["_li4"], "keypair4", &keypair_addr_proc)

        # ---- 5. Parse FORS sig ----
        t.to_top("sigRest")
        t.push_int("", fors_sig_len)
        t.split_op("forsSig", "htSigRest")

        # ---- 6. FORS -> forsPk ----
        t.copy_to_top("_pkSeedPad", "_psp")
        t.copy_to_top("treeAddr8", "_ta")
        t.copy_to_top("keypair4", "_kp")
        t.to_top("forsSig")
        t.to_top("md")
        t.raw_block(["_psp", "_ta", "_kp", "forsSig", "md"], "forsPk") do |e|
          _emit_slh_fors(e, p)
          e.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          e.call(_make_stack_op(op: "drop"))
          e.call(_make_stack_op(op: "drop"))
          e.call(_make_stack_op(op: "drop"))
          e.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
        end

        # ---- 7. Hypertree: d layers ----
        d.times do |layer|
          t.to_top("htSigRest")
          t.push_int("", xmss_sig_len)
          t.split_op("xsig#{layer}", "htSigRest")

          t.to_top("xsig#{layer}")
          t.push_int("", ln * n)
          t.split_op("wsig#{layer}", "auth#{layer}")

          cur_msg = layer == 0 ? "forsPk" : "root#{layer - 1}"
          t.copy_to_top("_pkSeedPad", "_psp")
          t.copy_to_top("treeAddr8", "_ta")
          t.copy_to_top("keypair4", "_kp")
          wsig_name = "wsig#{layer}"
          t.to_top(wsig_name)
          t.to_top(cur_msg)
          wpk_name = "wpk#{layer}"

          layer_val = layer
          t.raw_block(["_psp", "_ta", "_kp", wsig_name, cur_msg], wpk_name) do |e|
            _emit_slh_wots_all(e, p, layer_val)
            e.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
            e.call(_make_stack_op(op: "drop"))
            e.call(_make_stack_op(op: "drop"))
            e.call(_make_stack_op(op: "drop"))
            e.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          end

          # Merkle
          t.copy_to_top("_pkSeedPad", "_psp")
          t.copy_to_top("treeAddr8", "_ta")
          t.copy_to_top("keypair4", "_kp")
          t.to_top("leafIdx")
          auth_name = "auth#{layer}"
          t.to_top(auth_name)
          t.to_top(wpk_name)
          root_name = "root#{layer}"

          t.raw_block(["_psp", "_ta", "_kp", "leafIdx", auth_name, wpk_name], root_name) do |e|
            _emit_slh_merkle(e, p, layer_val)
            e.call(_make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
            e.call(_make_stack_op(op: "drop"))
            e.call(_make_stack_op(op: "drop"))
            e.call(_make_stack_op(op: "drop"))
            e.call(_make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          end

          # Update leafIdx, treeIdx, treeAddr8, keypair4 for next layer
          if layer < d - 1
            t.to_top("treeIdx")
            t.dup("_tic")
            t.raw_block(["_tic"], "leafIdx") do |e|
              e.call(_make_stack_op(op: "push", value: _big_int_push(1 << hp)))
              e.call(_make_stack_op(op: "opcode", code: "OP_MOD"))
            end
            t.swap
            t.raw_block(["treeIdx"], "treeIdx") do |e|
              e.call(_make_stack_op(op: "push", value: _big_int_push(1 << hp)))
              e.call(_make_stack_op(op: "opcode", code: "OP_DIV"))
            end

            t.to_top("treeAddr8")
            t.drop
            t.copy_to_top("treeIdx", "_ti8")
            t.raw_block(["_ti8"], "treeAddr8", &tree_addr_proc)

            t.to_top("keypair4")
            t.drop
            t.copy_to_top("leafIdx", "_li4")
            t.raw_block(["_li4"], "keypair4", &keypair_addr_proc)
          end
        end

        # ---- 8. Compare root to pkRoot ----
        t.to_top("root#{d - 1}")
        t.to_top("pkRoot")
        t.equal("_result")

        # ---- 9. Cleanup ----
        t.to_top("_result")
        t.to_alt

        leftover = ["msg", "R", "pkSeed", "htSigRest", "treeIdx", "leafIdx",
                     "_pkSeedPad", "treeAddr8", "keypair4"]
        leftover.each do |nm|
          if t.has(nm)
            t.to_top(nm)
            t.drop
          end
        end
        while t.depth > 0
          t.drop
        end

        t.from_alt("_result")
      end

    end
  end
end
