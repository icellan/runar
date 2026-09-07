# frozen_string_literal: true

# EC codegen -- secp256k1 elliptic curve operations for Bitcoin Script.
#
# Follows the slh_dsa.rb pattern: self-contained module imported by stack.rb.
# Uses an ECTracker (similar to SLHTracker) for named stack state tracking.
#
# Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
# Internal arithmetic uses Jacobian coordinates for scalar multiplication.
#
# Direct port of compilers/python/runar_compiler/codegen/ec.py

require "set"
require_relative "comb"
require_relative "cost_model"

module RunarCompiler
  module Codegen
    module EC
      # =================================================================
      # Constants
      # =================================================================

      # secp256k1 field prime p = 2^256 - 2^32 - 977
      EC_FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

      # p - 2, used for Fermat's little theorem modular inverse
      EC_FIELD_P_MINUS_2 = EC_FIELD_P - 2

      # secp256k1 generator x-coordinate
      EC_GEN_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

      # secp256k1 generator y-coordinate
      EC_GEN_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

      # secp256k1 curve order
      EC_CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

      # Convert an integer to a 32-byte big-endian binary string.
      #
      # @param n [Integer]
      # @return [String] 32-byte binary string
      def self.bigint_to_bytes32(n)
        hex = n.to_s(16).rjust(64, "0")
        [hex].pack("H*")
      end

      # -----------------------------------------------------------------
      # StackOp / PushValue helpers (avoid circular dependency with stack.rb)
      # -----------------------------------------------------------------

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

      # Build a PushValue hash.
      #
      # @param kind [String] "bigint", "bool", or "bytes"
      # @param kwargs [Hash] additional fields
      # @return [Hash] PushValue hash
      def self.make_push_value(kind:, **kwargs)
        result = { kind: kind }
        kwargs.each { |k, v| result[k] = v }
        result
      end

      # Build a PushValue for a big integer.
      #
      # @param n [Integer]
      # @return [Hash] PushValue hash
      def self.big_int_push(n)
        make_push_value(kind: "bigint", big_int: n)
      end

      # =================================================================
      # Codegen options and sign lattice
      # =================================================================

      # Codegen options shared by every EC / NIST-curve emitter.
      #
      # Off by default: with nil (or an all-false instance) each emitter is
      # byte-identical to what the seven tiers ship today, so no golden, size
      # baseline, or cross-tier parity gate can move.
      #
      # constant_pool: park large repeated constants (the field prime, the group
      #   order) in a stack slot and copy them with OP_PICK instead of
      #   re-pushing the literal. field_mod pushes the 256-bit prime at every
      #   modular reduction -- 34 bytes a time, 20,025 times in p256-wallet
      #   (71 % of that fixture). A pick from a slot a dozen deep costs 2.
      # reduction_sinking: emit `a mod p` without the sign fix-up wherever the
      #   dividend is provably non-negative, and the cheap `a - b + p` form for
      #   subtraction wherever the subtrahend is provably reduced. Which
      #   reductions qualify is decided by the sign lattice below -- never
      #   assumed. Only useful alongside constant_pool: the cheap subtraction
      #   references the prime twice, so without a pooled slot it does not pay
      #   (and the emitters compare the two costs, so it is never taken when it
      #   does not).
      # fixed_base_comb: use a fixed-base comb instead of the binary ladder
      #   wherever the base point is a compile-time constant. The window width
      #   is not fixed here: the emitter renders each candidate and keeps
      #   whichever the byte-cost model scores smallest.
      EcCodegenOptions = Struct.new(:constant_pool, :reduction_sinking, :fixed_base_comb) do
        def initialize(constant_pool: false, reduction_sinking: false, fixed_base_comb: false)
          super(constant_pool, reduction_sinking, fixed_base_comb)
        end
      end

      # What is known about a tracked value's sign and range.
      #
      # DOM_REDUCED implies DOM_NON_NEGATIVE; the ordering is what the transfer
      # functions meet over. DOM_UNKNOWN is the default for every slot the
      # analysis has not explicitly proved something about -- including
      # everything a raw_block or an OP_IF produces -- so an un-analysed value
      # can only ever fall back to the shipping reduction.
      #
      # The distinction is not academic. OP_BIN2NUM of 32 unsigned coordinate
      # bytes gives DOM_NON_NEGATIVE but NOT DOM_REDUCED: a coordinate may
      # legitimately be up to 2^256 - 1 while p is 2^32 + 977 smaller.
      # Multiplication and addition need only DOM_NON_NEGATIVE; subtraction's
      # cheap form needs the subtrahend DOM_REDUCED, and conflating the two
      # produces a script that passes 256 EC oracle assertions and is still
      # wrong on ecAdd((0,1), (2^256-1,1)).

      # Nothing known. May be negative.
      DOM_UNKNOWN = 0
      # Provably >= 0. May be >= p.
      DOM_NON_NEGATIVE = 1
      # Provably in [0, p).
      DOM_REDUCED = 2

      # True when d proves the value is >= 0.
      #
      # @param d [Integer]
      # @return [Boolean]
      def self.non_negative?(d)
        d >= DOM_NON_NEGATIVE
      end

      # Stack slot names reserved for pooled constants.
      POOL_FIELD_P = "_pool$p"
      POOL_GROUP_N = "_pool$n"

      # =================================================================
      # ECTracker -- named stack state tracker (mirrors TS ECTracker)
      # =================================================================

      class ECTracker
        # @return [Array<String>] named stack entries
        attr_accessor :nm
        # @return [Array<Integer>] sign-lattice fact per stack SLOT
        attr_accessor :dm
        # @return [Proc] emit callback
        attr_reader :e
        # @return [Boolean] may this tracker serve constants from a pooled slot?
        attr_reader :pooling
        # @return [Boolean] may this tracker emit sunk reductions?
        attr_reader :sinking
        # @return [Boolean] may a compile-time-known base use a fixed-base comb?
        attr_reader :comb

        # @param init [Array<String>] initial stack names
        # @param emit [Proc] callback receiving a StackOp hash
        # @param opts [EcCodegenOptions, nil] codegen options
        # @param init_domains [Array<Integer>, nil] lattice facts for init slots
        def initialize(init, emit, opts = nil, init_domains = nil)
          @nm = init.dup
          # dm is kept parallel to nm, slot by slot.
          #
          # Slot-parallel rather than keyed by name on purpose: names are reused
          # (_fmul_prod is written by every multiply) and the same name can be
          # resident twice, so a name-keyed hash would go stale in exactly the
          # cases that matter. Every mutation of nm below mirrors into dm with
          # the same splice, so the two cannot drift.
          @dm = init_domains ? init_domains.dup : Array.new(@nm.length, DOM_UNKNOWN)
          # Lattice facts for values parked on the alt stack, bottom -> top.
          @alt_dm = []
          @e = emit
          @pooling = opts ? !!opts.constant_pool : false
          @sinking = opts ? !!opts.reduction_sinking : false
          @comb = opts ? !!opts.fixed_base_comb : false
        end

        # The options this tracker was built with, for a nested tracker.
        #
        # @return [EcCodegenOptions]
        def options
          EcCodegenOptions.new(constant_pool: @pooling, reduction_sinking: @sinking,
                               fixed_base_comb: @comb)
        end

        # -- sign lattice ---------------------------------------------

        # What is known about the named value. DOM_UNKNOWN when absent.
        #
        # @param name [String]
        # @return [Integer]
        def domain_of(name)
          # A silent desync here would hand a transfer function a fact about the
          # WRONG slot, which is the one failure mode that produces a smaller
          # script that quietly computes something else. Fail loudly instead.
          if @dm.length != @nm.length
            raise "ECTracker: lattice desynchronised (#{@nm.length} slots, " \
                  "#{@dm.length} facts). Every nm mutation must go through a " \
                  "tracker method or push_tracked/pop_tracked."
          end
          i = @nm.length - 1
          while i >= 0
            return @dm[i] if @nm[i] == name

            i -= 1
          end
          DOM_UNKNOWN
        end

        # Record a fact about the named value's slot.
        #
        # @param name [String]
        # @param d [Integer]
        def set_domain(name, d)
          i = @nm.length - 1
          while i >= 0
            if @nm[i] == name
              @dm[i] = d
              return
            end
            i -= 1
          end
        end

        # Push a slot the caller tracks itself (where raw opcodes create items).
        def push_tracked(name, d = DOM_UNKNOWN)
          @nm.push(name)
          @dm.push(d)
        end

        # Pop a slot the caller tracks itself. Mirror of push_tracked.
        def pop_tracked
          return "" if @nm.empty?

          @dm.pop
          @nm.pop
        end

        # Remove the slot at an absolute (bottom-relative) index.
        #
        # @return [Array(String, Integer)]
        def remove_slot_at(index)
          n = @nm.delete_at(index)
          d = @dm.delete_at(index)
          [n, d]
        end

        def depth
          @nm.length
        end

        # Find the depth (distance from top) of a named stack entry.
        #
        # @param name [String]
        # @return [Integer]
        def find_depth(name)
          i = @nm.length - 1
          while i >= 0
            return @nm.length - 1 - i if @nm[i] == name

            i -= 1
          end
          raise "ECTracker: '#{name}' not on stack #{@nm}"
        end

        # Push raw bytes onto the stack.
        def push_bytes(n, v)
          @e.call(EC.make_stack_op(op: "push", value: EC.make_push_value(kind: "bytes", bytes_val: v)))
          # A byte blob is not a number until BIN2NUM decides how to read it.
          push_tracked(n, DOM_UNKNOWN)
        end

        # Push a big integer onto the stack.
        def push_big_int(n, v)
          @e.call(EC.make_stack_op(op: "push", value: EC.make_push_value(kind: "bigint", big_int: v)))
          push_tracked(n, v >= 0 ? DOM_NON_NEGATIVE : DOM_UNKNOWN)
        end

        # Push an integer onto the stack using big_int_push encoding.
        def push_int(n, v)
          @e.call(EC.make_stack_op(op: "push", value: EC.big_int_push(v)))
          push_tracked(n, v >= 0 ? DOM_NON_NEGATIVE : DOM_UNKNOWN)
        end

        # Duplicate top of stack.
        def dup(n)
          @e.call(EC.make_stack_op(op: "dup"))
          push_tracked(n, @dm.empty? ? DOM_UNKNOWN : @dm[-1])
        end

        # Drop top of stack.
        def drop
          @e.call(EC.make_stack_op(op: "drop"))
          pop_tracked
        end

        # Remove second-to-top stack element.
        def nip
          @e.call(EC.make_stack_op(op: "nip"))
          l = @nm.length
          remove_slot_at(l - 2) if l >= 2
        end

        # Copy second-to-top onto top.
        def over(n)
          @e.call(EC.make_stack_op(op: "over"))
          push_tracked(n, @dm.length >= 2 ? @dm[-2] : DOM_UNKNOWN)
        end

        # Swap top two stack elements.
        def swap
          @e.call(EC.make_stack_op(op: "swap"))
          l = @nm.length
          if l >= 2
            @nm[l - 1], @nm[l - 2] = @nm[l - 2], @nm[l - 1]
            @dm[l - 1], @dm[l - 2] = @dm[l - 2], @dm[l - 1]
          end
        end

        # Rotate top three stack elements.
        def rot
          @e.call(EC.make_stack_op(op: "rot"))
          l = @nm.length
          if l >= 3
            r, rd = remove_slot_at(l - 3)
            push_tracked(r, rd)
          end
        end

        # Emit a raw opcode.
        def op(code)
          @e.call(EC.make_stack_op(op: "opcode", code: code))
        end

        # Roll an item from depth d to top.
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
          @e.call(EC.make_stack_op(op: "push", value: EC.big_int_push(d)))
          push_tracked("", DOM_NON_NEGATIVE)
          @e.call(EC.make_stack_op(op: "roll", depth: d))
          pop_tracked # the depth literal
          idx = @nm.length - 1 - d
          r, rd = remove_slot_at(idx)
          push_tracked(r, rd)
        end

        # Pick (copy) an item from depth d to top.
        def pick(d, n)
          if d == 0
            dup(n)
            return
          end
          if d == 1
            over(n)
            return
          end
          @e.call(EC.make_stack_op(op: "push", value: EC.big_int_push(d)))
          push_tracked("", DOM_NON_NEGATIVE)
          @e.call(EC.make_stack_op(op: "pick", depth: d))
          pop_tracked # the depth literal
          # Once the depth literal is gone the copied slot sits at depth d.
          src = @dm.length > d ? @dm[@dm.length - 1 - d] : DOM_UNKNOWN
          push_tracked(n, src)
        end

        # Roll the named item to the top of the stack.
        def to_top(name)
          roll(find_depth(name))
        end

        # Copy the named item to the top of the stack.
        def copy_to_top(name, n)
          pick(find_depth(name), n)
        end

        # -- constant pool --------------------------------------------
        #
        # A pooled constant is an ordinary tracked slot; nothing about the stack
        # model changes. push_const just chooses, per call site and by emitted
        # bytes, between copying that slot and re-pushing the literal. Nested
        # trackers built from t.nm.dup inherit the slot for free, so pooled
        # constants work unchanged inside an OP_IF arm.

        # Park value in slot for this emitter. No-op when pooling is off.
        def pool_constant(slot, value)
          return if !@pooling || @nm.include?(slot)

          push_big_int(slot, value)
        end

        # Remove a pooled slot. No-op when pooling is off or the slot is absent.
        def release_constant(slot)
          return if !@pooling || !@nm.include?(slot)

          to_top(slot)
          drop
        end

        # Emitted bytes a push_const of this constant would cost right now.
        #
        # The comparison is exact -- size_of_push_int is the same encoder the
        # emit pass uses -- so pooling can never make a call site bigger. A pick
        # at depth d costs size_of_push_int(d) + 1; depths 0 and 1 are OP_DUP /
        # OP_OVER, 1 byte each.
        def const_cost(slot, value)
          if @pooling && @nm.include?(slot)
            d = find_depth(slot)
            pick_cost = d <= 1 ? 1 : CostModel.size_of_push_int(d) + 1
            return pick_cost if pick_cost < CostModel.size_of_push_int(value)
          end
          CostModel.size_of_push_int(value)
        end

        # Materialize value on top as name, from the pooled slot when that is
        # cheaper in emitted bytes than pushing the literal.
        def push_const(slot, value, name)
          if @pooling && @nm.include?(slot)
            d = find_depth(slot)
            pick_cost = d <= 1 ? 1 : CostModel.size_of_push_int(d) + 1
            if pick_cost < CostModel.size_of_push_int(value)
              pick(d, name)
              return
            end
          end
          push_big_int(name, value)
        end

        # Move top of stack to alt stack.
        def to_alt
          op("OP_TOALTSTACK")
          return if @nm.empty?

          d = @dm[-1]
          pop_tracked
          @alt_dm.push(d)
        end

        # Pop from alt stack to main stack.
        def from_alt(n)
          op("OP_FROMALTSTACK")
          push_tracked(n, @alt_dm.empty? ? DOM_UNKNOWN : @alt_dm.pop)
        end

        # Rename the top of stack.
        def rename(n)
          @nm[-1] = n if @nm.length > 0
        end

        # Emit raw opcodes; tracker only records net stack effect.
        #
        # @param consume [Array<String>] names consumed from the stack
        # @param produce [String] name produced ("" means no output pushed)
        # @param fn [Proc] block receiving an emit callback
        def raw_block(consume, produce, fn)
          consume.reverse_each { pop_tracked }
          fn.call(@e)
          # Opaque opcodes: nothing is known about the result unless the caller
          # proves it and records that with set_domain afterwards.
          push_tracked(produce, DOM_UNKNOWN) unless produce.empty?
        end

        # Emit if/else with tracked stack effect.
        #
        # @param cond_name [String] name of the condition value
        # @param then_fn [Proc] block receiving an emit callback for then-branch
        # @param else_fn [Proc] block receiving an emit callback for else-branch
        # @param result_name [String] name for the result ("" means no result)
        def emit_if(cond_name, then_fn, else_fn, result_name)
          to_top(cond_name)
          pop_tracked # condition consumed
          then_ops = []
          else_ops = []
          then_fn.call(->(op) { then_ops.push(op) })
          else_fn.call(->(op) { else_ops.push(op) })
          @e.call(EC.make_stack_op(op: "if", then: then_ops, else_ops: else_ops))
          # A join over two arms this tracker did not analyse: nothing is known.
          push_tracked(result_name, DOM_UNKNOWN) unless result_name.empty?
        end
      end

      # =================================================================
      # Field arithmetic helpers
      # =================================================================

      # Push the field prime p onto the stack as a script number.
      #
      # @param t [ECTracker]
      # @param name [String]
      def self.ec_push_field_p(t, name)
        t.push_const(POOL_FIELD_P, EC_FIELD_P, name)
      end

      # `a mod p` with no sign fix-up: 1 opcode instead of 7.
      #
      # Sound only when the dividend is provably >= 0, because OP_MOD takes the
      # sign of the dividend. The caller proves that; this does not check.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.ec_field_mod_short(t, a_name, result_name)
        t.to_top(a_name)
        ec_push_field_p(t, "_fmods_p")
        t.raw_block([a_name, "_fmods_p"], result_name,
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MOD")) })
        t.set_domain(result_name, DOM_REDUCED)
      end

      # Does the cheap `a - b + p` subtraction shape pay here?
      #
      # It references the prime TWICE where the shipping shape references it
      # once and pays six more opcodes, so it only wins when the prime is cheap
      # to materialise -- i.e. when it is pooled. Without a pool this rewrite
      # makes p256-wallet LARGER (958,792 -> 999,371 measured), which is why it
      # is a cost comparison and not a flag.
      #
      # @param t [ECTracker]
      # @return [Boolean]
      def self.ec_cheap_sub_pays(t)
        c = t.const_cost(POOL_FIELD_P, EC_FIELD_P)
        2 * c + 2 < c + 8
      end

      # Reduce TOS mod p, ensuring non-negative result.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.ec_field_mod(t, a_name, result_name)
        if t.sinking && non_negative?(t.domain_of(a_name))
          ec_field_mod_short(t, a_name, result_name)
          return
        end
        t.to_top(a_name)
        ec_push_field_p(t, "_fmod_p")
        # (a % p + p) % p
        fn = ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_2DUP"))   # a p a p
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))     # a p (a%p)
          e.call(make_stack_op(op: "rot"))                         # p (a%p) a
          e.call(make_stack_op(op: "drop"))                        # p (a%p)
          e.call(make_stack_op(op: "over"))                        # p (a%p) p
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))      # p (a%p+p)
          e.call(make_stack_op(op: "swap"))                        # (a%p+p) p
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))      # ((a%p+p)%p)
        }
        t.raw_block([a_name, "_fmod_p"], result_name, fn)
        t.set_domain(result_name, DOM_REDUCED)
      end

      # Compute (a + b) mod p.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.ec_field_add(t, a_name, b_name, result_name)
        # Read the operand facts BEFORE raw_block consumes their slots.
        sum_non_neg = non_negative?(t.domain_of(a_name)) && non_negative?(t.domain_of(b_name))
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_fadd_sum", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.set_domain("_fadd_sum", DOM_NON_NEGATIVE) if sum_non_neg
        ec_field_mod(t, "_fadd_sum", result_name)
      end

      # Compute (a - b) mod p (non-negative).
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.ec_field_sub(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        # The cheap shape needs a >= 0 AND b in [0, p): then a - b > -p, so a
        # single shifted reduction is exact. `b >= 0` alone is NOT enough -- a
        # coordinate decoded from 32 unsigned bytes can exceed p by up to
        # 2^32 + 977, which is precisely the ecAdd((0,1), (2^256-1,1))
        # counterexample.
        cheap = t.sinking &&
                non_negative?(t.domain_of(a_name)) &&
                t.domain_of(b_name) == DOM_REDUCED &&
                ec_cheap_sub_pays(t)

        t.raw_block([a_name, b_name], "_fsub_diff", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_SUB")) })

        if cheap
          ec_push_field_p(t, "_fsub_p")
          t.raw_block(["_fsub_diff", "_fsub_p"], "_fsub_shift",
                      ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
          t.set_domain("_fsub_shift", DOM_NON_NEGATIVE)
          ec_field_mod_short(t, "_fsub_shift", result_name)
          return
        end
        ec_field_mod(t, "_fsub_diff", result_name)
      end

      # Compute (a * b) mod p.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.ec_field_mul(t, a_name, b_name, result_name, product_non_negative = false)
        # product_non_negative lets ec_field_sqr assert the sign independently
        # of the operand: a*a >= 0 for any a whatsoever.
        non_neg = product_non_negative ||
                  (non_negative?(t.domain_of(a_name)) && non_negative?(t.domain_of(b_name)))
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_fmul_prod", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        t.set_domain("_fmul_prod", DOM_NON_NEGATIVE) if non_neg
        ec_field_mod(t, "_fmul_prod", result_name)
      end

      # Compute (a * c) mod p where c is a small constant.
      #
      # Uses OP_2MUL when c == 2 (single opcode, no push needed).
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param c [Integer] small constant multiplier
      # @param result_name [String]
      def self.ec_field_mul_const(t, a_name, c, result_name)
        # Every call site passes a small positive c, so the product keeps a's sign.
        non_neg = c > 0 && non_negative?(t.domain_of(a_name))
        t.to_top(a_name)
        t.raw_block([a_name], "_fmc_prod", ->(e) {
          if c == 2
            # Use OP_2MUL (single opcode, no push needed)
            e.call(make_stack_op(op: "opcode", code: "OP_2MUL"))
          else
            e.call(make_stack_op(op: "push", value: big_int_push(c)))
            e.call(make_stack_op(op: "opcode", code: "OP_MUL"))
          end
        })
        t.set_domain("_fmc_prod", DOM_NON_NEGATIVE) if non_neg
        ec_field_mod(t, "_fmc_prod", result_name)
      end

      # Compute (a * a) mod p.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.ec_field_sqr(t, a_name, result_name)
        t.copy_to_top(a_name, "_fsqr_copy")
        ec_field_mul(t, a_name, "_fsqr_copy", result_name, true)
      end

      # Compute a^(p-2) mod p via square-and-multiply.
      #
      # Consumes a_name from the tracker.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.ec_field_inv(t, a_name, result_name)
        # p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
        # Bits 255..32: 224 bits, all 1 except bit 32 which is 0
        # Bits 31..0: 0xFFFFFC2D

        # Start: result = a (bit 255 = 1)
        t.copy_to_top(a_name, "_inv_r")
        # Bits 254 down to 33: all 1's (222 bits). Bit 32 is 0 (handled below).
        222.times do
          ec_field_sqr(t, "_inv_r", "_inv_r2")
          t.rename("_inv_r")
          t.copy_to_top(a_name, "_inv_a")
          ec_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
          t.rename("_inv_r")
        end
        # Bit 32 is 0: square only (no multiply)
        ec_field_sqr(t, "_inv_r", "_inv_r2")
        t.rename("_inv_r")
        # Bits 31 down to 0 of p-2
        low_bits = EC_FIELD_P_MINUS_2 & 0xFFFFFFFF
        31.downto(0) do |i|
          ec_field_sqr(t, "_inv_r", "_inv_r2")
          t.rename("_inv_r")
          if (low_bits >> i) & 1 == 1
            t.copy_to_top(a_name, "_inv_a")
            ec_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
            t.rename("_inv_r")
          end
        end
        # Clean up original input and rename result
        t.to_top(a_name)
        t.drop
        t.to_top("_inv_r")
        t.rename(result_name)
      end

      # =================================================================
      # Point decompose / compose
      # =================================================================

      # Emit inline byte reversal for a 32-byte value on TOS.
      #
      # @param e [Proc] emit callback
      def self.ec_emit_reverse32(e)
        # Push empty accumulator, swap with data
        e.call(make_stack_op(op: "opcode", code: "OP_0"))
        e.call(make_stack_op(op: "swap"))
        # 32 iterations: peel first byte, prepend to accumulator
        32.times do
          # Stack: [accum, remaining]
          e.call(make_stack_op(op: "push", value: big_int_push(1)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          # Stack: [accum, byte0, rest]
          e.call(make_stack_op(op: "rot"))
          # Stack: [byte0, rest, accum]
          e.call(make_stack_op(op: "rot"))
          # Stack: [rest, accum, byte0]
          e.call(make_stack_op(op: "swap"))
          # Stack: [rest, byte0, accum]
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          # Stack: [rest, byte0||accum]
          e.call(make_stack_op(op: "swap"))
          # Stack: [byte0||accum, rest]
        end
        # Stack: [reversed, empty]
        e.call(make_stack_op(op: "drop"))
      end

      # Decompose a 64-byte Point into (x_num, y_num) on stack.
      #
      # Consumes point_name, produces x_name and y_name.
      #
      # @param t [ECTracker]
      # @param point_name [String]
      # @param x_name [String]
      # @param y_name [String]
      def self.ec_decompose_point(t, point_name, x_name, y_name)
        t.to_top(point_name)
        # OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top)
        split_fn = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(32)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        }
        t.raw_block([point_name], "", split_fn)
        # Manually track the two new items
        t.push_tracked("_dp_xb", DOM_UNKNOWN)
        t.push_tracked("_dp_yb", DOM_UNKNOWN)

        # Convert y_bytes (on top) to num
        # Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
        convert_y = ->(e) {
          ec_emit_reverse32(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        }
        t.raw_block(["_dp_yb"], y_name, convert_y)
        # A 0x00 sign byte is appended before BIN2NUM, so the coordinate decodes
        # UNSIGNED: >= 0, but it may be up to 2^(8*coordBytes) - 1 and therefore
        # >= p. That gap is exactly what the subtraction precondition turns on.
        t.set_domain(y_name, DOM_NON_NEGATIVE)

        # Convert x_bytes to num
        t.to_top("_dp_xb")
        convert_x = ->(e) {
          ec_emit_reverse32(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        }
        t.raw_block(["_dp_xb"], x_name, convert_x)
        t.set_domain(x_name, DOM_NON_NEGATIVE)

        # Stack: [yName, xName] -- swap to standard order [xName, yName]
        t.swap
      end

      # Compose (x_num, y_num) into a 64-byte Point.
      #
      # Consumes x_name and y_name, produces result_name.
      #
      # @param t [ECTracker]
      # @param x_name [String]
      # @param y_name [String]
      # @param result_name [String]
      def self.ec_compose_point(t, x_name, y_name, result_name)
        # Convert x to 32-byte big-endian
        t.to_top(x_name)
        convert_x = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(33)))
          e.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          # Drop the sign byte (last byte) -- split at 32, keep left
          e.call(make_stack_op(op: "push", value: big_int_push(32)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(make_stack_op(op: "drop"))
          ec_emit_reverse32(e)
        }
        t.raw_block([x_name], "_cp_xb", convert_x)

        # Convert y to 32-byte big-endian
        t.to_top(y_name)
        convert_y = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(33)))
          e.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          e.call(make_stack_op(op: "push", value: big_int_push(32)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(make_stack_op(op: "drop"))
          ec_emit_reverse32(e)
        }
        t.raw_block([y_name], "_cp_yb", convert_y)

        # Cat: x_be || y_be (x is below y after the two to_top calls)
        t.to_top("_cp_xb")
        t.to_top("_cp_yb")
        t.raw_block(["_cp_xb", "_cp_yb"], result_name, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_CAT")) })
      end

      # =================================================================
      # Affine point addition (for ecAdd)
      # =================================================================

      # Perform affine point addition.
      #
      # Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.
      #
      # @param t [ECTracker]
      def self.ec_affine_add(t)
        # The chord slope s = (qy - py) / (qx - px) is undefined when P == Q:
        # the denominator is zero and the correct slope is the TANGENT,
        # 3px^2 / (2py). Without this, ecAdd(P, P) silently produced a wrong
        # point, so every contract that doubled deployed an unspendable script.
        #
        # Both cases are `s = num / den`, so only the NUMERATOR and DENOMINATOR
        # are selected and the single expensive field_inv still runs once.
        # rx and ry below are already correct for doubling.
        #
        #   cond = (px == qx) AND (py == qy)   1 when doubling, else 0
        #   num  = cond ? 3*px^2 : (qy - py)
        #   den  = cond ? 2*py   : (qx - px)
        #
        # selected as `b + cond*(a - b)`, which needs no branch and keeps the
        # emitted op sequence identical on both paths.
        #
        # THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx
        # ALONE sends it down the tangent path and returns 2P -- an on-curve,
        # entirely plausible, WRONG point. Before the doubling fix the chord
        # path ran there, divided by zero (ec_field_inv is Fermat, inv(0) = 0)
        # and produced an OFF-curve blob, so `assert(ecOnCurve(ecAdd(a, b)))`
        # -- the idiom this codegen tells authors to write -- happened to
        # reject it. Selecting on px alone would have silently disarmed that.
        #
        # P + (-P) is the point at infinity, which affine x||y cannot
        # represent. This codegen already has a representation for O: the
        # ALL-ZERO blob, which is what `ecMul(P, 0n)` returns and what the
        # `ec-mulgen-linear` rewrite in optimizer/ec-rules.json produces for
        # k1 + k2 == 0 (mod n). So return that, by masking the result with
        # `notinf = NOT(px == qx AND NOT cond)`:
        #
        #   - it agrees with the rewrite, so the same source cannot give two
        #     answers depending on whether the optimizer fired;
        #   - O is not on the curve (0^2 != 0^3 + 7), so the on-curve gate
        #     rejects it and the idiom above works again;
        #   - it adds no failure channel to what is a pure value-producing
        #     expression, the same reason ec_emit_scalar_reduce reduces
        #     instead of rejecting.
        #
        # The mask is a bare OP_MUL with no reduction: rx, ry are already in
        # [0, p) and notinf is 0 or 1, so the product is canonical either way.
        t.copy_to_top("px", "_px_eq")
        t.copy_to_top("qx", "_qx_eq")
        t.raw_block(["_px_eq", "_qx_eq"], "_xeq",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        t.copy_to_top("py", "_py_eq")
        t.copy_to_top("qy", "_qy_eq")
        t.raw_block(["_py_eq", "_qy_eq"], "_yeq",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        t.copy_to_top("_xeq", "_xeq_c")
        t.to_top("_yeq")
        t.raw_block(["_xeq_c", "_yeq"], "_cond",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })
        # notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and
        # the points are not equal, i.e. exactly the P == -Q case.
        t.to_top("_xeq")
        t.copy_to_top("_cond", "_cond_c")
        t.raw_block(["_xeq", "_cond_c"], "_notinf", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
          e.call(make_stack_op(op: "opcode", code: "OP_NOT"))
        })

        # chord numerator / denominator
        t.copy_to_top("qy", "_qy1")
        t.copy_to_top("py", "_py1")
        ec_field_sub(t, "_qy1", "_py1", "_num_chord")
        t.copy_to_top("qx", "_qx1")
        t.copy_to_top("px", "_px1")
        ec_field_sub(t, "_qx1", "_px1", "_den_chord")

        # tangent numerator / denominator: 3*px^2 and 2*py
        t.copy_to_top("px", "_px_t")
        ec_field_sqr(t, "_px_t", "_px_sq")
        ec_field_mul_const(t, "_px_sq", 3, "_num_tan")
        t.copy_to_top("py", "_py_t")
        ec_field_mul_const(t, "_py_t", 2, "_den_tan")

        # num = num_chord + cond*(num_tan - num_chord)
        t.copy_to_top("_num_chord", "_num_chord_c")
        ec_field_sub(t, "_num_tan", "_num_chord_c", "_num_diff")
        t.copy_to_top("_cond", "_cond_n")
        ec_field_mul(t, "_num_diff", "_cond_n", "_num_sel")
        ec_field_add(t, "_num_chord", "_num_sel", "_s_num")

        # den = den_chord + cond*(den_tan - den_chord)
        t.copy_to_top("_den_chord", "_den_chord_c")
        ec_field_sub(t, "_den_tan", "_den_chord_c", "_den_diff")
        t.to_top("_cond")
        t.rename("_cond_d")
        ec_field_mul(t, "_den_diff", "_cond_d", "_den_sel")
        ec_field_add(t, "_den_chord", "_den_sel", "_s_den")

        # s = s_num / s_den mod p
        ec_field_inv(t, "_s_den", "_s_den_inv")
        ec_field_mul(t, "_s_num", "_s_den_inv", "_s")

        # rx = s^2 - px - qx mod p
        t.copy_to_top("_s", "_s_keep")
        ec_field_sqr(t, "_s", "_s2")
        t.copy_to_top("px", "_px2")
        ec_field_sub(t, "_s2", "_px2", "_rx1")
        t.copy_to_top("qx", "_qx2")
        ec_field_sub(t, "_rx1", "_qx2", "rx")

        # ry = s * (px - rx) - py mod p
        t.copy_to_top("px", "_px3")
        t.copy_to_top("rx", "_rx2")
        ec_field_sub(t, "_px3", "_rx2", "_px_rx")
        ec_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx")
        t.copy_to_top("py", "_py2")
        ec_field_sub(t, "_s_px_rx", "_py2", "ry")

        # Clean up original points
        t.to_top("px")
        t.drop
        t.to_top("py")
        t.drop
        t.to_top("qx")
        t.drop
        t.to_top("qy")
        t.drop

        # P == -Q -> force the all-zero point (see the header comment).
        t.to_top("rx")
        t.copy_to_top("_notinf", "_notinf_x")
        t.raw_block(["rx", "_notinf_x"], "rx",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        t.to_top("ry")
        t.to_top("_notinf")
        t.raw_block(["ry", "_notinf"], "ry",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
      end

      # =================================================================
      # Jacobian point operations (for ecMul)
      # =================================================================

      # Perform Jacobian point doubling (a=0 for secp256k1).
      #
      # Expects jx, jy, jz on tracker. Replaces with updated values.
      #
      # @param t [ECTracker]
      def self.ec_jacobian_double(t)
        # Save copies of jx, jy, jz for later use
        t.copy_to_top("jy", "_jy_save")
        t.copy_to_top("jx", "_jx_save")
        t.copy_to_top("jz", "_jz_save")

        # A = jy^2
        ec_field_sqr(t, "jy", "_A")

        # B = 4 * jx * A
        t.copy_to_top("_A", "_A_save")
        ec_field_mul(t, "jx", "_A", "_xA")
        t.push_int("_four", 4)
        ec_field_mul(t, "_xA", "_four", "_B")

        # C = 8 * A^2
        ec_field_sqr(t, "_A_save", "_A2")
        t.push_int("_eight", 8)
        ec_field_mul(t, "_A2", "_eight", "_C")

        # D = 3 * X^2
        ec_field_sqr(t, "_jx_save", "_x2")
        t.push_int("_three", 3)
        ec_field_mul(t, "_x2", "_three", "_D")

        # nx = D^2 - 2*B
        t.copy_to_top("_D", "_D_save")
        t.copy_to_top("_B", "_B_save")
        ec_field_sqr(t, "_D", "_D2")
        t.copy_to_top("_B", "_B1")
        ec_field_mul_const(t, "_B1", 2, "_2B")
        ec_field_sub(t, "_D2", "_2B", "_nx")

        # ny = D*(B - nx) - C
        t.copy_to_top("_nx", "_nx_copy")
        ec_field_sub(t, "_B_save", "_nx_copy", "_B_nx")
        ec_field_mul(t, "_D_save", "_B_nx", "_D_B_nx")
        ec_field_sub(t, "_D_B_nx", "_C", "_ny")

        # nz = 2 * Y * Z
        ec_field_mul(t, "_jy_save", "_jz_save", "_yz")
        ec_field_mul_const(t, "_yz", 2, "_nz")

        # Clean up leftovers: _B and old jz (only copied, never consumed)
        t.to_top("_B")
        t.drop
        t.to_top("jz")
        t.drop
        t.to_top("_nx")
        t.rename("jx")
        t.to_top("_ny")
        t.rename("jy")
        t.to_top("_nz")
        t.rename("jz")
      end

      # Convert Jacobian to affine coordinates.
      #
      # Consumes jx, jy, jz; produces rx_name, ry_name.
      #
      # @param t [ECTracker]
      # @param rx_name [String]
      # @param ry_name [String]
      def self.ec_jacobian_to_affine(t, rx_name, ry_name)
        ec_field_inv(t, "jz", "_zinv")
        t.copy_to_top("_zinv", "_zinv_keep")
        ec_field_sqr(t, "_zinv", "_zinv2")
        t.copy_to_top("_zinv2", "_zinv2_keep")
        ec_field_mul(t, "_zinv_keep", "_zinv2", "_zinv3")
        ec_field_mul(t, "jx", "_zinv2_keep", rx_name)
        ec_field_mul(t, "jy", "_zinv3", ry_name)
      end

      # =================================================================
      # Jacobian mixed addition (P_jacobian + Q_affine)
      # =================================================================

      # Build Jacobian mixed-add ops for use inside OP_IF.
      #
      # Uses an inner ECTracker to leverage field arithmetic helpers.
      #
      # Stack layout: [..., ax, ay, _k, jx, jy, jz]
      # After:        [..., ax, ay, _k, jx', jy', jz']
      #
      # @param e [Proc] emit callback
      # @param t [ECTracker]
      def self.ec_build_jacobian_add_affine_inline(e, t)
        # Create inner tracker with cloned stack state
        # The inner tracker inherits the stack state AND the lattice facts:
        # the operands' proved domains are what decide which reduction shape the
        # body emits, so dropping them here would silently fall back everywhere.
        ec_jacobian_add_affine_body(
          ECTracker.new(t.nm.dup, e, t.options, t.dm.dup), false
        )
      end

      # The mixed-add itself, emitting through a tracker the caller owns.
      #
      # +keep_hr+ additionally leaves copies of H and R on the stack. They are
      # the exception detector: H = U2 - X1 and R = S2 - Y1 are both zero
      # exactly when the Jacobian accumulator is the same curve point as the
      # affine operand, the one case these formulas cannot compute (see
      # ec_build_jacobian_add_or_double_inline).
      def self.ec_jacobian_add_affine_body(it, keep_hr)
        # Save copies of values that get consumed but are needed later
        it.copy_to_top("jz", "_jz_for_z1cu")   # consumed by Z1sq, needed for Z1cu
        it.copy_to_top("jz", "_jz_for_z3")     # needed for Z3
        it.copy_to_top("jy", "_jy_for_y3")     # consumed by R, needed for Y3
        it.copy_to_top("jx", "_jx_for_u1h2")   # consumed by H, needed for U1H2

        # Z1sq = jz^2
        ec_field_sqr(it, "jz", "_Z1sq")

        # Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
        it.copy_to_top("_Z1sq", "_Z1sq_for_u2")
        ec_field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu")

        # U2 = ax * Z1sq_for_u2
        it.copy_to_top("ax", "_ax_c")
        ec_field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2")

        # S2 = ay * Z1cu
        it.copy_to_top("ay", "_ay_c")
        ec_field_mul(it, "_ay_c", "_Z1cu", "_S2")

        # H = U2 - jx
        ec_field_sub(it, "_U2", "jx", "_H")

        # R = S2 - jy
        ec_field_sub(it, "_S2", "jy", "_R")

        if keep_hr
          it.copy_to_top("_H", "_H_keep")
          it.copy_to_top("_R", "_R_keep")
        end

        # Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
        it.copy_to_top("_H", "_H_for_h3")
        it.copy_to_top("_H", "_H_for_z3")

        # H2 = H^2
        ec_field_sqr(it, "_H", "_H2")

        # Save H2 for U1H2
        it.copy_to_top("_H2", "_H2_for_u1h2")

        # H3 = H_for_h3 * H2
        ec_field_mul(it, "_H_for_h3", "_H2", "_H3")

        # U1H2 = _jx_for_u1h2 * H2_for_u1h2
        ec_field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2")

        # Save R, U1H2, H3 for Y3 computation
        it.copy_to_top("_R", "_R_for_y3")
        it.copy_to_top("_U1H2", "_U1H2_for_y3")
        it.copy_to_top("_H3", "_H3_for_y3")

        # X3 = R^2 - H3 - 2*U1H2
        ec_field_sqr(it, "_R", "_R2")
        ec_field_sub(it, "_R2", "_H3", "_x3_tmp")
        ec_field_mul_const(it, "_U1H2", 2, "_2U1H2")
        ec_field_sub(it, "_x3_tmp", "_2U1H2", "_X3")

        # Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
        it.copy_to_top("_X3", "_X3_c")
        ec_field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x")
        ec_field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp")
        ec_field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3")
        ec_field_sub(it, "_r_tmp", "_jy_h3", "_Y3")

        # Z3 = _jz_for_z3 * _H_for_z3
        ec_field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3")

        # Rename results to jx/jy/jz
        it.to_top("_X3")
        it.rename("jx")
        it.to_top("_Y3")
        it.rename("jy")
        it.to_top("_Z3")
        it.rename("jz")
      end

      # Branchless select of one Jacobian coordinate: +add + cond*(dbl - add)+.
      # Same shape as the numerator/denominator select in ec_affine_add, so both
      # paths emit the identical op sequence and the tracker's static stack
      # model holds. Consumes add_name, dbl_name and cond_name.
      def self.ec_select_coord(t, add_name, dbl_name, cond_name, result_name)
        t.copy_to_top(add_name, "_sel_add_c")
        ec_field_sub(t, dbl_name, "_sel_add_c", "_sel_diff")
        ec_field_mul(t, "_sel_diff", cond_name, "_sel_scaled")
        ec_field_add(t, add_name, "_sel_scaled", result_name)
      end

      # The ladder's LAST conditional step: mixed-add, but correct when the
      # accumulator already equals the point being added.
      #
      # The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when
      # the two operands are the same curve point H = 0, so Z3 = Z1*H = 0 -- the
      # point at infinity -- and since ec_field_inv is Fermat (inv(0) = 0),
      # ec_jacobian_to_affine turns that into the ALL-ZERO point instead of 2P.
      # ecMul(P, 2n) and ecMulGen(2n) returned 64 zero bytes.
      #
      # WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
      # c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
      # (c_i - 1)*P. secp256k1 has cofactor 1, so P has order n and the
      # degenerate cases are exactly c_i == 2 (mod n) -- accumulator == P -- and
      # c_i == 0 or 1 (mod n) -- accumulator == -P or O. c_i ranges over a
      # CONTIGUOUS interval determined only by i, so this is decidable by
      # interval arithmetic rather than by sampling, and over the whole domain
      # k in [0, n-1] only two steps qualify, both at i = 0:
      #
      #   k = 2  -> c_0 = 3n+2 == 2, odd, so the add runs: accumulator == P.
      #   k = 0  -> c_0 = 3n   == 0, odd, so the add runs: accumulator == -P,
      #             true result the point at infinity, which affine coordinates
      #             cannot represent; it stays the all-zero point, as before.
      #
      # At i >= 1, c_i lies in [3n>>i, (4n-1)>>i] -- the lower bound is 3n, not
      # 3n+1, because the reduce puts k = 0 in the domain -- and that interval
      # contains no value == 0, 1 or 2 (mod n) that is also odd; c_256 = 2 is
      # even, so no add runs. Handling H == 0 at every one of the 257 steps
      # would cost ~70% more script bytes; handling it here costs 0.26%.
      #
      # THE ENTIRE ARGUMENT IS CONDITIONED ON k in [0, n-1], which is only true
      # because emit_ec_mul reduces k mod n before adding 3n. That reduce landed
      # one commit AFTER this select (03f50d48 then f16790a9). 03f50d48 ON ITS
      # OWN IS UNSOUND: a last-step-only select while the scalar is still
      # unbounded leaves c_i free to hit 0, 1 or 2 (mod n) at other steps. The
      # two commits must land together and must never be bisected,
      # cherry-picked or reverted apart.
      #
      # The interval argument does 100% of the work; there is no defence in
      # depth here. In particular c_i == 1 (mod n) -- a pre-add accumulator of
      # O -- is UNREACHABLE, not handled: were it reachable the select would
      # still take the ADD path, because O is carried as Z1 = 0, which makes
      # U2 = 0 and H = -X1 != 0. Anything that changes the +3n offset, the
      # iteration count or the reduce must redo the interval check, not assume
      # this still holds.
      #
      # This is NOT a "no honest input hits it" argument: the operand P is
      # caller-supplied but cannot move the exception, because the condition
      # depends only on c_i mod ord(P) and ord(P) = n for every point on the
      # curve. Points that are NOT on the curve carry no such guarantee -- gate
      # untrusted input on ecOnCurve first.
      #
      # Stack layout: [..., ax, ay, _k, jx, jy, jz] -- same in and out.
      def self.ec_build_jacobian_add_or_double_inline(e, t)
        it = ECTracker.new(t.nm.dup, e, t.options, t.dm.dup)

        # Keep the pre-add accumulator: it is what must be DOUBLED in the
        # exceptional case, and the add below consumes jx/jy/jz.
        it.copy_to_top("jx", "_sx")
        it.copy_to_top("jy", "_sy")
        it.copy_to_top("jz", "_sz")

        ec_jacobian_add_affine_body(it, true)

        # cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
        # accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
        # signals the point at infinity.
        it.to_top("_H_keep")
        it.push_int("_zero_h", 0)
        it.raw_block(["_H_keep", "_zero_h"], "_h_is0",
                     ->(e2) { e2.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        it.to_top("_R_keep")
        it.push_int("_zero_r", 0)
        it.raw_block(["_R_keep", "_zero_r"], "_r_is0",
                     ->(e2) { e2.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        it.to_top("_h_is0")
        it.to_top("_r_is0")
        it.raw_block(["_h_is0", "_r_is0"], "_cond",
                     ->(e2) { e2.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })

        # Move the add result aside so ec_jacobian_double can work on jx/jy/jz
        # again, this time holding the saved accumulator.
        it.to_top("jx")
        it.rename("_add_x")
        it.to_top("jy")
        it.rename("_add_y")
        it.to_top("jz")
        it.rename("_add_z")
        it.to_top("_sx")
        it.rename("jx")
        it.to_top("_sy")
        it.rename("jy")
        it.to_top("_sz")
        it.rename("jz")
        ec_jacobian_double(it)
        it.to_top("jx")
        it.rename("_dbl_x")
        it.to_top("jy")
        it.rename("_dbl_y")
        it.to_top("jz")
        it.rename("_dbl_z")

        it.copy_to_top("_cond", "_cond_x")
        ec_select_coord(it, "_add_x", "_dbl_x", "_cond_x", "jx")
        it.copy_to_top("_cond", "_cond_y")
        ec_select_coord(it, "_add_y", "_dbl_y", "_cond_y", "jy")
        it.to_top("_cond")
        it.rename("_cond_z")
        ec_select_coord(it, "_add_z", "_dbl_z", "_cond_z", "jz")
      end

      # =================================================================
      # Public entry points (called from stack lowerer)
      # =================================================================

      # Add two points.
      #
      # Stack in: [point_a, point_b] (b on top)
      # Stack out: [result_point]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_add(emit, opts = nil)
        t = ECTracker.new(["_pa", "_pb"], emit, opts)
        t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
        ec_decompose_point(t, "_pa", "px", "py")
        ec_decompose_point(t, "_pb", "qx", "qy")
        ec_affine_add(t)
        ec_compose_point(t, "rx", "ry", "_result")
        t.release_constant(POOL_FIELD_P)
      end

      # Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.
      #
      # OP_MOD takes the sign of the DIVIDEND, so `k mod n` alone lands in
      # (-n, n); the `+ n, mod n` normalises the negative half. One push of n
      # covers both reductions -- the same shape as `emit_ec_mod_reduce`.
      #
      # Without it, `emit_ec_mul`'s ladder is only correct while
      # 2^257 <= k + 3n < 2^258: a scalar >= ~n sets bit 258, the 257-iteration
      # loop never sees it, and the ladder returns a DIFFERENT multiple of P
      # rather than failing. Scalars are contract input, so that is
      # attacker-chosen. Reducing costs 1 push + 8 opcodes (42 bytes) against a
      # ~429 KB script, and makes k >= n, k < 0 and k = 0 all well defined.
      def self.ec_emit_scalar_reduce(t, k_name, result_name, curve_n)
        t.push_const(POOL_GROUP_N, curve_n, "_n_red")
        t.raw_block([k_name, "_n_red"], result_name, lambda { |e|
          e.call(make_stack_op(op: "opcode", code: "OP_2DUP"))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          e.call(make_stack_op(op: "rot"))
          e.call(make_stack_op(op: "drop"))
          e.call(make_stack_op(op: "over"))
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
          e.call(make_stack_op(op: "swap"))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        })
      end

      # Perform scalar multiplication P * k.
      #
      # Stack in: [point, scalar] (scalar on top)
      # Stack out: [result_point]
      #
      # Uses 256-iteration double-and-add with Jacobian coordinates.
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_mul(emit, opts = nil)
        t = ECTracker.new(["_pt", "_k"], emit, opts)
        t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
        t.pool_constant(POOL_GROUP_N, EC_CURVE_N)
        # Decompose to affine base point
        ec_decompose_point(t, "_pt", "ax", "ay")

        # k' = k + 3n: guarantees bit 257 is set.
        # k in [1, n-1], so k+3n in [3n+1, 4n-1]. Since 3n > 2^257, bit 257
        # is always 1. Adding 3n (= 0 mod n) preserves the EC point: k*G = (k+3n)*G.
        #
        # "k in [1, n-1]" is a PRECONDITION the caller cannot enforce -- the
        # scalar is usually an unlock argument -- so reduce it first.
        t.to_top("_k")
        ec_emit_scalar_reduce(t, "_k", "_kr", EC_CURVE_N)
        t.push_const(POOL_GROUP_N, EC_CURVE_N, "_n")
        t.raw_block(["_kr", "_n"], "_kn", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.push_const(POOL_GROUP_N, EC_CURVE_N, "_n2")
        t.raw_block(["_kn", "_n2"], "_kn2", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.push_const(POOL_GROUP_N, EC_CURVE_N, "_n3")
        t.raw_block(["_kn2", "_n3"], "_kn3", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.rename("_k")

        # Init accumulator = P (bit 257 of k+3n is always 1)
        t.copy_to_top("ax", "jx")
        t.copy_to_top("ay", "jy")
        t.push_int("jz", 1)

        # 257 iterations: bits 256 down to 0
        256.downto(0) do |bit|
          # Double accumulator
          ec_jacobian_double(t)

          # Extract bit: (k >> bit) & 1, using OP_RSHIFTNUM / OP_2DIV
          t.copy_to_top("_k", "_k_copy")
          if bit == 1
            # Single-bit shift: OP_2DIV (no push needed)
            t.raw_block(["_k_copy"], "_shifted", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_2DIV")) })
          elsif bit > 1
            # Multi-bit shift: push shift amount, OP_RSHIFTNUM
            t.push_int("_shift", bit)
            t.raw_block(["_k_copy", "_shift"], "_shifted", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_RSHIFTNUM")) })
          else
            t.rename("_shifted")
          end
          t.push_int("_two", 2)
          t.raw_block(["_shifted", "_two"], "_bit", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MOD")) })

          # Move _bit to TOS and remove from tracker BEFORE generating add ops,
          # because OP_IF consumes _bit and the add ops run with _bit already gone.
          t.to_top("_bit")
          t.pop_tracked # _bit consumed by IF
          add_ops = []
          add_emit = ->(op) { add_ops.push(op) }
          # Only the final step can be handed two equal operands -- see
          # ec_build_jacobian_add_or_double_inline for why, and for what it
          # costs not to.
          if bit.zero?
            ec_build_jacobian_add_or_double_inline(add_emit, t)
          else
            ec_build_jacobian_add_affine_inline(add_emit, t)
          end
          emit.call(make_stack_op(op: "if", then: add_ops, else_ops: []))
        end

        # Convert Jacobian to affine
        ec_jacobian_to_affine(t, "_rx", "_ry")

        # Clean up base point and scalar
        t.to_top("ax")
        t.drop
        t.to_top("ay")
        t.drop
        t.to_top("_k")
        t.drop

        # Compose result
        ec_compose_point(t, "_rx", "_ry", "_result")
        t.release_constant(POOL_GROUP_N)
        t.release_constant(POOL_FIELD_P)
      end
      # =================================================================
      # Fixed-base comb (secp256k1)
      # =================================================================

      # Round i's digit and the selected table entry, as ax/ay/_flag.
      #
      # Exactly one equality holds, so sum(eq_j * T_j) is that entry's
      # coordinate and every term is non-negative and below p -- no reduction is
      # needed, and the result is DOM_REDUCED by construction. When the digit is
      # zero every term vanishes and _flag is 0, so no add runs.
      #
      # Shared by both comb emitters: the selection is pure scalar bit-twiddling
      # and table indexing, with no curve arithmetic in it at all.
      #
      # @param t [ECTracker]
      # @param i [Integer] round index
      # @param w [Integer] window width
      # @param d [Integer] block width / round count
      def self.comb_emit_select(t, i, w, d)
        entries = (1 << w) - 1
        (0...w).each do |b|
          shift = i + b * d
          kc = "_kc#{b}"
          sh = "_sh#{b}"
          t.copy_to_top("_k", kc)
          if shift.zero?
            t.rename(sh)
          elsif shift == 1
            t.raw_block([kc], sh, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_2DIV")) })
          else
            sd = "_sd#{b}"
            t.push_int(sd, shift)
            t.raw_block([kc, sd], sh, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_RSHIFTNUM")) })
          end
          two = "_two#{b}"
          bit = "_b#{b}"
          t.push_int(two, 2)
          t.raw_block([sh, two], bit, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MOD")) })
          t.set_domain(bit, DOM_REDUCED)
        end

        t.to_top("_b0")
        t.rename("_idx")
        (1...w).each do |b|
          bit = "_b#{b}"
          wt = "_wt#{b}"
          bw = "_bw#{b}"
          t.to_top(bit)
          t.push_int(wt, 1 << b)
          t.raw_block([bit, wt], bw, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
          t.to_top("_idx")
          t.raw_block([bw, "_idx"], "_idx", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        end
        t.set_domain("_idx", DOM_REDUCED)

        (1..entries).each do |j|
          ic = "_ic#{j}"
          jv = "_jv#{j}"
          eq = "_eq#{j}"
          t.copy_to_top("_idx", ic)
          t.push_int(jv, j)
          t.raw_block([ic, jv], eq, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
          t.set_domain(eq, DOM_REDUCED)
        end

        %w[x y].each do |coord|
          acc = coord == "x" ? "ax" : "ay"
          (1..entries).each do |j|
            ecn = "_e#{coord}#{j}"
            tc = "_t#{coord}#{j}"
            pr = "_pr#{coord}#{j}"
            t.copy_to_top("_eq#{j}", ecn)
            t.copy_to_top("_T#{coord}#{j}", tc)
            t.raw_block([ecn, tc], pr, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
            if j == 1
              t.rename(acc)
            else
              t.to_top(acc)
              t.raw_block([pr, acc], acc, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
            end
          end
          t.set_domain(acc, DOM_REDUCED)
        end

        entries.downto(1) do |j|
          t.to_top("_eq#{j}")
          t.drop
        end

        t.to_top("_idx")
        t.raw_block(["_idx"], "_flag", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_0NOTEQUAL")) })
      end

      # k*G by a Lim-Lee fixed-base comb instead of the 257-round binary ladder.
      #
      # The ladder doubles and conditionally adds once per SCALAR BIT. A comb
      # splits the scalar into w blocks of d bits and reads one bit from each
      # block per round, so it performs one doubling and one conditional add per
      # COLUMN: the round count falls from w*d to d at the price of a 2^w - 1
      # entry table. G is a compile-time constant here, so the table costs
      # nothing to build.
      #
      # This is the secp256k1 twin of c_emit_comb_mul_gen in p256_p384.rb. The
      # curve arithmetic is NOT shared: secp256k1 has a = 0, so
      # ec_jacobian_double computes D = 3X^2 where the NIST version computes
      # 3(X-Z^2)(X+Z^2). Only comb.rb -- the compile-time table and the interval
      # checker -- is common, and it takes a from the curve record.
      #
      # SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add
      # accumulator equal to the addend, its negation, or the point at infinity.
      # ec_build_jacobian_add_or_double_inline's comment justifies using it
      # everywhere but the ladder's LAST step by an interval argument over
      # c_i mod n, and insists that argument be re-derived by anything changing
      # the offset or the iteration count. A comb changes both, so it is
      # re-derived: comb_safe_rounds evaluates the same argument as executable
      # interval arithmetic over the comb's own geometry, and any round it
      # cannot prove gets the complete add-or-double form instead. Nothing is
      # assumed safe.
      #
      # The other half of that argument is that the accumulator never starts at
      # infinity, which needs the first digit non-zero. comb_geometry searches
      # for the scalar offset that guarantees it rather than reusing the
      # ladder's hardcoded +3n -- right for secp256k1 at w=3, wrong for P-384.
      #
      # Stack in: [_k]. Stack out: [_result].
      #
      # @return [Boolean] false when no geometry exists for w
      def self.ec_emit_comb_mul_gen(emit, w, opts = nil)
        curve = Comb::SECP256K1_COMB_CURVE
        params = Comb.comb_geometry(w, curve)
        return false if params.nil?

        d = params.d
        table = Comb.comb_table(w, d, curve)
        safe = Comb.comb_safe_rounds(params, curve)
        entries = (1 << w) - 1

        t = ECTracker.new(["_k"], emit, opts)
        t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
        t.pool_constant(POOL_GROUP_N, EC_CURVE_N)

        # k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so
        # what makes the interval argument apply at all.
        t.to_top("_k")
        ec_emit_scalar_reduce(t, "_k", "_kr", EC_CURVE_N)
        t.rename("_k")
        (0...params.offset_multiple).each do |i|
          off = "_off#{i}"
          t.push_const(POOL_GROUP_N, EC_CURVE_N, off)
          t.raw_block(["_k", off], "_k", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        end
        t.set_domain("_k", DOM_NON_NEGATIVE)

        # Table, resident for the whole comb: picking an entry costs 2-3 bytes
        # against a 34-byte literal push, and every round reads all of them.
        (1..entries).each do |j|
          pt = table[j]
          t.push_big_int("_Tx#{j}", pt.x)
          t.push_big_int("_Ty#{j}", pt.y)
          t.set_domain("_Tx#{j}", DOM_REDUCED)
          t.set_domain("_Ty#{j}", DOM_REDUCED)
        end

        # Round d-1 initialises the accumulator. The first digit is non-zero by
        # construction (comb_geometry), so this is a real point, never infinity.
        comb_emit_select(t, d - 1, w, d)
        t.to_top("_flag")
        t.drop
        t.to_top("ax")
        t.rename("jx")
        t.to_top("ay")
        t.rename("jy")
        t.push_int("jz", 1)
        t.set_domain("jz", DOM_REDUCED)

        (d - 2).downto(0) do |i|
          ec_jacobian_double(t)
          comb_emit_select(t, i, w, d)

          # ec_jacobian_add_affine_body documents its layout as
          # [..., ax, ay, jx, jy, jz] and replaces the accumulator IN PLACE at
          # the top. The selection leaves ax/ay above jz, so restore the
          # contract before the branch -- otherwise the add arm would reorder
          # the stack and the empty else arm would not, leaving the two arms
          # with different layouts at OP_ENDIF.
          t.to_top("_flag")
          t.to_alt
          t.to_top("jx")
          t.to_top("jy")
          t.to_top("jz")
          t.from_alt("_flag")

          t.pop_tracked # consumed by OP_IF
          add_ops = []
          add_emit = ->(o) { add_ops.push(o) }
          if safe[i]
            ec_build_jacobian_add_affine_inline(add_emit, t)
          else
            ec_build_jacobian_add_or_double_inline(add_emit, t)
          end
          emit.call(make_stack_op(op: "if", then: add_ops, else_ops: []))

          # The addend was selected fresh for this round; the add only copied it.
          t.to_top("ay")
          t.drop
          t.to_top("ax")
          t.drop
        end

        ec_jacobian_to_affine(t, "_rx", "_ry")

        entries.downto(1) do |j|
          t.to_top("_Ty#{j}")
          t.drop
          t.to_top("_Tx#{j}")
          t.drop
        end
        t.to_top("_k")
        t.drop

        ec_compose_point(t, "_rx", "_ry", "_result")
        t.release_constant(POOL_GROUP_N)
        t.release_constant(POOL_FIELD_P)
        true
      end

      # Emit the cheapest comb over the candidate window widths.
      #
      # Each candidate is rendered in full and scored with the same byte-cost
      # model the emitter is measured by, and the smallest wins -- the window
      # width is not hardcoded. w=1 is the binary ladder and is excluded; beyond
      # w=4 the 2^w selection logic outgrows the saving.
      #
      # @return [Array<Hash>, nil] nil when no candidate could be built, so the
      #   caller falls back to the ladder rather than emitting nothing
      def self.ec_emit_comb_best(opts = nil)
        best = nil
        [2, 3, 4].each do |w|
          ops = []
          next unless ec_emit_comb_mul_gen(->(o) { ops.push(o) }, w, opts)

          if best.nil? ||
             CostModel.estimate_script_bytes(ops) < CostModel.estimate_script_bytes(best)
            best = ops
          end
        end
        best
      end


      # Perform scalar multiplication G * k.
      #
      # Stack in: [scalar]
      # Stack out: [result_point]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_mul_gen(emit, opts = nil)
        # G is a compile-time constant, so this is the one secp256k1 call site
        # where a fixed-base comb applies. emit_ec_mul cannot use it: its base
        # arrives at run time.
        if opts && opts.fixed_base_comb
          ops = ec_emit_comb_best(opts)
          if ops
            ops.each { |o| emit.call(o) }
            return
          end
        end

        # Push generator point as 64-byte blob, then delegate to ecMul
        g_point = bigint_to_bytes32(EC_GEN_X) + bigint_to_bytes32(EC_GEN_Y)
        emit.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: g_point)))
        emit.call(make_stack_op(op: "swap")) # [point, scalar]
        emit_ec_mul(emit, opts)
      end

      # Negate a point (x, p - y).
      #
      # Stack in: [point]
      # Stack out: [negated_point]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_negate(emit, opts = nil)
        t = ECTracker.new(["_pt"], emit, opts)
        t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
        ec_decompose_point(t, "_pt", "_nx", "_ny")
        ec_push_field_p(t, "_fp")
        ec_field_sub(t, "_fp", "_ny", "_neg_y")
        ec_compose_point(t, "_nx", "_neg_y", "_result")
        t.release_constant(POOL_FIELD_P)
      end

      # Check if point is on secp256k1 (y^2 = x^3 + 7 mod p).
      #
      # Stack in: [point]
      # Stack out: [boolean]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_on_curve(emit, opts = nil)
        t = ECTracker.new(["_pt"], emit, opts)
        t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
        ec_decompose_point(t, "_pt", "_x", "_y")

        # GAP-301: coordinate canonicity. `ec_decompose_point` BIN2NUMs each
        # coordinate as an unsigned value that may be >= p; the field arithmetic
        # below would silently reduce it mod p, so a non-canonical encoding of a
        # valid point would pass. Reject it: require x < p AND y < p (coordinates
        # are unsigned, so the 0 <= lower bound holds by construction). Combined
        # with the curve equation at the end via OP_BOOLAND so ecOnCurve still
        # returns a boolean.
        t.copy_to_top("_x", "_x_lt")
        ec_push_field_p(t, "_p_for_x")
        t.raw_block(["_x_lt", "_p_for_x"], "_x_canon", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_LESSTHAN")) })
        t.copy_to_top("_y", "_y_lt")
        ec_push_field_p(t, "_p_for_y")
        t.raw_block(["_y_lt", "_p_for_y"], "_y_canon", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_LESSTHAN")) })
        t.to_top("_x_canon")
        t.to_top("_y_canon")
        t.raw_block(["_x_canon", "_y_canon"], "_canon", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })

        # lhs = y^2
        ec_field_sqr(t, "_y", "_y2")

        # rhs = x^3 + 7
        t.copy_to_top("_x", "_x_copy")
        ec_field_sqr(t, "_x", "_x2")
        ec_field_mul(t, "_x2", "_x_copy", "_x3")
        t.push_int("_seven", 7)
        ec_field_add(t, "_x3", "_seven", "_rhs")

        # Compare curve equation
        t.to_top("_y2")
        t.to_top("_rhs")
        t.raw_block(["_y2", "_rhs"], "_curve_eq", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_EQUAL")) })

        # on-curve = canonical AND curve-equation
        t.to_top("_canon")
        t.to_top("_curve_eq")
        t.raw_block(["_canon", "_curve_eq"], "_result", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })
        t.release_constant(POOL_FIELD_P)
      end

      # Compute ((value % mod) + mod) % mod.
      #
      # Stack in: [value, mod]
      # Stack out: [result]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_mod_reduce(emit)
        emit.call(make_stack_op(op: "opcode", code: "OP_2DUP"))
        emit.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(make_stack_op(op: "rot"))
        emit.call(make_stack_op(op: "drop"))
        emit.call(make_stack_op(op: "over"))
        emit.call(make_stack_op(op: "opcode", code: "OP_ADD"))
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "opcode", code: "OP_MOD"))
      end

      # Encode a point as a 33-byte compressed pubkey.
      #
      # Stack in: [point (64 bytes)]
      # Stack out: [compressed (33 bytes)]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_encode_compressed(emit)
        # Split at 32: [x_bytes, y_bytes]
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        # Get last byte of y for parity
        emit.call(make_stack_op(op: "opcode", code: "OP_SIZE"))
        emit.call(make_stack_op(op: "push", value: big_int_push(1)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SUB"))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        # Stack: [x_bytes, y_prefix, last_byte]
        emit.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        emit.call(make_stack_op(op: "push", value: big_int_push(2)))
        emit.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        # Stack: [x_bytes, y_prefix, parity]
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "drop")) # drop y_prefix
        # Stack: [x_bytes, parity]
        emit.call(make_stack_op(
          op: "if",
          then: [make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x03".b))],
          else_ops: [make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x02".b))]
        ))
        # Stack: [x_bytes, prefix_byte]
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
      end

      # Convert (x: bigint, y: bigint) to a 64-byte Point.
      #
      # Stack in: [x_num, y_num] (y on top)
      # Stack out: [point_bytes (64 bytes)]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_make_point(emit)
        # Convert y to 32 bytes big-endian
        emit.call(make_stack_op(op: "push", value: big_int_push(33)))
        emit.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "drop"))
        ec_emit_reverse32(emit)
        # Stack: [x_num, y_be]
        emit.call(make_stack_op(op: "swap"))
        # Stack: [y_be, x_num]
        emit.call(make_stack_op(op: "push", value: big_int_push(33)))
        emit.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "drop"))
        ec_emit_reverse32(emit)
        # Stack: [y_be, x_be]
        emit.call(make_stack_op(op: "swap"))
        # Stack: [x_be, y_be]
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
      end

      # Extract the x-coordinate from a Point.
      #
      # Stack in: [point (64 bytes)]
      # Stack out: [x as bigint]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_point_x(emit)
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "drop"))
        ec_emit_reverse32(emit)
        # Append 0x00 sign byte to ensure unsigned interpretation
        emit.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
        emit.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
      end

      # Extract the y-coordinate from a Point.
      #
      # Stack in: [point (64 bytes)]
      # Stack out: [y as bigint]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_point_y(emit)
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "drop"))
        ec_emit_reverse32(emit)
        # Append 0x00 sign byte to ensure unsigned interpretation
        emit.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
        emit.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
      end

      # =================================================================
      # Dispatch table (called from stack.rb)
      # =================================================================

      EC_BUILTIN_NAMES = %w[
        ecAdd ecMul ecMulGen
        ecNegate ecOnCurve ecModReduce
        ecEncodeCompressed ecMakePoint
        ecPointX ecPointY
      ].to_set.freeze

      # Return true if name is a recognized EC builtin function.
      #
      # @param name [String]
      # @return [Boolean]
      def self.is_ec_builtin(name)
        EC_BUILTIN_NAMES.include?(name)
      end

      EC_DISPATCH = {
        "ecAdd" => method(:emit_ec_add),
        "ecMul" => method(:emit_ec_mul),
        "ecMulGen" => method(:emit_ec_mul_gen),
        "ecNegate" => method(:emit_ec_negate),
        "ecOnCurve" => method(:emit_ec_on_curve),
        "ecModReduce" => method(:emit_ec_mod_reduce),
        "ecEncodeCompressed" => method(:emit_ec_encode_compressed),
        "ecMakePoint" => method(:emit_ec_make_point),
        "ecPointX" => method(:emit_ec_point_x),
        "ecPointY" => method(:emit_ec_point_y),
      }.freeze

      # Call the appropriate EC emit function for func_name.
      #
      # @param func_name [String]
      # @param emit [Proc] callback receiving a StackOp hash
      # @raise [RuntimeError] if func_name is not a known EC builtin
      # Emitters the size flags cannot reach take no options argument. Passing
      # one anyway would be a silent no-op today and a latent divergence the day
      # someone gives them a body -- so the split is explicit.
      EC_FLAG_AWARE = %w[ecAdd ecMul ecMulGen ecNegate ecOnCurve].freeze

      def self.dispatch_ec_builtin(func_name, emit, opts = nil)
        fn = EC_DISPATCH[func_name]
        raise "unknown EC builtin: #{func_name}" if fn.nil?

        if EC_FLAG_AWARE.include?(func_name)
          fn.call(emit, opts)
        else
          fn.call(emit)
        end
      end
    end
  end
end
