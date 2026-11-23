# frozen_string_literal: true

require "set"
require_relative "../frontend/locktime_domain"
require_relative "preimage_rules"

# D26 on --ir input. Port of assertIrLocktimeDomain in
# packages/runar-compiler/src/passes/locktime-domain.ts: --ir skips typecheck,
# so the rule is re-derived from the ANF of every public method (stateless and
# stateful): a bin_op gate whose operand resolves (through load_const "@ref:"
# aliases) to a call extractLocktime, and an assert whose value resolves to a
# pin compare, or to the && lowering (a value +if+ whose else arm is the
# constant false) of a chain with a pin conjunct. Run right after the D15
# preimage rules.
module RunarCompiler
  module IR
    module LocktimeDomain
      LD = Frontend::LocktimeDomain

      # bs[i] is the ANF image of currentBlockHeight() (anf_lower.rb): a call
      # extractLocktime followed in the same block by load_const 500000000;
      # bin_op < (bs[i], that const); assert (that compare). The assert runs on
      # every path through the block before any later use, so the read is a
      # height by construction and the --ir path does not count it as a
      # locktime read (nothing derived from it is a gate), as the source path
      # does not count currentBlockHeight(). Its assert still counts as a pin.
      # Matches only that exact four-binding shape. Mirrors
      # isSelfPinnedLocktimeRead.
      def self.self_pinned_read?(bs, i)
        return false unless bs.is_a?(Array) && i + 3 < bs.length

        r, l, c, a = bs[i], bs[i + 1], bs[i + 2], bs[i + 3]
        return false if [r, l, c, a].any? { |b| b.value.nil? }

        rv, lv, cv, av = r.value, l.value, c.value, a.value
        rv.kind == "call" && rv.func == "extractLocktime" &&
          lv.kind == "load_const" && lv.const_bool.nil? && lv.const_big_int == 500_000_000 &&
          cv.kind == "bin_op" && cv.op == "<" && cv.left == r.name && cv.right == l.name &&
          av.kind == "assert" && av.value_ref == c.name
      end

      def self.reads?(bindings)
        (bindings || []).each_with_index.any? do |b, i|
          v = b.value
          next false if v.nil?

          case v.kind
          when "call" then v.func == "extractLocktime" && !self_pinned_read?(bindings, i)
          when "if" then reads?(v.then) || reads?(v.else_)
          when "loop" then reads?(v.body)
          else false
          end
        end
      end

      # The D26 text for the first public method with an unpinned gate.
      def self.error(program)
        methods = program.methods || []
        # Prefilter (as contract_reads_locktime?): no extractLocktime call that
        # is not currentBlockHeight()'s self-pinned one, no gate.
        return nil unless methods.any? { |m| reads?(m.body) }

        privates = {}
        methods.each { |m| privates[m.name] = m if !m.is_public && m.name != "constructor" }
        exits_of = {}
        in_progress = Set.new
        exits = lambda do |m, arg_levels|
          params, sig = LD.helper_params(m.params, arg_levels)
          key = [m.name, sig]
          next exits_of[key] if exits_of.key?(key)
          next LD::FRESH if in_progress.include?(m.name)

          in_progress.add(m.name)
          helper = ->(name, levels) { privates[name] && exits.call(privates[name], levels) }
          ex = Gates.new(m, params, helper).run(m.body, LD::FRESH)
          in_progress.delete(m.name)
          exits_of[key] = ex
        end
        methods.each do |m|
          next if !m.is_public || m.name == "constructor"
          return LD.locktime_domain_message(m.name) if LD.unpinned?(exits.call(m, []))
        end
        nil
      end

      def self.assert!(program)
        err = error(program)
        raise ArgumentError, "IR validation: #{err}" if err
      end

      def self.const_false_arm?(arm)
        return false unless arm.is_a?(Array) && arm.length == 1

        v = arm[0].value
        !v.nil? && v.kind == "load_const" && v.const_bool == false
      end

      class Gates
        def initialize(method, params, helper_exits)
          @helper_exits = helper_exits
          # Every binding of the method, by name (a name bound more than once
          # keeps all its values).
          @defs = {}
          # currentBlockHeight()'s reads (no locktime reads) and their bin_op <
          # compares, whose assert still pins the domain on its path (the pin
          # bounds the transaction's nLockTime, whichever read it is spelled
          # on). By identity.
          self_pinned = Set.new.compare_by_identity
          @self_pin_compares = Set.new.compare_by_identity
          index = lambda do |bs|
            (bs || []).each_with_index do |b, i|
              v = b.value
              next if v.nil?

              if LocktimeDomain.self_pinned_read?(bs, i)
                self_pinned << v
                @self_pin_compares << bs[i + 2].value
              end

              (@defs[b.name] ||= []) << v
              if v.kind == "if"
                index.call(v.then)
                index.call(v.else_)
              elsif v.kind == "loop"
                index.call(v.body)
              end
            end
          end
          index.call(method.body)
          binds = []
          @defs.each { |n, vs| vs.each { |v| binds << [n, v] } }
          last = ->(arm) { arm.is_a?(Array) && !arm.empty? ? arm[-1].name : nil }
          ref = ->(v) { PreimageRules.ref_target(v) }
          tainted = lambda do |v, t|
            r = ref.call(v)
            next t.include?(r) unless r.nil?

            case v.kind
            when "call"
              (v.func == "extractLocktime" && !self_pinned.include?(v)) || (v.args || []).any? { |a| t.include?(a) }
            when "load_param" then (params[v.name] || LD::NONE) != LD::NONE
            when "bin_op" then LD::PROPAGATE.include?(v.op) && (t.include?(v.left) || t.include?(v.right))
            when "unary_op" then LD::PROPAGATE_UNARY.include?(v.op) && t.include?(v.operand)
            when "if" then [last.call(v.then), last.call(v.else_)].any? { |n| !n.nil? && t.include?(n) }
            else false
            end
          end
          direct = lambda do |v, d|
            r = ref.call(v)
            next d.include?(r) unless r.nil?

            case v.kind
            when "call" then v.func == "extractLocktime" && !self_pinned.include?(v)
            when "load_param" then params[v.name] == LD::DIRECT
            else false
            end
          end
          @taint = LD.solve_taint(binds, tainted, direct)
        end

        def run(bs, states)
          s = states
          (bs || []).each do |b|
            v = b.value
            next if v.nil?

            case v.kind
            when "bin_op" then s = LD.or_all(s, LD::G) if compare(v) == :gate
            when "assert" then s = LD.or_all(s, LD::P) if asserted_pin?(v.value_ref, Set.new)
            when "method_call"
              ex = @helper_exits.call(v.method, (v.args || []).map { |a| level(a) })
              s = LD.compose(s, ex) if ex
            when "if" then s = run(v.then, s) | run(v.else_, s)
            when "loop" then s |= run(v.body, s)
            end
          end
          s
        end

        private

        def level(name)
          @taint[name] || LD::NONE
        end

        def literal(name, seen = Set.new)
          return nil if name.nil? || !seen.add?(name)

          vs = @defs[name] || []
          return nil unless vs.length == 1

          v = vs[0]
          return nil unless v.kind == "load_const"
          return v.const_big_int if !v.const_big_int.nil? && v.const_bool.nil?

          r = PreimageRules.ref_target(v)
          r.nil? ? nil : literal(r, seen)
        end

        def compare(v)
          return :none unless v.kind == "bin_op"

          LD.classify_compare(v.op, v.left, v.right, method(:level), ->(x) { literal(x) })
        end

        # Does assert(name) imply a pin?
        def asserted_pin?(name, seen)
          return false if name.nil? || !seen.add?(name)

          vs = @defs[name] || []
          return false unless vs.length == 1

          v = vs[0]
          return true if compare(v) == :pin || @self_pin_compares.include?(v)

          r = PreimageRules.ref_target(v)
          return asserted_pin?(r, seen) unless r.nil?

          # a && b lowers to: if a then [..., b] else [false].
          if v.kind == "if" && LocktimeDomain.const_false_arm?(v.else_) && v.then.is_a?(Array) && !v.then.empty?
            return asserted_pin?(v.cond, seen) || asserted_pin?(v.then[-1].name, seen)
          end
          false
        end
      end
    end
  end
end
