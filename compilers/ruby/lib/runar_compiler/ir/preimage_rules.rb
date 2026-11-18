# frozen_string_literal: true

require "set"
require_relative "../frontend/validator"
require_relative "../frontend/typecheck"

# D15: the preimage rules on --ir input. Port of
# packages/runar-compiler/src/passes/ir-preimage-rules.ts (see its header for
# the full rule and for what ANF cannot carry). --ir skips the frontend, so D9
# (no SigHashPreimage property), GK-GAP-010 (a public method's SigHashPreimage
# parameter is asserted on every path) and D14 (an extractor reads only a
# checked preimage) are re-derived here, failing closed.
module RunarCompiler
  module IR
    module PreimageRules
      SHP = "SigHashPreimage"

      # nil stands for "everything" (what a constant-false arm implies).
      def self.union(a, b)
        a.nil? || b.nil? ? nil : a | b
      end

      def self.intersect(a, b)
        return b if a.nil?
        return a if b.nil?

        a & b
      end

      def self.ref_target(v)
        s = v.const_string
        v.kind == "load_const" && s.is_a?(String) && s.start_with?("@ref:") ? s[5..] : nil
      end

      THEN = -1
      ELSE = -2
      BODY = -3

      # Is the binding at def_path in scope at from_path? Only if it sits
      # earlier in the same list or in a list enclosing it: stack lowering
      # resolves names by position, so a binding after (or beside) a use never
      # answers for it.
      def self.visible?(def_path, from_path)
        n = def_path.length
        return false if from_path.length < n || def_path[0...(n - 1)] != from_path[0...(n - 1)]

        def_path[n - 1] < from_path[n - 1]
      end

      # Per-method view: bindings by name with their positions.
      class View
        def initialize(method, implicit_tx)
          @defs = {}
          # A name bound more than once, or under a parameter's name (the
          # parameter slot answers to it too), never resolves.
          @poisoned = (method.params || []).map(&:name).to_set
          collect(method.body, [])
          @shp = (method.params || []).select { |p| p.type == SHP }.map(&:name).to_set
          own = (method.params || []).any? { |p| p.name == "txPreimage" }
          @implicit = !method.is_public && implicit_tx && !own
        end

        def collect(bindings, at)
          (bindings || []).each_with_index do |b, i|
            path = at + [i]
            @poisoned << b.name if @defs.key?(b.name)
            @defs[b.name] = [b.value, path]
            if b.value.kind == "if"
              collect(b.value.then, path + [THEN])
              collect(b.value.else_, path + [ELSE])
            elsif b.value.kind == "loop"
              collect(b.value.body, path + [BODY])
            end
          end
        end

        def lookup(name, from_path)
          return nil if name.nil? || @poisoned.include?(name)

          d = @defs[name]
          d && PreimageRules.visible?(d[1], from_path) ? d : nil
        end

        def resolve(name, from_path)
          (@defs.size + 1).times do
            d = lookup(name, from_path)
            return nil if d.nil?

            v, path = d
            case v.kind
            when "load_param"
              return v.name if @shp.include?(v.name)

              return @implicit && v.name == "txPreimage" ? v.name : nil
            when "load_prop"
              return @implicit && v.name == "txPreimage" ? v.name : nil
            end
            name = PreimageRules.ref_target(v)
            from_path = path
          end
          nil
        end

        def truth_of(name, from_path, depth = 0)
          d = lookup(name, from_path)
          d.nil? ? Set.new : truth_value(d[0], d[1], depth)
        end

        def truth_value(v, path, depth)
          return Set.new if depth > @defs.size

          case v.kind
          when "check_preimage"
            o = resolve(v.preimage, path)
            o.nil? ? Set.new : Set[o]
          when "load_const"
            return nil if v.const_bool == false

            nxt = PreimageRules.ref_target(v)
            nxt.nil? ? Set.new : truth_of(nxt, path, depth + 1)
          when "if"
            return Set.new if (v.results || []).any? || (v.then || []).empty? || (v.else_ || []).empty?

            nt = v.then.length - 1
            ne = v.else_.length - 1
            t = PreimageRules.union(truth_of(v.cond, path, depth + 1),
                                    truth_value(v.then[nt].value, path + [THEN, nt], depth + 1))
            PreimageRules.intersect(t, truth_value(v.else_[ne].value, path + [ELSE, ne], depth + 1))
          else
            Set.new
          end
        end
      end

      def self.errors(program)
        errors = (program.properties || []).select { |p| p.type == SHP }
                                           .map { |p| Frontend.preimage_property_message(p.name) }
        # A method_call resolves exactly as stack lowering inlines it: to the
        # LAST non-public, non-constructor method of that name
        # (codegen/stack.rb). The loader refuses duplicate names first; this
        # never relies on that alone.
        privates = {}
        program.methods.each { |m| privates[m.name] = m if !m.is_public && m.name != "constructor" }
        publics = program.methods.select { |m| m.is_public && m.name != "constructor" }
        implicit_tx = !publics.empty? &&
                      publics.all? { |m| (m.params || []).any? { |p| p.name == "txPreimage" && p.type == SHP } } &&
                      (program.properties || []).none? { |p| p.name == "txPreimage" }
        memo = {}.compare_by_identity # keyed by method identity, never by name
        must_checked = nil
        must_checked = lambda do |m, stack|
          return memo[m] if memo.key?(m)
          return Set.new if stack.any? { |s| s.equal?(m) }

          mv = View.new(m, implicit_tx)
          inner = stack + [m]
          walk = nil
          walk = lambda do |bindings, at, done_in|
            done = done_in.dup
            (bindings || []).each_with_index do |b, bi|
              path = at + [bi]
              v = b.value
              case v.kind
              when "assert"
                c = mv.truth_of(v.value_ref, path)
                done |= c unless c.nil?
              when "if"
                done = walk.call(v.then, path + [THEN], done) & walk.call(v.else_, path + [ELSE], done)
              when "method_call"
                target = privates[v.method]
                next if target.nil?

                checked = must_checked.call(target, inner)
                args = v.args || []
                (target.params || []).each_with_index do |p, i|
                  next unless checked.include?(p.name) && i < args.length

                  o = mv.resolve(args[i], path)
                  done << o unless o.nil?
                end
              end
            end
            done
          end
          memo[m] = walk.call(m.body, [], Set.new)
        end

        program.methods.each do |m|
          next if m.name == "constructor"

          mv = View.new(m, implicit_tx)
          visit = nil
          visit = lambda do |bindings, at|
            (bindings || []).each_with_index do |b, bi|
              path = at + [bi]
              v = b.value
              args = v.args || []
              case v.kind
              when "call"
                if Frontend::PREIMAGE_EXTRACTORS.include?(v.func) && mv.resolve(args[0], path).nil?
                  errors << Frontend.unchecked_preimage_arg_message(v.func)
                end
              when "method_call"
                target = privates[v.method]
                if !target.nil? &&
                   (target.params || []).each_with_index.any? { |p, i| p.type == SHP && mv.resolve(args[i], path).nil? }
                  errors << Frontend.unchecked_preimage_arg_message(target.name)
                end
              when "if"
                visit.call(v.then, path + [THEN])
                visit.call(v.else_, path + [ELSE])
              when "loop"
                visit.call(v.body, path + [BODY])
              end
            end
          end
          visit.call(m.body, [])
          next unless m.is_public

          done = must_checked.call(m, [])
          (m.params || []).each do |p|
            errors << Frontend.preimage_not_checked_message(m.name, p.name) if p.type == SHP && !done.include?(p.name)
          end
        end
        errors
      end

      # GK-BUG-015's shared text on the IR path: a repeated method name,
      # refused before anything looks a method up by name (the source
      # validator refuses it; --ir did not, so two bodies could share a name).
      def self.assert_unique_method_names!(program)
        seen = Set.new
        program.methods.each do |m|
          if seen.include?(m.name)
            raise ArgumentError,
                  "IR validation: method '#{m.name}' is already declared in this contract and cannot be re-declared"
          end

          seen << m.name
        end
      end

      def self.assert!(program)
        errs = errors(program)
        raise ArgumentError, "IR validation: #{errs.join('; ')}" unless errs.empty?
      end
    end
  end
end
