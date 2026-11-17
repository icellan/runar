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

      # Per-method view: bindings by name, names bound more than once.
      class View
        attr_reader :defs, :dup

        def initialize(method, implicit_tx)
          @defs = {}
          @dup = Set.new
          collect(method.body)
          @shp = (method.params || []).select { |p| p.type == SHP }.map(&:name).to_set
          own = (method.params || []).any? { |p| p.name == "txPreimage" }
          @implicit = !method.is_public && implicit_tx && !own
        end

        def collect(bindings)
          (bindings || []).each do |b|
            @dup << b.name if @defs.key?(b.name)
            @defs[b.name] = b.value
            if b.value.kind == "if"
              collect(b.value.then)
              collect(b.value.else_)
            elsif b.value.kind == "loop"
              collect(b.value.body)
            end
          end
        end

        def resolve(name)
          seen = Set.new
          until name.nil? || @dup.include?(name) || seen.include?(name)
            seen << name
            v = @defs[name]
            return nil if v.nil?

            case v.kind
            when "load_param"
              return v.name if @shp.include?(v.name)

              return @implicit && v.name == "txPreimage" ? v.name : nil
            when "load_prop"
              return @implicit && v.name == "txPreimage" ? v.name : nil
            end
            name = PreimageRules.ref_target(v)
          end
          nil
        end

        def truth_checks(name, seen)
          return Set.new if name.nil? || @dup.include?(name) || seen.include?(name)

          seen << name
          v = @defs[name]
          return Set.new if v.nil?

          case v.kind
          when "check_preimage"
            o = resolve(v.preimage)
            o.nil? ? Set.new : Set[o]
          when "load_const"
            return nil if v.const_bool == false

            nxt = PreimageRules.ref_target(v)
            nxt.nil? ? Set.new : truth_checks(nxt, seen)
          when "if"
            return Set.new if (v.results || []).any? || (v.then || []).empty? || (v.else_ || []).empty?

            t = PreimageRules.union(truth_checks(v.cond, seen), truth_checks(v.then.last.name, seen))
            PreimageRules.intersect(t, truth_checks(v.else_.last.name, seen))
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
          walk = lambda do |bindings, done_in|
            done = done_in.dup
            (bindings || []).each do |b|
              v = b.value
              case v.kind
              when "assert"
                c = mv.truth_checks(v.value_ref, Set.new)
                done |= c unless c.nil?
              when "if"
                done = walk.call(v.then, done) & walk.call(v.else_, done)
              when "method_call"
                target = privates[v.method]
                next if target.nil?

                checked = must_checked.call(target, inner)
                args = v.args || []
                (target.params || []).each_with_index do |p, i|
                  next unless checked.include?(p.name) && i < args.length

                  o = mv.resolve(args[i])
                  done << o unless o.nil?
                end
              end
            end
            done
          end
          memo[m] = walk.call(m.body, Set.new)
        end

        program.methods.each do |m|
          next if m.name == "constructor"

          mv = View.new(m, implicit_tx)
          visit = nil
          visit = lambda do |bindings|
            (bindings || []).each do |b|
              v = b.value
              args = v.args || []
              case v.kind
              when "call"
                if Frontend::PREIMAGE_EXTRACTORS.include?(v.func) && mv.resolve(args[0]).nil?
                  errors << Frontend.unchecked_preimage_arg_message(v.func)
                end
              when "method_call"
                target = privates[v.method]
                if !target.nil? &&
                   (target.params || []).each_with_index.any? { |p, i| p.type == SHP && mv.resolve(args[i]).nil? }
                  errors << Frontend.unchecked_preimage_arg_message(target.name)
                end
              when "if"
                visit.call(v.then)
                visit.call(v.else_)
              when "loop"
                visit.call(v.body)
              end
            end
          end
          visit.call(m.body)
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
