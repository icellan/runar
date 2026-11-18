# frozen_string_literal: true

require "set"
require_relative "../frontend/continuation_rules"

# D18 on --ir input. Port of assertIrNoDroppedContinuation in
# packages/runar-compiler/src/passes/continuation-rules.ts: --ir skips
# typecheck, so the rule is re-derived from the ANF, per path. A public method
# of a StatefulSmartContract program that declares an output (add_output /
# add_raw_output, at any depth and through method_calls to private methods)
# and has a path that reaches an update_prop but no add_output is refused with
# the source path's text. Path states are the bits {W = update_prop reached,
# A = add_output reached}: +if+ unions its arms (a missing arm is identity), a
# loop unions with skipping it, a method_call to a private method composes
# with that method's exit states. Run after the N-101 stateful-scaffolding check.
# D27 rides the same walk (bit D = update_prop since the last add_output): a
# path whose last add_output is followed by an update_prop is refused with
# D18's sibling text; D18 wins when a method has both.
module RunarCompiler
  module IR
    module ContinuationRules
      def self.error(program)
        privates = {}
        (program.methods || []).each do |m|
          privates[m.name] = m if !m.is_public && m.name != "constructor"
        end
        (program.methods || []).each do |m|
          next if !m.is_public || m.name == "constructor"

          case verdict(m, privates)
          when :dropped then return Frontend::ContinuationRules.dropped_continuation_message(m.name)
          when :dead_write then return Frontend::ContinuationRules.dead_state_write_message(m.name)
          end
        end
        nil
      end

      ZERO = Frontend::ContinuationRules::ZERO

      # :dropped (D18), :dead_write (D27) or nil.
      def self.verdict(method, privates)
        return nil unless declares_output?(method, privates)

        exits = helper_exits(method, privates)
        Frontend::ContinuationRules.verdict(run(method.body || [], ZERO, privates, exits))
      end

      # Any add_output / add_raw_output, at any depth, through method_calls.
      # Explicit work list (no host recursion on deep nesting).
      def self.declares_output?(method, privates)
        visited = Set.new
        work = [method.body || []]
        until work.empty?
          (work.pop || []).each do |b|
            v = b.value
            next if v.nil?
            return true if %w[add_output add_raw_output].include?(v.kind)

            if v.kind == "method_call"
              target = privates[v.method]
              work << (target.body || []) if target && visited.add?(target.name)
            end
            [v.then, v.else_, v.body].each { |inner| work << inner if inner.is_a?(Array) }
          end
        end
        false
      end

      # Private methods a binding list calls, at any depth.
      def self.callees(bindings, privates)
        out = []
        work = [bindings]
        until work.empty?
          (work.pop || []).each do |b|
            v = b.value
            next if v.nil?

            out << privates[v.method] if v.kind == "method_call" && privates[v.method]
            [v.then, v.else_, v.body].each { |inner| work << inner if inner.is_a?(Array) }
          end
        end
        out.uniq(&:name)
      end

      # Exit states of every private method reachable from +method+, computed
      # bottom-up by an explicit post-order (N-264: no host recursion across
      # helper chains). A cyclic helper stays unresolved and contributes {0}.
      def self.helper_exits(method, privates)
        exits = {}
        open = Set.new
        stack = [[nil, callees(method.body || [], privates)]]
        until stack.empty?
          helper, todo = stack.last
          nxt = todo.find { |m| !exits.key?(m.name) && !open.include?(m.name) }
          if nxt
            open.add(nxt.name)
            stack << [nxt, callees(nxt.body || [], privates)]
          else
            stack.pop
            next if helper.nil?

            exits[helper.name] = run(helper.body || [], ZERO, privates, exits)
            open.delete(helper.name)
          end
        end
        exits
      end

      def self.run(bindings, states, privates, exits)
        s = states
        bindings.each do |b|
          v = b.value
          next if v.nil?

          case v.kind
          when "update_prop" then s = Frontend::ContinuationRules.write(s)
          when "add_output" then s = Frontend::ContinuationRules.add_output(s)
          when "method_call"
            s = Frontend::ContinuationRules.compose(s, exits[v.method] || ZERO) if privates[v.method]
          else
            if v.then.is_a?(Array) || v.else_.is_a?(Array)
              t = v.then.is_a?(Array) ? run(v.then, s, privates, exits) : s
              e = v.else_.is_a?(Array) ? run(v.else_, s, privates, exits) : s
              s = t | e
            elsif v.body.is_a?(Array)
              s |= run(v.body, s, privates, exits)
            end
          end
        end
        s
      end

      def self.assert!(program)
        err = error(program)
        raise ArgumentError, "IR validation: #{err}" if err
      end
    end
  end
end
