# frozen_string_literal: true

require "set"
require_relative "../frontend/continuation_rules"

# D18 on --ir input. Port of assertIrNoDroppedContinuation in
# packages/runar-compiler/src/passes/continuation-rules.ts: --ir skips
# typecheck, so the rule is re-derived from the ANF. A public method of a
# StatefulSmartContract program whose bindings reach an update_prop and an
# add_raw_output but no add_output -- at any depth (if arms, loop body) and
# through method_calls to private methods -- is refused with the source
# path's text. Run after the N-101 stateful-scaffolding check.
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
          next unless drops_continuation?(m, privates)

          return Frontend::ContinuationRules.dropped_continuation_message(m.name)
        end
        nil
      end

      def self.drops_continuation?(method, privates)
        seen = { writes: false, raw: false, add: false }
        visited = Set.new
        # Explicit work list (no host recursion on deep nesting).
        work = [method.body || []]
        until work.empty?
          (work.pop || []).each do |b|
            v = b.value
            next if v.nil?

            case v.kind
            when "update_prop" then seen[:writes] = true
            when "add_raw_output" then seen[:raw] = true
            when "add_output" then seen[:add] = true
            when "method_call"
              target = privates[v.method]
              if target && !visited.include?(target.name)
                visited.add(target.name)
                work << (target.body || [])
              end
            end
            [v.then, v.else_, v.body].each { |inner| work << inner if inner.is_a?(Array) }
          end
        end
        seen[:writes] && seen[:raw] && !seen[:add]
      end

      def self.assert!(program)
        err = error(program)
        raise ArgumentError, "IR validation: #{err}" if err
      end
    end
  end
end
