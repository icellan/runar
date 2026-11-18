# frozen_string_literal: true

# #199 (warning) and D18 (error): where a StatefulSmartContract's satoshis can
# go. Port of packages/runar-compiler/src/passes/continuation-rules.ts (see
# its header for the full rationale). Both rules read the method effects
# anf_lower.rb's transitive continuation predicates compute, so they see
# exactly the effects the continuation is injected from. anf_lower.rb is
# wire-format gated, so the one new predicate (calls addOutput, as opposed to
# addOutput OR addRawOutput) lives here, mirroring _expr_has_add_output's
# callee matching exactly.
#
# Like typecheck.rb, this file reaches anf_lower.rb's private predicates via
# +send+ and requires anf_lower.rb lazily (anf_lower.rb requires validator.rb
# and typecheck.rb, so a top-level require here would be circular).

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"

module RunarCompiler
  module Frontend
    module ContinuationRules
      # #199: the shared warning text.
      def self.release_trap_message(contract)
        "contract '#{contract}' has no terminal method and no public method that calls " \
          "addOutput/addRawOutput; its satoshis can never leave instances of '#{contract}'"
      end

      # D18: the shared error text.
      def self.dropped_continuation_message(method)
        "method '#{method}' writes contract state but emits no state continuation: it calls " \
          "addRawOutput() without addOutput(), and a method that declares its own outputs gets no " \
          "auto-injected continuation, so the state write would be lost and the contract's satoshis " \
          "would leave with the spend. Add this.addOutput(satoshis, ...) to carry the new state, or " \
          "stop writing state in a method meant to end the contract"
      end

      def self.fe
        require_relative "anf_lower"
        RunarCompiler::Frontend
      end

      # Calls this.addOutput(...) itself, directly or through a private helper.
      def self.calls_add_output?(method, contract)
        q = fe.const_get(:CalleeQueue).new(Set.new)
        nxt = method.body || []
        until nxt.nil?
          return true if nxt.any? { |s| stmt_calls_add_output?(s, contract, q) }

          nxt = q.pending.shift
        end
        false
      end

      def self.stmt_calls_add_output?(stmt, contract, q)
        return true if fe.send(:_statement_expressions, stmt).any? { |e| expr_calls_add_output?(e, contract, q) }

        fe.send(:_child_statements, stmt).any? { |s| stmt_calls_add_output?(s, contract, q) }
      end

      def self.expr_calls_add_output?(expr, contract, q)
        return false if expr.nil?

        if expr.is_a?(CallExpr)
          callee = expr.callee
          return true if callee.is_a?(PropertyAccessExpr) && callee.property == "addOutput"
          if callee.is_a?(MemberExpr) && callee.object.is_a?(Identifier) &&
             callee.object.name == "this" && callee.property == "addOutput"
            return true
          end

          q.enqueue(fe.send(:_resolve_private_method, callee, contract))
        end
        fe.send(:_child_expressions, expr).any? { |e| expr_calls_add_output?(e, contract, q) }
      end

      # _method_mutates_state OR a write to an element of a mutable property
      # (this.arr[i] = v, this.arr[i]++, this.grid[i][j] = v). Both rules run
      # before FixedArray expansion (pass 3b), where an element write is still
      # an IndexAccessExpr target that anf_lower's walk (built for the expanded
      # contract) does not count.
      def self.mutates_state?(method, contract)
        fe.send(:_method_mutates_state, method, contract) || writes_mutable_element?(method, contract)
      end

      # Port of side-effect-summary.ts writesMutableProperty, element form only.
      def self.mutable_element?(target, mutable_props)
        return false unless target.is_a?(IndexAccessExpr)

        t = target
        t = t.object while t.is_a?(IndexAccessExpr)
        t.is_a?(PropertyAccessExpr) && mutable_props.include?(t.property)
      end

      # Element-write walk; same descent as anf_lower's _method_mutates_state
      # (statement and expression children, private callees queued for any
      # CallExpr, ++/-- not descended into).
      def self.writes_mutable_element?(method, contract)
        mutable_props = Set.new
        contract.properties.each { |p| mutable_props.add(p.name) unless p.readonly }
        return false if mutable_props.empty?

        q = fe.const_get(:CalleeQueue).new(Set.new)
        nxt = method.body || []
        until nxt.nil?
          return true if nxt.any? { |s| stmt_writes_element?(s, mutable_props, contract, q) }

          nxt = q.pending.shift
        end
        false
      end

      def self.stmt_writes_element?(stmt, mutable_props, contract, q)
        return true if stmt.is_a?(AssignmentStmt) && mutable_element?(stmt.target, mutable_props)
        return true if fe.send(:_statement_expressions, stmt).any? { |e| expr_writes_element?(e, mutable_props, contract, q) }

        fe.send(:_child_statements, stmt).any? { |s| stmt_writes_element?(s, mutable_props, contract, q) }
      end

      def self.expr_writes_element?(expr, mutable_props, contract, q)
        return false if expr.nil?
        return mutable_element?(expr.operand, mutable_props) if expr.is_a?(IncrementExpr) || expr.is_a?(DecrementExpr)

        q.enqueue(fe.send(:_resolve_private_method, expr.callee, contract)) if expr.is_a?(CallExpr)
        fe.send(:_child_expressions, expr).any? { |e| expr_writes_element?(e, mutable_props, contract, q) }
      end

      # D18: the method writes state and only raw outputs replace its continuation.
      def self.drops_continuation?(method, contract)
        mutates_state?(method, contract) &&
          fe.send(:_method_has_add_output, method, contract) &&
          !calls_add_output?(method, contract)
      end

      # #199: the contract-level warning, when it applies (stateful contracts only).
      def self.release_trap_warning(contract)
        return nil unless contract.parent_class == "StatefulSmartContract"

        publics = contract.methods.select { |m| m.visibility == "public" }
        return nil if publics.empty?

        trapped = publics.all? do |m|
          mutates = mutates_state?(m, contract)
          state_out = fe.send(:_method_has_add_output, m, contract)
          data_out = fe.send(:_method_has_add_data_output, m, contract)
          # needsChange (not terminal) and no declared state/raw output.
          (mutates || state_out || data_out) && !state_out
        end
        return nil unless trapped

        # Contract-level: no source location of its own.
        Diagnostic.new(message: release_trap_message(contract.name), severity: Severity::WARNING)
      end
    end
  end
end
