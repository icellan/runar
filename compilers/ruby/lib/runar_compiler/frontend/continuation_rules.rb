# frozen_string_literal: true

# #199 (warning) and D18 (error): where a StatefulSmartContract's satoshis can
# go. Port of packages/runar-compiler/src/passes/continuation-rules.ts (see
# its header for the full rationale). Both rules read the method effects
# anf_lower.rb's transitive continuation predicates compute, so they see
# exactly the effects the continuation is injected from. anf_lower.rb is
# wire-format gated, so D18's per-path analysis (SourcePaths below) lives
# here, mirroring _expr_has_add_output's callee matching exactly.
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
        "method '#{method}' writes contract state on a path that reaches no addOutput(): a method " \
          "that declares its own outputs (addOutput/addRawOutput) gets no auto-injected continuation, " \
          "so on that path the state write would be lost and the contract's satoshis would leave with " \
          "the spend. Add this.addOutput(satoshis, ...) on every path that writes state, or stop " \
          "writing state on a path meant to end the contract"
      end

      # D27: the shared error text (D18's sibling, same family).
      def self.dead_state_write_message(method)
        "method '#{method}' writes contract state after the last addOutput() on a path: a method that declares its own " \
          "outputs (addOutput/addRawOutput) commits only the values passed to its addOutput() calls, so on that path the " \
          "write never reaches the chain and a caller that tracks the final state builds a continuation the script " \
          "refuses. Pass the new value to addOutput(...) instead, or remove the write"
      end

      def self.fe
        require_relative "anf_lower"
        RunarCompiler::Frontend
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

      # D18 + D27, per path, in a method that declares a state output
      # somewhere (any addOutput / addRawOutput, so it gets no
      # auto-continuation): :dropped when some path writes state without
      # reaching an addOutput, else :dead_write when some path writes state
      # after its last addOutput (D27), else nil.
      def self.continuation_verdict(method, contract)
        return nil unless fe.send(:_method_has_add_output, method, contract)

        SourcePaths.new(contract).verdict(method.body || [])
      end

      W = 1 # path wrote state
      A = 2 # path reached addOutput
      D = 4 # path wrote state since its last addOutput (D27; addOutput clears it)
      ZERO = Set[0].freeze

      # True iff some path state wrote state and reached no addOutput.
      def self.dropped_state?(states)
        states.any? { |x| (x & W) != 0 && (x & A).zero? }
      end

      # D27: some path reached an addOutput and wrote state after its last one.
      def self.dead_write_state?(states)
        states.any? { |x| (x & A) != 0 && (x & D) != 0 }
      end

      # D18 wins when both apply.
      def self.verdict(states)
        return :dropped if dropped_state?(states)
        return :dead_write if dead_write_state?(states)

        nil
      end

      def self.write(states)
        states.map { |x| x | W | D }.to_set
      end

      def self.add_output(states)
        states.map { |x| (x | A) & ~D }.to_set
      end

      # Run a callee's exit state +y+ after the caller's +x+: an addOutput in
      # the callee clears the caller's pending write.
      def self.then_state(x, y)
        pending = (y & A) != 0 ? (y & D) : ((x | y) & D)
        ((x | y) & ~D) | pending
      end

      def self.compose(xs, ys)
        out = Set.new
        xs.each { |x| ys.each { |y| out.add(then_state(x, y)) } }
        out
      end

      # Port of continuation-rules.ts SourcePaths. A path state is three bits
      # {W, A, D}; a set of at most eight flows through a body. Every call in an
      # expression runs; +if+ unions its arms; a loop unions skipping it; a
      # private helper call composes the caller's states with the helper's
      # exit states (fallthrough + return). Callee matching mirrors
      # anf_lower.rb's _expr_has_add_output (addOutput) and
      # _resolve_private_method (helpers). Helper exits are computed bottom-up
      # by an explicit post-order over the call graph (N-264: no host recursion
      # across helper chains); an unresolved (cyclic) helper contributes {0}.
      class SourcePaths
        def initialize(contract)
          @contract = contract
          @mutable = Set.new
          contract.properties.each { |p| @mutable.add(p.name) unless p.readonly }
          @exits = {}
          @missing = nil
        end

        def verdict(body)
          prepare(body)
          ContinuationRules.verdict(exits(body))
        end

        # Exit states of a body entered with a fresh path.
        def exits(body)
          live, returned = stmts(body, ZERO)
          live | returned
        end

        private

        def prepare(body)
          open = Set.new
          stack = [[nil, body]]
          until stack.empty?
            helper, b = stack.last
            todo = unresolved(b).reject { |m| open.include?(m.name) }
            if todo.empty?
              stack.pop
              next if helper.nil?

              @exits[helper.name] = exits(b)
              open.delete(helper.name)
            else
              open.add(todo.first.name)
              stack << [todo.first, todo.first.body || []]
            end
          end
        end

        # Private helpers called in +body+ whose exits are not computed yet.
        def unresolved(body)
          @missing = []
          exits(body)
          @missing.uniq(&:name)
        ensure
          @missing = nil
        end

        def stmts(list, states)
          live = states
          returned = Set.new
          (list || []).each do |st|
            break if live.empty?

            l, r = stmt(st, live)
            returned |= r
            live = l
          end
          [live, returned]
        end

        def stmt(st, states)
          none = Set.new
          case st
          when AssignmentStmt
            s = expr(st.value, expr(st.target, states))
            s = ContinuationRules.write(s) if writes_mutable?(st.target)
            [s, none]
          when ExpressionStmt then [expr(st.expr, states), none]
          when VariableDeclStmt then [expr(st.init, states), none]
          when ReturnStmt then [none, st.value ? expr(st.value, states) : states]
          when IfStmt
            c = expr(st.condition, states)
            tl, tr = stmts(st.then, c)
            el, er = st.else_ ? stmts(st.else_, c) : [c, none]
            [tl | el, tr | er]
          when ForStmt
            il, ir = st.init ? stmt(st.init, states) : [states, none]
            c = expr(st.condition, il)
            bl, br = stmts(st.body, c)
            ul, ur = st.update ? stmt(st.update, bl) : [bl, none]
            [c | ul, ir | br | ur]
          else [states, none]
          end
        end

        def writes_mutable?(target)
          t = target
          t = t.object while t.is_a?(IndexAccessExpr)
          t.is_a?(PropertyAccessExpr) && @mutable.include?(t.property)
        end

        def expr(e, states)
          case e
          when IncrementExpr, DecrementExpr
            s = expr(e.operand, states)
            writes_mutable?(e.operand) ? ContinuationRules.write(s) : s
          when CallExpr
            s = states
            s = expr(e.callee, s) if e.callee && !e.callee.is_a?(Identifier)
            (e.args || []).each { |a| s = expr(a, s) }
            return ContinuationRules.add_output(s) if add_output_callee?(e.callee)

            helper = ContinuationRules.fe.send(:_resolve_private_method, e.callee, @contract)
            return s if helper.nil?

            ex = @exits[helper.name]
            if ex.nil?
              @missing << helper if @missing
              ex = ZERO
            end
            ContinuationRules.compose(s, ex)
          when BinaryExpr then expr(e.right, expr(e.left, states))
          when UnaryExpr then expr(e.operand, states)
          when TernaryExpr
            c = expr(e.condition, states)
            expr(e.consequent, c) | expr(e.alternate, c)
          when IndexAccessExpr then expr(e.index, expr(e.object, states))
          when MemberExpr then expr(e.object, states)
          when ArrayLiteralExpr
            s = states
            (e.elements || []).each { |el| s = expr(el, s) }
            s
          else states
          end
        end

        def add_output_callee?(callee)
          return true if callee.is_a?(PropertyAccessExpr) && callee.property == "addOutput"

          callee.is_a?(MemberExpr) && callee.object.is_a?(Identifier) &&
            callee.object.name == "this" && callee.property == "addOutput"
        end
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
