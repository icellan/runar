# frozen_string_literal: true

# N-115 -- normalise a reversed loop comparison to the canonical spelling.
#
# Every later pass reads a loop's iterator off the LEFT-hand side of its
# condition (W4, validate_for_condition_tests_iterator) and its bound off the
# right. `10 > i` says the same thing as `i < 10`, so the parser rewrites it
# once instead of every pass learning a second spelling:
#
#   N >  i  ->  i <  N        N <  i  ->  i >  N
#   N >= i  ->  i <= N        N <= i  ->  i >= N
#
# The rule, identical in all seven tiers: the condition is a `<`/`<=`/`>`/`>=`
# comparison, its RIGHT operand is the loop variable, and its LEFT operand is
# not -> swap the operands and mirror the operator. Nothing else is touched,
# so the W4 refusals (N40, N41) and the direction rule (N42) keep firing.

require_relative "ast_nodes"

module RunarCompiler
  module Frontend
    module LoopCondition
      MIRRORED = { "<" => ">", "<=" => ">=", ">" => "<", ">=" => "<=" }.freeze

      module_function

      # The canonical form of +cond+ for a loop over +iter_name+ (or +cond+).
      def normalize(cond, iter_name)
        return cond unless cond.is_a?(BinaryExpr) && MIRRORED.key?(cond.op)

        is_iter = ->(e) { e.is_a?(Identifier) && e.name == iter_name }
        return cond if !is_iter.call(cond.right) || is_iter.call(cond.left)

        BinaryExpr.new(op: MIRRORED[cond.op], left: cond.right, right: cond.left)
      end

      def normalize_statements(stmts)
        (stmts || []).each do |stmt|
          case stmt
          when ForStmt
            stmt.condition = normalize(stmt.condition, stmt.init.name) unless stmt.init.nil?
            normalize_statements(stmt.body)
          when IfStmt
            normalize_statements(stmt.then)
            normalize_statements(stmt.else_)
          end
        end
      end

      # Rewrite every loop condition in +contract+ to its canonical spelling.
      def normalize_contract(contract)
        normalize_statements(contract.constructor.body) unless contract.constructor.nil?
        (contract.methods || []).each { |m| normalize_statements(m.body) }
      end
    end
  end
end
