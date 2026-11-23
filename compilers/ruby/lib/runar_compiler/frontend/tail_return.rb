# frozen_string_literal: true

require_relative "ast_nodes"

module RunarCompiler
  module Frontend
    # N-511: tail values on the surfaces whose trailing expression IS the
    # value. On .runar.rs / .runar.move (with a declared return type) and
    # .runar.rb (private helpers) the trailing expression statement becomes an
    # explicit return, recursively through the arms of a trailing if/else
    # (`if c { x } else { 0 }`) when into_arms. The return keeps the
    # expression statement's own source location, so the lowered ANF is
    # unchanged; the type checker then needs no tail-value heuristic.
    module TailReturn
      def self.promote(stmts, into_arms = true)
        return if stmts.nil? || stmts.empty?

        last = stmts[-1]
        if last.is_a?(ExpressionStmt)
          stmts[-1] = ReturnStmt.new(value: last.expr, source_location: last.source_location)
        elsif into_arms && last.is_a?(IfStmt) && last.else_ && !last.else_.empty?
          promote(last.then, true)
          promote(last.else_, true)
        end
      end

      # Whether a `return <value>` appears anywhere in the list.
      def self.value_return?(stmts)
        (stmts || []).any? do |st|
          case st
          when ReturnStmt then !st.value.nil?
          when IfStmt then value_return?(st.then) || value_return?(st.else_)
          when ForStmt then value_return?(st.body)
          else false
          end
        end
      end
    end
  end
end
