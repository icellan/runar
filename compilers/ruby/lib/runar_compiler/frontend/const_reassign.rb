# frozen_string_literal: true

# N-342 -- a +const+ local on the +.runar.ts+ surface cannot be reassigned.
#
# spec/grammar.md section 9: "+const+ variables cannot be reassigned." The
# parser recorded +mutable = false+ for +const+ and nothing ever read it, so
# +const s = 1n; s = s + x;+ compiled. Refused, with one sentence in all seven
# tiers: +x = e+ (and the compound forms the parser desugars to it), +x+++ /
# +++x+ / +x--+ / +--x+, and a +const+ for-initializer, which the loop's own
# +i++ then advances. Element writes (+x[0] = e+) are not touched. Scoping
# follows blocks. Runs on the +.runar.ts+ parse result only: other surfaces
# spell immutability differently and several parsers record +mutable+ as a
# constant.

require_relative "ast_nodes"
require_relative "diagnostic"

module RunarCompiler
  module Frontend
    module ConstReassign
      module_function

      # The one sentence every tier emits for reassigning const +name+.
      def message(name)
        "Cannot assign to '#{name}' because it is a constant."
      end

      def lookup(scopes, name)
        scopes.reverse_each do |scope|
          return scope[name] if scope.key?(name)
        end
        nil
      end

      def check_target(target, scopes, loc, out)
        return unless target.is_a?(Identifier)
        return unless lookup(scopes, target.name) == false

        out << Diagnostic.new(message: message(target.name), severity: Severity::ERROR, loc: loc)
      end

      def check_simple(stmt, scopes, out)
        case stmt
        when AssignmentStmt
          check_target(stmt.target, scopes, stmt.source_location, out)
        when ExpressionStmt
          if stmt.expr.is_a?(IncrementExpr) || stmt.expr.is_a?(DecrementExpr)
            check_target(stmt.expr.operand, scopes, stmt.source_location, out)
          end
        end
      end

      def walk(stmts, scopes, out)
        here = {}
        scopes.push(here)
        (stmts || []).each do |stmt|
          case stmt
          when VariableDeclStmt
            here[stmt.name] = stmt.mutable ? true : false
          when IfStmt
            walk(stmt.then, scopes, out)
            walk(stmt.else_, scopes, out)
          when ForStmt
            loop_scope = {}
            loop_scope[stmt.init.name] = stmt.init.mutable ? true : false unless stmt.init.nil?
            scopes.push(loop_scope)
            check_simple(stmt.update, scopes, out)
            walk(stmt.body, scopes, out)
            scopes.pop
          else
            check_simple(stmt, scopes, out)
          end
        end
        scopes.pop
      end

      # A diagnostic for every reassigned +const+ local in +contract+.
      def check(contract)
        out = []
        walk(contract.constructor.body, [], out) unless contract.constructor.nil?
        (contract.methods || []).each { |m| walk(m.body, [], out) }
        out
      end
    end
  end
end
