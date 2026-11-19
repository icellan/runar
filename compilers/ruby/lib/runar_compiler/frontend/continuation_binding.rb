# frozen_string_literal: true

# D25 -- bind every state continuation to the input that made it.
#
# SECURITY CORE (fund safety). Mirrors
# packages/runar-compiler/src/passes/continuation-binding.ts (the TypeScript
# reference): same classification, same hidden field name, same diagnostics.
#
# Before D25 every stateful covenant checked
# `hash256(continuation || change) == hashOutputs` over the WHOLE output list,
# and the BIP-143 preimage carries no input position, so two UTXOs of one
# contract spent in one transaction that reach the same post-state were BOTH
# satisfied by ONE continuation output.
#
# The binding is a property of the CONTRACT, classified once:
#
# * "single"   every continuation-producing public method is mutate-only and
#              reads nothing SINGLE zeroes or redefines: those methods default
#              to SIGHASH_SINGLE|FORKID (ALL|ANYONECANPAY|FORKID becomes
#              SINGLE|ANYONECANPAY|FORKID); an explicit @sighash ALL|FORKID is
#              refused.
# * "bind"     at least one auto-continuation method, but not "single": a
#              hidden last state field
#              _spentOutpointHash = sha256(extractOutpoint(txPreimage)) is
#              written by every continuation.
# * "explicit" every continuation method sizes its own outputs: unchanged
#              bytes, a warning on an unsigned addOutput(extractAmount(...)).
# * "none"     stateless, or no public method produces a continuation.

require "set"
require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "sighash_directive"
require_relative "anf_lower"
require_relative "continuation_rules"

module RunarCompiler
  module Frontend
    module ContinuationBinding
      SD = SighashDirective

      # The hidden state field of a "bind" contract (reserved; last mutable property).
      TWIN_BINDING_FIELD = "_spentOutpointHash"

      # SIGHASH_SINGLE|FORKID.
      SIGHASH_SINGLE_FORKID = SD::BASE_SINGLE | SD::FLAG_FORKID

      # Builtins whose meaning SINGLE zeroes or redefines (a mutate-only method
      # reading one keeps ALL).
      SINGLE_INCOMPATIBLE_READS = %w[
        extractHashSequence
        extractOutputHash
        extractOutputs
        extractSigHashType
        requireOutputP2PKH
      ].to_set.freeze

      # D25: the shared error text for an explicit ALL sibling in a "single" contract.
      def self.explicit_all_sibling_message(method)
        "method '#{method}': @sighash ALL|FORKID on a state-continuation method of a contract whose " \
          "continuation methods are all mutate-only reopens twin-input theft: such a contract commits each " \
          "continuation under SIGHASH_SINGLE (one output per input), and one ALL method lets its input reuse " \
          "a sibling's output while its own value leaves as change. Remove the directive (the default is " \
          "SINGLE|FORKID) or write @sighash SINGLE|FORKID"
      end

      # D25: the shared warning text for an unsigned value-conserving addOutput (D12 C1).
      def self.unsigned_add_output_message(method)
        "method '#{method}' re-creates the contract with addOutput(extractAmount(...), ...) and checks no " \
          "signature: two UTXOs of this contract spent in one transaction that reach the same state are both " \
          "satisfied by ONE such output, and the other input's value leaves as anyone's change (twin-input " \
          "aliasing). A method that sizes its own outputs is not bound to its input; require a signature, or " \
          "let the compiler size the continuation (write state instead of calling addOutput)"
      end

      def self.callee_name(callee)
        return callee.name if callee.is_a?(Identifier)
        return callee.property if callee.is_a?(PropertyAccessExpr) || callee.is_a?(MemberExpr)

        nil
      end

      # Every call name reachable from +body+, through private helpers (cycle-guarded).
      def self.reachable_calls(body, privates)
        names = Set.new
        visiting = Set.new
        stmt = nil
        expr = nil
        stmts = ->(ss) { (ss || []).each { |s| stmt.call(s) } }
        stmt = lambda do |s|
          case s
          when AssignmentStmt then expr.call(s.target); expr.call(s.value)
          when ExpressionStmt then expr.call(s.expr)
          # Ruby-AST-only node (no parser emits it today); walked so a read in
          # it cannot hide.
          when AssertStmt then expr.call(s.condition); expr.call(s.message)
          when IfStmt then expr.call(s.condition); stmts.call(s.then); stmts.call(s.else_)
          when ForStmt then stmt.call(s.init); expr.call(s.condition); stmt.call(s.update); stmts.call(s.body)
          when ReturnStmt then expr.call(s.value)
          when VariableDeclStmt then expr.call(s.init)
          end
        end
        expr = lambda do |e|
          case e
          when CallExpr
            n = callee_name(e.callee)
            unless n.nil?
              names << n
              t = privates[n]
              if t && !visiting.include?(n)
                visiting << n
                stmts.call(t.body)
                visiting.delete(n)
              end
            end
            (e.args || []).each { |a| expr.call(a) }
            expr.call(e.callee) unless e.callee.is_a?(Identifier)
          when BinaryExpr then expr.call(e.left); expr.call(e.right)
          when UnaryExpr then expr.call(e.operand)
          when TernaryExpr then expr.call(e.condition); expr.call(e.consequent); expr.call(e.alternate)
          when IndexAccessExpr then expr.call(e.object); expr.call(e.index)
          when MemberExpr then expr.call(e.object)
          when ArrayLiteralExpr then (e.elements || []).each { |x| expr.call(x) }
          end
        end
        stmts.call(body)
        names
      end

      def self.privates_of(contract)
        contract.methods.select { |m| m.visibility == "private" }.to_h { |m| [m.name, m] }
      end

      # [cls, continuation_methods] (see the module comment).
      def self.classify(contract)
        return ["none", []] unless contract.parent_class == "StatefulSmartContract"

        fe = RunarCompiler::Frontend
        privates = privates_of(contract)
        continuation_methods = []
        any_auto = false
        all_single_eligible = true
        contract.methods.each do |m|
          next unless m.visibility == "public"

          # The side-effect summary of the unexpanded contract (as
          # sighash_validate.rb's continuation_needed? reads it).
          has_state_output = fe.send(:_method_has_add_output, m, contract)
          has_data_output = fe.send(:_method_has_add_data_output, m, contract)
          mutates = ContinuationRules.mutates_state?(m, contract)
          next unless mutates || has_state_output || has_data_output

          continuation_methods << m
          any_auto = true unless has_state_output
          mode = m.sighash_type
          base = mode.nil? ? SD::BASE_ALL : mode & SD::BASE_TYPE_MASK
          mode_ok = [SD::BASE_ALL, SD::BASE_SINGLE].include?(base)
          reads_ok = reachable_calls(m.body, privates).none? { |n| SINGLE_INCOMPATIBLE_READS.include?(n) }
          all_single_eligible = false if has_state_output || has_data_output || !mode_ok || !reads_ok
        end
        return ["none", continuation_methods] if continuation_methods.empty?
        return ["explicit", continuation_methods] unless any_auto

        [all_single_eligible ? "single" : "bind", continuation_methods]
      end

      # The contract's D25 class: "none" | "single" | "bind" | "explicit".
      def self.continuation_class(contract)
        classify(contract)[0]
      end

      # D25 resolution, run by the validator right before the @sighash checks.
      #
      # In a "single" contract it sets each continuation method's
      # +sighash_type+ and refuses an explicit pure-ALL directive; in an
      # "explicit" contract it warns about unsigned value-conserving addOutput
      # methods. Idempotent.
      def self.resolve(contract)
        diags = []
        cls, continuation_methods = classify(contract)
        if cls == "single"
          continuation_methods.each do |m|
            mode = m.sighash_type
            if mode.nil?
              m.sighash_type = SIGHASH_SINGLE_FORKID
            elsif (mode & SD::BASE_TYPE_MASK) == SD::BASE_ALL
              if (mode & SD::FLAG_ANYONECANPAY) != 0
                m.sighash_type = (mode & ~SD::BASE_TYPE_MASK) | SD::BASE_SINGLE
              else
                diags << Diagnostic.new(message: explicit_all_sibling_message(m.name),
                                        severity: Severity::ERROR, loc: m.source_location)
              end
            end
          end
        elsif cls == "explicit"
          privates = privates_of(contract)
          continuation_methods.each do |m|
            mode = m.sighash_type
            next if !mode.nil? && (mode & SD::BASE_TYPE_MASK) != SD::BASE_ALL
            next unless unsigned_value_conserving_add_output?(m, privates)

            # The Ruby AST carries no call-site location, so the warning points
            # at the method (TS points at the addOutput).
            diags << Diagnostic.new(message: unsigned_add_output_message(m.name),
                                    severity: Severity::WARNING, loc: m.source_location)
          end
        end
        diags
      end

      # A call name that verifies a signature (any scheme).
      def self.signature_check?(name)
        %w[checkSig checkMultiSig].include?(name) || name.start_with?("verify")
      end

      # D12 C1: an addOutput whose satoshis argument reads extractAmount
      # (directly, or through a local initialised from it) in a method that
      # verifies no signature.
      def self.unsigned_value_conserving_add_output?(method, privates)
        return false if reachable_calls(method.body, privates).any? { |n| signature_check?(n) }

        amount_locals = Set.new
        reads_amount = nil
        reads_amount = lambda do |e|
          case e
          when CallExpr
            callee_name(e.callee) == "extractAmount" || (e.args || []).any? { |a| reads_amount.call(a) }
          when Identifier then amount_locals.include?(e.name)
          when BinaryExpr then reads_amount.call(e.left) || reads_amount.call(e.right)
          when UnaryExpr then reads_amount.call(e.operand)
          when TernaryExpr
            reads_amount.call(e.condition) || reads_amount.call(e.consequent) || reads_amount.call(e.alternate)
          else false
          end
        end
        found = false
        visiting = Set.new
        stmt = nil
        expr = nil
        stmts = ->(ss) { (ss || []).each { |s| stmt.call(s) } }
        stmt = lambda do |s|
          case s
          when VariableDeclStmt
            amount_locals << s.name if !s.init.nil? && reads_amount.call(s.init)
            expr.call(s.init)
          when AssignmentStmt then expr.call(s.value)
          when ExpressionStmt then expr.call(s.expr)
          when IfStmt then expr.call(s.condition); stmts.call(s.then); stmts.call(s.else_)
          when ForStmt then stmts.call(s.body)
          when ReturnStmt then expr.call(s.value)
          end
        end
        expr = lambda do |e|
          return unless e.is_a?(CallExpr)

          n = callee_name(e.callee)
          args = e.args || []
          found = true if n == "addOutput" && !args.empty? && reads_amount.call(args[0])
          t = n.nil? ? nil : privates[n]
          if t && !visiting.include?(t.name)
            visiting << t.name
            stmts.call(t.body)
            visiting.delete(t.name)
          end
          args.each { |a| expr.call(a) }
        end
        stmts.call(method.body)
        found
      end

      # D25 injection, run after typecheck (before fixed-array expansion): a
      # "bind" contract gains the hidden `_spentOutpointHash: Sha256 = 0x00..00`
      # as its LAST property. ANF lowering then writes it in every
      # auto-continuation and appends it to every addOutput. The zero
      # initializer keeps it out of the constructor ABI. Any other class is
      # returned unchanged (the same object).
      def self.inject(contract)
        return contract unless continuation_class(contract) == "bind"
        return contract if contract.properties.any? { |p| p.name == TWIN_BINDING_FIELD }

        loc = contract.constructor&.source_location || SourceLocation.new
        field = PropertyNode.new(
          name: TWIN_BINDING_FIELD,
          type: PrimitiveType.new(name: "Sha256"),
          readonly: false,
          initializer: ByteStringLiteral.new(value: "00" * 32, source_location: loc),
          source_location: loc
        )
        out = contract.dup
        out.properties = [*contract.properties, field]
        out
      end
    end
  end
end
