# frozen_string_literal: true

# Field-usage validation for per-method `@sighash` modes (issue #123).
#
# SECURITY CORE. A relaxed sighash flag ZEROES specific BIP-143 preimage fields;
# a covenant that still reads one of those fields (or binds an output the flag no
# longer commits to) is exploitable — the attacker gets a free hand over exactly
# the part of the transaction the covenant believed it had pinned. This pass
# rejects, at compile time, every field read / output binding that becomes
# unsound under the method's declared mode.
#
# Direct port of packages/runar-compiler/src/passes/sighash-validate.ts.
#
# BIP-143 field availability by sighash type (✓ = committed, ✗ = ZEROED):
#   field           ALL   NONE   SINGLE   +ANYONECANPAY
#   hashPrevouts     ✓     ✓      ✓        ✗ (all-inputs digest)
#   hashSequence     ✓     ✗      ✗        ✗ (all-inputs digest)
#   hashOutputs      ✓     ✗    same-idx   (per base)
# The this-input / always-present extractors (extractVersion, extractOutpoint,
# extractAmount, extractSequence, extractScriptCode, extractLocktime,
# extractSigHashType) are sound under every mode and are never rejected.

require_relative "ast_nodes"
require_relative "diagnostic"
require_relative "sighash_directive"
# For the transitive state-mutation / output-intrinsic helpers reused from the
# ANF lowering pass (continuation detection).
require_relative "anf_lower"
require_relative "continuation_rules"

module RunarCompiler
  module Frontend
    module SighashValidate
      SD = SighashDirective

      # Builtins that read the all-inputs prevouts digest (zeroed under ANYONECANPAY).
      HASHPREVOUTS_READERS = %w[extractHashPrevouts].to_set.freeze
      # Builtins that read the all-inputs sequence digest (zeroed unless pure ALL).
      HASHSEQUENCE_READERS = %w[extractHashSequence].to_set.freeze
      # Builtins that read the outputs digest (zeroed under NONE).
      HASHOUTPUTS_READERS = %w[extractOutputHash extractOutputs].to_set.freeze
      # Intrinsic that binds a companion input's prevout script (needs hashPrevouts).
      PREVOUT_SCRIPT_INTRINSICS = %w[extractPrevOutputScript].to_set.freeze
      # Intrinsics that assert an output (bound via hashOutputs).
      OUTPUT_ASSERT_INTRINSICS = %w[requireOutputP2PKH].to_set.freeze
      # Output-emitting intrinsics (state continuation outputs).
      STATE_OUTPUT_INTRINSICS = %w[addOutput addRawOutput].to_set.freeze
      DATA_OUTPUT_INTRINSICS = %w[addDataOutput].to_set.freeze

      module_function

      # Validate every public method's `@sighash` field usage. Returns a list of
      # Diagnostic objects (errors AND warnings; empty when all modes are used
      # soundly). Methods with no directive (default ALL|FORKID) are never flagged.
      def validate_sighash_usage(contract)
        diags = []
        is_stateful = contract.parent_class == "StatefulSmartContract"

        private_by_name = {}
        contract.methods.each do |m|
          private_by_name[m.name] = m if m.visibility != "public"
        end

        contract.methods.each do |method|
          next if method.visibility != "public"
          mode = method.respond_to?(:sighash_type) ? method.sighash_type : nil
          next if mode.nil? # default ALL|FORKID — allow all

          base = mode & SD::BASE_TYPE_MASK
          acp = (mode & SD::FLAG_ANYONECANPAY) != 0
          label = SD.describe_sighash(mode)

          scan = scan_method(method, private_by_name)

          # State-continuation binding (stateful auto-injected hashOutputs).
          needs_continuation = is_stateful && continuation_needed?(method, contract)

          push = lambda do |usage, msg|
            diags << Diagnostic.new(message: msg, severity: Severity::ERROR,
                                    loc: usage[:loc] || method.source_location)
          end
          push_warn = lambda do |usage, msg|
            diags << Diagnostic.new(message: msg, severity: Severity::WARNING,
                                    loc: usage[:loc] || method.source_location)
          end

          # ---- ANYONECANPAY: only THIS input is signed ----------------------
          if acp
            scan[:hash_prevouts_reads].each do |u|
              push.call(u, "@sighash #{label}: '#{u[:name]}' reads hashPrevouts, which is zeroed under ANYONECANPAY (only this input is signed) — the covenant cannot constrain the input set, so any check on it is trivially bypassable. Remove ANYONECANPAY or drop the #{u[:name]} read.")
            end
            scan[:prevout_script_reads].each do |u|
              push.call(u, "@sighash #{label}: '#{u[:name]}' binds a companion input's prevout script, but ANYONECANPAY zeroes hashPrevouts so the input set is unconstrained — an attacker can substitute inputs freely. Companion-input covenants require the full prevout set to be committed (drop ANYONECANPAY).")
            end
          end

          # ---- hashSequence is committed only under pure ALL (no ACP) -------
          hash_sequence_sound = base == SD::BASE_ALL && !acp
          unless hash_sequence_sound
            scan[:hash_sequence_reads].each do |u|
              push.call(u, "@sighash #{label}: '#{u[:name]}' reads hashSequence, which is zeroed under any mode other than SIGHASH_ALL (NONE / SINGLE / ANYONECANPAY all clear it) — the read yields attacker-chosen zeros. Use SIGHASH_ALL or drop the #{u[:name]} read.")
            end
          end

          # ---- NONE commits to NO outputs -----------------------------------
          if base == SD::BASE_NONE
            if needs_continuation
              push.call({ name: "state continuation", loc: method.source_location },
                        "@sighash #{label}: this stateful method binds a state-continuation output via hashOutputs, but NONE commits to NO outputs (hashOutputs is zeroed) — the continuation is unenforceable, so the next-state covenant is meaningless and the spend is unsound. A continuation covenant cannot use NONE.")
            end
            scan[:hash_outputs_reads].each do |u|
              push.call(u, "@sighash #{label}: '#{u[:name]}' reads hashOutputs, which is zeroed under NONE — the read yields attacker-chosen zeros. Drop the output read or use ALL/SINGLE.")
            end
            scan[:output_asserts].each do |u|
              push.call(u, "@sighash #{label}: '#{u[:name]}' asserts an output, but NONE commits to no outputs — the assertion cannot be enforced. Use ALL/SINGLE.")
            end
            if scan[:state_output_count] + scan[:data_output_count] > 0
              n = scan[:state_output_count] + scan[:data_output_count]
              push.call({ name: "addOutput", loc: method.source_location },
                        "@sighash #{label}: this method emits #{n} output(s) (addOutput/addRawOutput/addDataOutput), but NONE commits to no outputs — those outputs are unenforceable. Use ALL/SINGLE.")
            end
          end

          # ---- SINGLE commits ONLY to the same-index output -----------------
          if base == SD::BASE_SINGLE
            # A fixed-index output assertion (requireOutputP2PKH) cannot be proven
            # to land at THIS input's index, the only output SINGLE commits to.
            scan[:output_asserts].each do |u|
              push.call(u, "@sighash #{label}: '#{u[:name]}' asserts an output at a fixed index, but SINGLE commits ONLY to the output at THIS input's index — the asserted index cannot be statically proven equal to the input index, so the assertion may bind an uncommitted (attacker-controllable) output or silently brick the spend. Use ALL.")
            end

            # A stateful mutate-only (or data-only) method has NO explicit output
            # intrinsic, so the compiler auto-injects a single state-continuation
            # output whose value is the caller-chosen `_newAmount`. Under SINGLE,
            # BIP-143 commits ONLY to the output at THIS input's index and does
            # NOT pin its value, so that continuation is value-skimmable. REJECT.
            is_mutate_only_auto_continuation =
              needs_continuation && scan[:state_output_count] == 0 && scan[:data_output_count] == 0

            state_outputs =
              if scan[:state_output_count] > 0
                scan[:state_output_count]
              elsif needs_continuation
                1
              else
                0
              end
            committed = state_outputs + scan[:data_output_count]

            if is_mutate_only_auto_continuation
              push.call({ name: "state continuation", loc: method.source_location },
                        "@sighash #{label}: this stateful method's state continuation is sized by the caller-chosen _newAmount, but SINGLE commits ONLY to the same-index output WITHOUT pinning its value — a spender can set _newAmount to dust, drive the change output to zero, and append a draining output while the covenant + OP_PUSH_TX binding still validate (value skim); an honest change>0 leaves the UTXO unspendable. A mutate-only SINGLE continuation is unsound. Use ALL, or emit an explicit addOutput/addRawOutput that carries the full protected value at this input's index.")
            elsif committed > 1
              push.call({ name: "multi-output continuation", loc: method.source_location },
                        "@sighash #{label}: SINGLE commits ONLY to the output at this input's index, but this method binds #{committed} outputs (#{scan[:state_output_count]} addOutput + #{scan[:data_output_count]} addDataOutput#{state_outputs > scan[:state_output_count] ? ' + state continuation' : ''}). Outputs beyond the same-index one are uncommitted and attacker-controllable. A SINGLE covenant must bind exactly one same-index output.")
            elsif committed == 1
              # Legitimate pairwise input↔output covenant: exactly one explicit
              # addOutput/addRawOutput (or single data output). The same-index
              # output IS committed, but SINGLE does not let the compiler prove
              # statically that its VALUE equals the full protected amount — a
              # runtime obligation on the caller. Allow, but warn.
              push_warn.call({ name: "single-output SINGLE covenant", loc: method.source_location },
                             "@sighash #{label}: SINGLE commits ONLY to the output at this input's index. This method binds exactly one output there, which is sound ONLY if that output carries the FULL protected value — SINGLE does not pin the amount, so a short-changed same-index output cannot be caught at compile time. Ensure the caller places the fully-valued output at this input's index.")
            end
          end
        end

        diags
      end

      # Stateful continuation is auto-injected when the method mutates state or
      # emits an output (mirrors anf_lower's needs_change_output trigger).
      def continuation_needed?(method, contract)
        # ContinuationRules.mutates_state? also counts FixedArray element writes,
        # which this unexpanded contract still spells as such.
        RunarCompiler::Frontend::ContinuationRules.mutates_state?(method, contract) ||
          RunarCompiler::Frontend.send(:_method_has_add_output, method, contract) ||
          RunarCompiler::Frontend.send(:_method_has_add_data_output, method, contract)
      end

      # Resolve a call/method-call callee to a bare name.
      def callee_name(callee)
        return callee.name if callee.is_a?(Identifier)
        return callee.property if callee.is_a?(PropertyAccessExpr) || callee.is_a?(MemberExpr)
        nil
      end

      # Walk a method body (transitively through private-method calls) collecting
      # every flagged builtin/intrinsic usage with its source location.
      def scan_method(method, private_by_name)
        scan = {
          hash_prevouts_reads: [],
          hash_sequence_reads: [],
          hash_outputs_reads: [],
          prevout_script_reads: [],
          output_asserts: [],
          state_output_count: 0,
          data_output_count: 0,
        }
        visiting = {}

        walk_expr = nil
        walk_stmt = nil

        walk_body = lambda { |stmts| stmts.each { |s| walk_stmt.call(s) } }

        walk_stmt = lambda do |stmt|
          case stmt
          when AssignmentStmt
            # Walk BOTH sides: a forbidden field read can hide in the assignment
            # target (e.g. `arr[extractOutputHash(pre)] = x`), not just the value.
            walk_expr.call(stmt.target)
            walk_expr.call(stmt.value)
          when ExpressionStmt
            walk_expr.call(stmt.expr)
          when AssertStmt
            walk_expr.call(stmt.condition)
            walk_expr.call(stmt.message) if stmt.message
          when IfStmt
            walk_expr.call(stmt.condition)
            walk_body.call(stmt.then)
            walk_body.call(stmt.else_) if stmt.else_
          when ForStmt
            # Walk the full loop header: init and condition can hide a forbidden
            # field read just as easily as the body/update do.
            walk_stmt.call(stmt.init) if stmt.init
            walk_expr.call(stmt.condition) if stmt.condition
            walk_stmt.call(stmt.update) if stmt.update
            walk_body.call(stmt.body)
          when ReturnStmt
            walk_expr.call(stmt.value) if stmt.value
          when VariableDeclStmt
            walk_expr.call(stmt.init) if stmt.init
          end
        end

        walk_expr = lambda do |expr|
          return if expr.nil?

          case expr
          when CallExpr
            name = callee_name(expr.callee)
            loc = nil
            if name
              scan[:hash_prevouts_reads] << { name: name, loc: loc } if HASHPREVOUTS_READERS.include?(name)
              scan[:hash_sequence_reads] << { name: name, loc: loc } if HASHSEQUENCE_READERS.include?(name)
              scan[:hash_outputs_reads] << { name: name, loc: loc } if HASHOUTPUTS_READERS.include?(name)
              scan[:prevout_script_reads] << { name: name, loc: loc } if PREVOUT_SCRIPT_INTRINSICS.include?(name)
              scan[:output_asserts] << { name: name, loc: loc } if OUTPUT_ASSERT_INTRINSICS.include?(name)
              scan[:state_output_count] += 1 if STATE_OUTPUT_INTRINSICS.include?(name)
              scan[:data_output_count] += 1 if DATA_OUTPUT_INTRINSICS.include?(name)
              # Recurse into a private helper so its usages surface to the caller.
              target = private_by_name[name]
              if target && !visiting[name]
                visiting[name] = true
                walk_body.call(target.body)
                visiting.delete(name)
              end
            end
            expr.args.each { |a| walk_expr.call(a) }
            walk_expr.call(expr.callee) unless expr.callee.is_a?(Identifier)
          when MethodCallExpr
            name = expr.method
            if name
              scan[:state_output_count] += 1 if STATE_OUTPUT_INTRINSICS.include?(name)
              scan[:data_output_count] += 1 if DATA_OUTPUT_INTRINSICS.include?(name)
              scan[:output_asserts] << { name: name, loc: nil } if OUTPUT_ASSERT_INTRINSICS.include?(name)
              target = private_by_name[name]
              if target && !visiting[name]
                visiting[name] = true
                walk_body.call(target.body)
                visiting.delete(name)
              end
            end
            walk_expr.call(expr.object) if expr.object
            expr.args.each { |a| walk_expr.call(a) }
          when BinaryExpr
            walk_expr.call(expr.left)
            walk_expr.call(expr.right)
          when UnaryExpr
            walk_expr.call(expr.operand)
          when TernaryExpr
            walk_expr.call(expr.condition)
            walk_expr.call(expr.consequent)
            walk_expr.call(expr.alternate)
          when IndexAccessExpr
            walk_expr.call(expr.object)
            walk_expr.call(expr.index)
          when MemberExpr
            walk_expr.call(expr.object)
          when ArrayLiteralExpr
            expr.elements.each { |el| walk_expr.call(el) }
          end
        end

        walk_body.call(method.body)
        scan
      end
    end
  end
end
