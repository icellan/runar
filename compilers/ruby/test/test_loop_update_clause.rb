# frozen_string_literal: true

# R-065 regression guard for the Ruby tier: the for-loop `update` clause is
# parsed, carried through the whole AST, and then never validated and never
# lowered.
#
# `frontend/anf_lower.rb`'s `extract_loop_step` only ever understood a UNIT
# step: it returns `1` for `IncrementExpr`, `-1` for `DecrementExpr`, and
# otherwise falls back to the *comparison direction* -- so any other update
# clause is silently coerced to `+-1` and the clause itself is discarded.
# `validator.rb`'s `validate_for_statement` never looked at `stmt.update` at all,
# and `typecheck.rb`'s `ForStmt` arm checked `init`, `condition` and `body` but
# skipped `update` entirely.
#
# Three shapes of the same hole, all observable from ordinary source:
#
#   * `for (let i = 0n; i < 3n; undefinedFn())` compiled to byte-identical
#     output. A nonexistent function name raised nothing -- a hole in the rule
#     that only Runar builtins and contract methods are callable (CLAUDE.md
#     names `console.log` explicitly).
#   * `for (let i = 0n; i < 3n; this.count++)` silently DROPPED the state write
#     from the emitted script.
#   * a non-unit step (`i += 2` in the Go / Zig / Solidity surface formats)
#     unrolled 5 times over i = 0..4 instead of 3 times over i = 0,2,4 --
#     byte-identical to the `i++` loop, with no diagnostic.
#
# spec/grammar.md is authoritative and permits only the unit forms: its
# ForStatement production admits `Identifier ( '++' | '--' )` and nothing else,
# and its Statement Restrictions say "The loop variable MUST use simple
# increment (`++`) or decrement (`--`)". So rejecting is the fix rather than
# lowering: the ANF `loop` node can express exactly
# `{count, iterVar, start, step, body}` and synthesizes the iterator on unrolled
# iteration k as `start + k*step`. There is no slot for an arbitrary update
# statement, and appending the update's lowering to the loop body would re-emit
# `i++` as a dead binding on every loop that already compiles correctly --
# moving bytes across the whole corpus to express nothing.
#
# The diagnostic text is shared verbatim with the other six tiers.
#
# What these tests do NOT prove: nothing here says the update clause is
# *lowered*; the contract is that a non-representable update is a compile error
# instead of silent output. The controls pin the `bounded-loop` shape only.

require_relative "test_helper"

require "tmpdir"

class TestLoopUpdateClause < Minitest::Test
  REPO_ROOT = File.expand_path("../../..", __dir__)

  # The one correct answer. `bounded-loop` sums `start + i` for i in 0..4 and
  # asserts the total; all nine frontends lower to these exact 42 bytes.
  BOUNDED_LOOP_HEX =
    "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c"

  LOOP_UPDATE_DIAGNOSTIC = "must advance the loop variable by one"

  def example(rel)
    File.read(File.join(REPO_ROOT, rel))
  end

  # Compile a source string through the real pipeline by staging it under the
  # file name that selects the right frontend.
  # Returns [ok, hex, message].
  def compile_source(source, file_name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      begin
        artifact = RunarCompiler.compile_from_source(path, disable_constant_folding: true)
        [true, artifact.script, ""]
      rescue RunarCompiler::CompilationError => e
        [false, "", e.message]
      end
    end
  end

  # A stateful contract parameterised on the for-loop update clause.
  def ts_with_update(update)
    <<~TS
      import { StatefulSmartContract, assert } from 'runar-lang';

      class UpdateProbe extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) { super(count); this.count = count; }

        public unlock(expected: bigint): void {
          let acc: bigint = 0n;
          for (let i: bigint = 0n; i < 3n; #{update}) {
            acc = acc + i;
          }
          assert(acc === expected);
        }
      }
    TS
  end

  # -------------------------------------------------------------------------
  # The defect
  # -------------------------------------------------------------------------

  # The Zig `while (c) : (i += 2)` fold produces the ASSIGNMENT spelling
  # `i = i + 2`.
  def test_non_unit_step_rejected_zig
    source = example("examples/zig/bounded-loop/BoundedLoop.runar.zig").sub("i += 1", "i += 2")
    ok, hex, msg = compile_source(source, "BoundedLoop.runar.zig")
    refute ok, "`i += 2` must not compile: it silently unrolled with step 1 (#{hex.length} hex chars)"
    assert_includes msg, LOOP_UPDATE_DIAGNOSTIC,
                    "rejection must carry the shared cross-tier diagnostic"
  end

  # The Go surface spelling of the same thing.
  def test_non_unit_step_rejected_go
    source = example("examples/go/bounded-loop/BoundedLoop.runar.go").sub("i++", "i += 2")
    ok, hex, msg = compile_source(source, "BoundedLoop.runar.go")
    refute ok, "`i += 2` must not compile (#{hex.length} hex chars)"
    assert_includes msg, LOOP_UPDATE_DIAGNOSTIC
  end

  # Guards against an accepted set that only checks counting up.
  def test_negative_non_unit_step_rejected
    source = example("examples/zig/bounded-loop/BoundedLoop.runar.zig")
                 .sub("var i: i64 = 0;", "var i: i64 = 5;")
                 .sub("while (i < 5) : (i += 1)", "while (i > 0) : (i -= 2)")
    ok, _hex, msg = compile_source(source, "BoundedLoop.runar.zig")
    refute ok, "`i -= 2` must not compile"
    assert_includes msg, LOOP_UPDATE_DIAGNOSTIC
  end

  # The silent-drop half. `this.count++` in the update position is a write to
  # contract state that never reached the emitted script.
  def test_state_mutation_in_update_rejected_not_dropped
    ok, _hex, msg = compile_source(ts_with_update("this.count++"), "UpdateProbe.runar.ts")
    refute ok, "a state mutation in the update clause is not representable in the ANF " \
               "loop node, so it must be a compile error -- silently dropping it is " \
               "what this test forbids"
    assert_includes msg, LOOP_UPDATE_DIAGNOSTIC
  end

  def test_update_advancing_another_variable_rejected
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class OtherVar extends SmartContract {
        readonly expected: bigint;

        constructor(expected: bigint) { super(expected); this.expected = expected; }

        public verify(start: bigint): void {
          let sum: bigint = 0n;
          let j: bigint = 0n;
          for (let i: bigint = 0n; i < 3n; j++) {
            sum = sum + start + i;
          }
          assert(sum === this.expected);
        }
      }
    TS
    ok, _hex, msg = compile_source(source, "OtherVar.runar.ts")
    refute ok, "`j++` advances a variable the loop model never binds"
    assert_includes msg, LOOP_UPDATE_DIAGNOSTIC
  end

  # The rejection must be a diagnostic, not a crash.
  def test_rejection_is_a_diagnostic_not_a_crash
    ok, _hex, msg = compile_source(ts_with_update("this.count++"), "UpdateProbe.runar.ts")
    refute ok
    refute_empty msg.strip, "rejection must carry a diagnostic, got an empty message"
  end

  # -------------------------------------------------------------------------
  # Controls: every shape that compiles today must still compile, byte-identical
  # -------------------------------------------------------------------------

  CONTROLS = [
    ["examples/ts/bounded-loop/BoundedLoop.runar.ts", "BoundedLoop.runar.ts"],
    ["examples/sol/bounded-loop/BoundedLoop.runar.sol", "BoundedLoop.runar.sol"],
    ["examples/go/bounded-loop/BoundedLoop.runar.go", "BoundedLoop.runar.go"],
    ["examples/move/bounded-loop/BoundedLoop.runar.move", "BoundedLoop.runar.move"],
    ["examples/python/bounded-loop/BoundedLoop.runar.py", "BoundedLoop.runar.py"],
    # `while (i < 5) : (i += 1)` -- the assignment spelling `i = i + 1`, which
    # the accepted set has to keep alongside `i++`.
    ["examples/zig/bounded-loop/BoundedLoop.runar.zig", "BoundedLoop.runar.zig"],
    # `i = i.plus(Bigint.ONE)` -- the Java surface's unit-step spelling.
    ["examples/java/src/main/java/runar/examples/bounded-loop/BoundedLoop.runar.java",
     "BoundedLoop.runar.java"]
  ].freeze

  def test_control_bounded_loop_bytes_unchanged
    CONTROLS.each do |rel, file_name|
      ok, hex, msg = compile_source(example(rel), file_name)
      assert ok, "#{file_name} must still compile: #{msg}"
      assert_equal BOUNDED_LOOP_HEX, hex, "#{file_name}: lowering moved bytes"
    end
  end

  # `i--` with `>`: guards against an accepted set that only counts up.
  def test_control_countdown_still_compiles
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Countdown extends SmartContract {
        readonly expected: bigint;

        constructor(expected: bigint) { super(expected); this.expected = expected; }

        public verify(start: bigint): void {
          let sum: bigint = 0n;
          for (let i: bigint = 3n; i > 0n; i--) {
            sum = sum + start + i;
          }
          assert(sum === this.expected);
        }
      }
    TS
    ok, _hex, msg = compile_source(source, "Countdown.runar.ts")
    assert ok, "a countdown loop must still compile: #{msg}"
  end
end
