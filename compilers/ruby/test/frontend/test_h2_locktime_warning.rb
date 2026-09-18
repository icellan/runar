# frozen_string_literal: true

require_relative "../test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/parser_ts"

# ---------------------------------------------------------------------------
# H2 (#131): locktime soundness warning.
#
# A method that reads extractLocktime(preimage) only enforces a timelock if the
# covenant ALSO asserts the spending tx is non-final
# (extractSequence(preimage) < 0xffffffff). Without that, a hand-built
# all-final-sequence transaction bypasses the locktime gate. The compiler
# should emit an advisory WARNING (non-fatal) when a public method reads
# extractLocktime but does not (transitively) assert a sequence-finality guard.
# ---------------------------------------------------------------------------

class TestH2LocktimeWarning < Minitest::Test
  WARNING_NEEDLE = "does not assert extractSequence"

  def parse_contract(source, file_name = "TimeLock.runar.ts")
    result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil result.contract, "expected a contract from parsing"
    result.contract
  end

  def validate_source(source, file_name = "TimeLock.runar.ts")
    RunarCompiler::Frontend.validate(parse_contract(source, file_name))
  end

  def locktime_warning(result)
    result.warnings.find { |w| w.message.include?(WARNING_NEEDLE) }
  end

  def has_locktime_warning?(result)
    !locktime_warning(result).nil?
  end

  def test_warns_when_method_reads_locktime_without_sequence_guard
    source = <<~TS
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        public unlock() {
          assert(extractLocktime(this.txPreimage) >= this.deadline);
          this.count++;
        }
      }
    TS

    result = validate_source(source)
    assert has_locktime_warning?(result),
           "expected a locktime-without-sequence-guard warning"

    w = locktime_warning(result)
    assert_equal RunarCompiler::Frontend::Severity::WARNING, w.severity
    assert_includes w.message, "unlock"
    assert_includes w.message, "0xffffffff"
  end

  def test_does_not_warn_when_sequence_guard_present
    source = <<~TS
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        public unlock() {
          assert(extractSequence(this.txPreimage) < 0xffffffffn);
          assert(extractLocktime(this.txPreimage) >= this.deadline);
          this.count++;
        }
      }
    TS

    result = validate_source(source)
    refute has_locktime_warning?(result),
           "sequence guard present -- must not warn"
  end

  def test_warns_when_sequence_comparison_is_negated
    source = <<~TS
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        public unlock() {
          assert(!(extractSequence(this.txPreimage) !== 0xffffffffn));
          assert(extractLocktime(this.txPreimage) >= this.deadline);
          this.count++;
        }
      }
    TS

    result = validate_source(source)
    assert has_locktime_warning?(result),
           "negated sequence comparison must not count as a guard"
  end

  def test_does_not_warn_when_method_never_reads_locktime
    source = <<~TS
      class Counter extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) {
          super(count);
          this.count = count;
        }
        public increment() {
          this.count++;
        }
      }
    TS

    result = validate_source(source, "Counter.runar.ts")
    refute has_locktime_warning?(result),
           "no locktime read -- must not warn"
  end

  def test_sees_sequence_guard_supplied_transitively_through_private_helper
    source = <<~TS
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        private requireNonFinal() {
          assert(extractSequence(this.txPreimage) < 0xffffffffn);
        }
        public unlock() {
          this.requireNonFinal();
          assert(extractLocktime(this.txPreimage) >= this.deadline);
          this.count++;
        }
      }
    TS

    result = validate_source(source)
    refute has_locktime_warning?(result),
           "transitive sequence guard through a private helper -- must not warn"
  end

  def test_warns_when_locktime_read_in_private_helper_without_sequence_guard
    source = <<~TS
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        private checkDeadline() {
          assert(extractLocktime(this.txPreimage) >= this.deadline);
        }
        public unlock() {
          this.checkDeadline();
          this.count++;
        }
      }
    TS

    result = validate_source(source)
    assert has_locktime_warning?(result),
           "transitive locktime read through a private helper -- must warn"
  end

  def test_warns_when_comparison_is_assigned_not_asserted
    source = <<~TS
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        public unlock() {
          const ok: boolean = extractSequence(this.txPreimage) !== 0xffffffffn;
          assert(extractLocktime(this.txPreimage) >= this.deadline);
          this.count++;
        }
      }
    TS

    result = validate_source(source)
    assert has_locktime_warning?(result),
           "assigned comparison must not silence the warning"
  end

  def test_warns_for_vacuous_strict_bound
    source = <<~TS
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        public unlock() {
          assert(extractSequence(this.txPreimage) < 0n);
          assert(extractLocktime(this.txPreimage) >= this.deadline);
          this.count++;
        }
      }
    TS

    result = validate_source(source)
    assert has_locktime_warning?(result),
           "extractSequence < 0n is not a finality guard"
  end
end
