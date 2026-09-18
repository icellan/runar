# frozen_string_literal: true

# R-189 — a private method may shadow a builtin, and nothing upstream of ANF
# lowering notices when the two disagree about arity.
#
# Typecheck resolves a BARE-IDENTIFIER call against the builtin table BEFORE it
# looks at the contract's own methods; ANF lowering resolves the same call
# against private methods FIRST. So `min(x, y)` against `private min(a, b, c)`
# type-checks as the two-argument BUILTIN `min` and then lowers as the
# three-parameter METHOD `min`. No validator forbids the shadowing.
#
# The zip that bound params to args stopped at the shorter list. When the
# surplus parameter was never read the contract compiled CLEAN — an arity
# mismatch silently accepted. When it was read, the defect surfaced two passes
# later as "method parameter 'c' is not on the stack", a stack-lowering message
# about a pass the author never wrote in.
#
# The compiler is invoked via subprocess for the same reason as
# test_conformance_goldens.rb: the Ruby compiler's TS and Ruby parsers share a
# constant namespace, so running them in-process corrupts tokenization.

require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class R189PrivateCallArityTest < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')

  # The silent case: `c` is never read, so nothing downstream ever noticed.
  SURPLUS_PARAM_UNREAD = <<~TS
    class R189Unread extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      private min(a: bigint, b: bigint, c: bigint): bigint {
        this.count = a + b;
        this.addOutput(1000n, this.count);
        return a;
      }

      public go(x: bigint, y: bigint) {
        min(x, y);
      }
    }
  TS

  # Too many arguments: `y` was evaluated and then dropped on the floor.
  TOO_MANY_ARGS = <<~TS
    class R189Extra extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      private min(a: bigint): bigint {
        this.count = a;
        this.addOutput(1000n, this.count);
        return a;
      }

      public go(x: bigint, y: bigint) {
        min(x, y);
      }
    }
  TS

  # Control 1: the SAME builtin-shadowing private, called at its real arity
  # through `this.` — the bare form cannot reach pass 4 at arity 3, because
  # pass 3 checks it against the two-argument BUILTIN `min` and refuses.
  CONTROL_SHADOWING_AT_REAL_ARITY = <<~TS
    class R189ControlShadow extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      private min(a: bigint, b: bigint, c: bigint): bigint {
        this.count = a + b + c;
        this.addOutput(1000n, this.count);
        return a;
      }

      public go(x: bigint, y: bigint, z: bigint) {
        this.min(x, y, z);
      }
    }
  TS

  # Control 2: an ordinary private helper, bare-identifier call at matching
  # arity — the Move / Go-DSL lowering path this refusal sits directly on.
  # Without the controls, a refusal that simply rejected every private call
  # would pass both tests above.
  CONTROL_PLAIN_PRIVATE = <<~TS
    class R189ControlPlain extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      private tally(a: bigint, b: bigint): bigint {
        this.count = a + b;
        this.addOutput(1000n, this.count);
        return a;
      }

      public go(x: bigint, y: bigint) {
        tally(x, y);
      }
    }
  TS

  # Compile to ANF IR. Returns [success?, combined output].
  def compile_to_ir(source, file_name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      stdout, stderr, status = Open3.capture3(
        RbConfig.ruby, RUBY_CLI, '--source', path, '--emit-ir'
      )
      [status.success?, "#{stdout}\n#{stderr}"]
    end
  end

  def assert_arity_refusal(source, file_name, expected)
    ok, out = compile_to_ir(source, file_name)
    refute ok, "arity mismatch was accepted: ANF lowering produced a program"
    assert_includes out, expected, "refusal does not name the mismatch"
  end

  def test_surplus_parameter_is_refused_not_silently_dropped
    assert_arity_refusal(SURPLUS_PARAM_UNREAD, 'R189Unread.runar.ts',
                         "private method 'min' expects 3 argument(s), got 2.")
  end

  def test_surplus_argument_is_refused_not_silently_dropped
    assert_arity_refusal(TOO_MANY_ARGS, 'R189Extra.runar.ts',
                         "private method 'min' expects 1 argument(s), got 2.")
  end

  def test_shadowing_private_at_real_arity_still_lowers
    ok, out = compile_to_ir(CONTROL_SHADOWING_AT_REAL_ARITY, 'R189ControlShadow.runar.ts')
    assert ok, "control must still lower: #{out}"
  end

  def test_plain_private_helper_still_lowers
    ok, out = compile_to_ir(CONTROL_PLAIN_PRIVATE, 'R189ControlPlain.runar.ts')
    assert ok, "control must still lower: #{out}"
  end
end
