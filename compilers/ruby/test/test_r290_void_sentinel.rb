# frozen_string_literal: true

# R-290 — `inline_private_method_call` used to emit a `load_const "@void"`
# sentinel when the inlined body produced no bindings.
#
# No tier's stack lowering recognises "@void" (unlike "@this", which IS
# special-cased), so the sentinel survived pass 4 and died in the hex decoder:
# Go said `invalid byte: U+0040 '@'`, Rust said `invalid hex string length: 5`.
# Neither names the method or the problem, and both fire only because the
# string happens to be odd-length and non-hex — an even-length sentinel would
# decode to zeros in Rust's `from_str_radix(..).unwrap_or(0)` and reach the
# script.
#
# In the Go / Rust / Python / TypeScript tiers it is REACHABLE: their
# side-effect summary resolves a called name through a LAST-WINS map and caches
# the result under that name, while `getPrivateMethod` returns the FIRST match.
# Declare the public caller BEFORE two same-named privates and the two
# disagree — the summary describes the output-emitting `helper`, so inlining
# fires, while the lowerer inlines the EMPTY one. Measured on the Go CLI
# pre-fix: `--emit-ir` exit 0 with "@void" in the IR, `--hex` exit 1 in the hex
# decoder.
#
# This tier is NOT reachable that way: `should_inline_private?` asks
# `get_private_method` — the same first-match lookup the inliner uses — so the
# two cannot disagree, and the duplicate-name contract simply never inlines.
# The refusal still ships here, because the sentinel must not exist in any
# tier and because the tiers' inline-decision paths have drifted before. The
# test below therefore pins the INVARIANT rather than the refusal: whatever
# this tier does with that contract, no "@void" may survive into the IR. If a
# future change routes this tier's inline decision through a summary map, the
# contract starts refusing and the first branch takes over.
#
# The compiler is invoked via subprocess for the same reason as
# test_conformance_goldens.rb: the Ruby compiler's TS and Ruby parsers share a
# constant namespace, so running them in-process corrupts tokenization.

require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class R290VoidSentinelTest < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')

  EMPTY_INLINED_BODY = <<~TS
    class R290Void extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      public go(x: bigint) {
        this.count = x;
        this.helper();
      }

      private helper(): void {
      }

      private helper(): void {
        this.addOutput(1000n, this.count);
      }
    }
  TS

  # Control: the ordinary shape — one private helper that really does emit an
  # output. The inlining path must still work; a refusal that simply rejected
  # every inlined private would pass the test above.
  CONTROL_EMITTING_HELPER = <<~TS
    class R290Control extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      public go(x: bigint) {
        this.count = x;
        this.helper();
      }

      private helper(): void {
        this.addOutput(1000n, this.count);
      }
    }
  TS

  def compile_to_ir(source, file_name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      stdout, stderr, status = Open3.capture3(
        RbConfig.ruby, RUBY_CLI, '--source', path, '--emit-ir'
      )
      [status.success?, stdout, "#{stdout}\n#{stderr}"]
    end
  end

  def test_empty_inlined_body_never_yields_a_sentinel
    ok, ir, out = compile_to_ir(EMPTY_INLINED_BODY, 'R290Void.runar.ts')
    if ok
      refute_includes ir, '@void',
                      'the empty inlined body produced the @void sentinel instead of a refusal'
    else
      assert_includes out,
                      "private method 'helper' was inlined but produced no bindings",
                      'refused, but not with the R-290 diagnostic'
    end
  end

  def test_no_void_sentinel_remains
    ok, ir, out = compile_to_ir(CONTROL_EMITTING_HELPER, 'R290Control.runar.ts')
    assert ok, "control must lower: #{out}"
    refute_includes ir, '@void', 'the @void sentinel is still emitted somewhere'
  end

  def test_emitting_helper_still_inlines
    ok, _ir, out = compile_to_ir(CONTROL_EMITTING_HELPER, 'R290Control.runar.ts')
    assert ok, "control must still lower: #{out}"
  end
end
