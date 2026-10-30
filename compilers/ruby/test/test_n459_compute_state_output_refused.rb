# frozen_string_literal: true

# N-459: `computeStateOutput` is a compiler-internal call (anf_lower emits it for
# the single-output stateful continuation) that the Ruby typecheck table
# declares so the IR loader and anf_lower can read its signature. A SOURCE call
# to it used to pass typecheck and then die in stack lowering with
# `value "_codePart" not found on stack`. The other six tiers refuse it in
# typecheck as `unknown function 'computeStateOutput'`.
#
# What this proves: a source call to computeStateOutput is refused at typecheck
# with the peers' "unknown function" diagnostic (TS surface), while an ordinary
# stateful contract (which makes the compiler emit computeStateOutput itself)
# still compiles.
# What it does NOT prove: IR-path acceptance of the builtin (covered by the
# R-165 loader tests) or the other tiers' behaviour.
#
# Subprocess invocation, as in test_n002: parsers share a constant namespace.

require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class N459ComputeStateOutputRefusedTest < Minitest::Test
  RUBY_CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)

  CALLER = <<~TS
    import { SmartContract, ByteString, assert } from 'runar-lang';

    class C extends SmartContract {
      readonly h: ByteString;

      constructor(h: ByteString) {
        super(h);
        this.h = h;
      }

      public unlock(b: ByteString) {
        const o = computeStateOutput(b, b, 1n);
        assert(o === this.h);
      }
    }
  TS

  COUNTER = <<~TS
    import { StatefulSmartContract, assert } from 'runar-lang';

    class Counter extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      public inc() {
        this.count = this.count + 1n;
        assert(true);
      }
    }
  TS

  def run_cli(src, name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, name)
      File.write(path, src)
      out, status = Open3.capture2e('ruby', RUBY_CLI, '--source', path)
      [out, status]
    end
  end

  def test_source_call_refused_at_typecheck
    out, status = run_cli(CALLER, 'C.runar.ts')
    refute status.success?, out
    assert_includes out, "unknown function 'computeStateOutput'"
    refute_includes out, '_codePart'
  end

  def test_internal_use_still_compiles
    out, status = run_cli(COUNTER, 'Counter.runar.ts')
    assert status.success?, out
  end
end
