# frozen_string_literal: true

require_relative "test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/anf_lower"
require "runar_compiler/frontend/parser_ts"

# N-006 / CL-BUG-186 -- the pass-4 backstop behind R-127.
#
# R-127 is a syntactic search in the validator. `Frontend.lower_to_anf` is
# public, so a caller can lower a parsed contract having run no validator at
# all, and `_lower_for_statement` used to drop the body sub-context's output
# refs without a word: the loop's outputs were built but left out of the
# continuation hash, so a spender could drop them (proven on @bsv/sdk Spend for
# the TS and Go tiers in
# packages/runar-testing/src/__tests__/f005-go-loop-output-continuation.test.ts).
#
# What this proves: this tier's pass 4 refuses a loop whose body registered an
# output ref, with R-127's shared diagnostic, whatever let the contract past
# passes 1-3; a loop with no output in it still lowers.
# What it does not prove: anything about emitted bytes.
class TestN006LoopOutputLoweringBackstop < Minitest::Test
  HEAD = <<~TS
    import { StatefulSmartContract, ByteString, assert, num2bin } from 'runar-lang';

    class Fan extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }
  TS

  def lower_unvalidated(method)
    parse_result = RunarCompiler.send(:_parse_source, "#{HEAD}#{method}\n}\n", "Fan.runar.ts")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    RunarCompiler::Frontend.lower_to_anf(parse_result.contract)
    nil
  rescue StandardError => e
    e.message
  end

  def test_array_literal_raw_output_in_loop_is_refused_at_lowering
    msg = lower_unvalidated(<<~TS)
      public fan(n: bigint) {
        this.addOutput(1000n, this.count + 1n);
        for (let i = 0n; i < 2n; i++) {
          const xs = [this.addRawOutput(n, num2bin(i, 4n))];
        }
      }
    TS
    refute_nil msg, "lower_to_anf accepted an output intrinsic inside a loop body"
    assert_includes msg, "Output intrinsic 'addRawOutput' cannot be called inside a loop body."
  end

  def test_add_output_and_data_output_in_loop_are_refused_at_lowering
    out = lower_unvalidated(<<~TS)
      public fan(n: bigint) {
        this.addOutput(1000n, this.count);
        for (let i = 0n; i < 2n; i++) {
          this.addOutput(1000n, this.count + i);
        }
        assert(n > 0n);
      }
    TS
    refute_nil out, "addOutput in a loop lowered"
    assert_includes out, "Output intrinsic 'addOutput' cannot be called inside a loop body."

    data = lower_unvalidated(<<~TS)
      public fan(n: bigint) {
        for (let i = 0n; i < 2n; i++) {
          if (i < n) {
            this.addDataOutput(0n, num2bin(i, 4n));
          }
        }
        this.count = this.count + 1n;
      }
    TS
    refute_nil data, "addDataOutput in a loop lowered"
    assert_includes data, "Output intrinsic 'addDataOutput' cannot be called inside a loop body."
  end

  def test_control_loop_without_outputs_still_lowers
    assert_nil lower_unvalidated(<<~TS)
      public fan(n: bigint) {
        let acc: bigint = 0n;
        for (let i = 0n; i < 2n; i++) {
          acc = acc + n;
        }
        this.addOutput(1000n, this.count + acc);
      }
    TS
  end
end
