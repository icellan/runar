# frozen_string_literal: true

require_relative 'test_helper'

# Edge-case coverage for the .runar.ts (TypeScript) surface parser as
# exercised by the Ruby compiler's TS frontend. The base test_parser_ts.rb
# covers 5 happy-path shapes; this file adds depth around property
# initializers, addOutput/addRawOutput intrinsics, ByteString literals,
# multi-output stateful flows, and parser robustness.

class TestParserTSEdges < Minitest::Test
  require 'runar_compiler/frontend/parser_ts'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.ts')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def test_property_initializer_captured
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Init extends SmartContract {
        readonly x: bigint = 42n;

        constructor() {
          super();
        }

        public check(): void {
          assert(this.x > 0n);
        }
      }
    TS

    result = parse(source, 'Init.runar.ts')
    assert_empty result.errors.map(&:format_message), result.error_strings.join('; ')
    prop = result.contract.properties.first
    refute_nil prop.initializer
    assert_instance_of BigIntLiteral, prop.initializer
    assert_equal 42, prop.initializer.value
  end

  def test_bool_property_initializer
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Flag extends SmartContract {
        readonly flag: boolean = true;

        constructor() {
          super();
        }

        public check(): void {
          assert(this.flag);
        }
      }
    TS

    result = parse(source, 'Flag.runar.ts')
    assert_empty result.errors.map(&:format_message)
    init = result.contract.properties.first.initializer
    refute_nil init
    assert_instance_of BoolLiteral, init
    assert_equal true, init.value
  end

  def test_bytestring_literal_initializer
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class HexProp extends SmartContract {
        readonly tag: ByteString = "deadbeef";

        constructor() {
          super();
        }

        public check(): void {
          assert(this.tag === this.tag);
        }
      }
    TS

    result = parse(source, 'HexProp.runar.ts')
    assert_empty result.errors.map(&:format_message)
    init = result.contract.properties.first.initializer
    refute_nil init
    assert_instance_of ByteStringLiteral, init
    assert_equal 'deadbeef', init.value
  end

  def test_add_output_intrinsic
    source = <<~TS
      import { StatefulSmartContract } from 'runar-lang';

      class Out extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public bump(): void {
          this.count = this.count + 1n;
          this.addOutput(1000n, this.count);
        }
      }
    TS

    result = parse(source, 'Out.runar.ts')
    assert_empty result.errors.map(&:format_message)
    refute_nil result.contract
  end

  def test_add_raw_output_intrinsic
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Raw extends SmartContract {
        readonly script: ByteString;

        constructor(script: ByteString) {
          super(script);
          this.script = script;
        }

        public check(amount: bigint): void {
          this.addRawOutput(amount, this.script);
          assert(amount > 0n);
        }
      }
    TS

    result = parse(source, 'Raw.runar.ts')
    assert_empty result.errors.map(&:format_message),
                 "addRawOutput should parse, got: #{result.error_strings}"
  end

  def test_multiple_private_helpers
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Helpers extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        private double(): bigint {
          return this.x * 2n;
        }

        private triple(): bigint {
          return this.x * 3n;
        }

        public check(): void {
          assert(this.double() + this.triple() > 0n);
        }
      }
    TS

    result = parse(source, 'Helpers.runar.ts')
    assert_empty result.errors.map(&:format_message)
    privs = result.contract.methods.select { |m| m.visibility == 'private' }
    assert_equal %w[double triple], privs.map(&:name)
  end

  def test_conditional_in_method_body
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class Cond extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          if (a > 0n) {
            assert(a > this.x);
          } else {
            assert(a < this.x);
          }
        }
      }
    TS

    result = parse(source, 'Cond.runar.ts')
    assert_empty result.errors.map(&:format_message)
  end

  def test_garbage_input_yields_errors
    result = parse('@@@ not typescript $$$', 'garbage.runar.ts')
    refute_nil result.errors
    # Either contract is nil OR there are errors — both are OK.
    bad = result.contract.nil? || !result.errors.empty?
    assert bad, 'expected diagnostics or nil contract for garbage input'
  end
end
