# frozen_string_literal: true

# Audit C3 -- property initializers are restricted to literal values.
#
# `ts`, `go` and `java` enforced this; `rust`, `zig`, `python` and `ruby` did
# not -- they compiled e.g. `p: bigint = 1n + 2n;` and emitted a deployable
# locking script for a program the language does not define.
#
# Mirrors packages/runar-compiler/src/__tests__/property-initializer-literal.test.ts

require_relative "test_helper"

require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/parser_ts"

class TestPropertyInitializerLiteral < Minitest::Test
  include RunarCompiler::Frontend

  # The cross-tier diagnostic substring.
  NON_LITERAL_INIT = "initializer must be a literal value"

  def validate_source(source, file_name = "Test.runar.ts")
    result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil result.contract, "expected a contract from parsing"
    RunarCompiler::Frontend.validate(result.contract)
  end

  def assert_non_literal_init_error(result)
    assert result.errors.any? { |e| e.message.include?(NON_LITERAL_INIT) },
           "expected a non-literal-initializer error, got: #{result.error_strings}"
  end

  def test_rejects_arithmetic_property_initializer
    source = <<~TS
      import { StatefulSmartContract, Addr } from 'runar-lang';

      class Bad extends StatefulSmartContract {
        count: bigint = 1n + 2n;
        readonly owner: Addr;

        constructor(owner: Addr) {
          super(owner);
          this.owner = owner;
        }

        public bump() {
          this.count = this.count + 1n;
        }
      }
    TS
    assert_non_literal_init_error(validate_source(source))
  end

  def test_rejects_call_expression_property_initializer
    source = <<~TS
      import { StatefulSmartContract, Addr } from 'runar-lang';

      class Bad2 extends StatefulSmartContract {
        count: bigint = abs(-3n);
        readonly owner: Addr;

        constructor(owner: Addr) {
          super(owner);
          this.owner = owner;
        }

        public bump() {
          this.count = this.count + 1n;
        }
      }
    TS
    assert_non_literal_init_error(validate_source(source))
  end

  def test_accepts_literal_property_initializers
    source = <<~TS
      import { StatefulSmartContract, Addr, ByteString } from 'runar-lang';

      class Good extends StatefulSmartContract {
        count: bigint = 7n;
        flag: boolean = true;
        tag: ByteString = 'deadbeef';
        offset: bigint = -3n;
        readonly owner: Addr;

        constructor(owner: Addr) {
          super(owner);
          this.owner = owner;
        }

        public bump() {
          this.count = this.count + 1n;
        }
      }
    TS
    result = validate_source(source)
    assert_empty result.error_strings
  end

  # ---------------------------------------------------------------------------
  # `toByteString('<hex>')` IS the ByteStringLiteral production -- see
  # spec/grammar.md section 11:
  #
  #     ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
  #
  # 0e192af6 folded it in ANF lowering, which covers every EXPRESSION position.
  # A property INITIALIZER is not one: the validator runs on the AST, BEFORE
  # ANF lowering, and still saw a call node. The `.runar.rs` surface needs
  # exactly this spelling in exactly this position -- the Rust DSL writes
  # initializers as assignments inside `init()` that the parser LIFTS into
  # `PropertyNode.initializer`, and a bare `"1976a914"` is a `&str` that cannot
  # be assigned to a `ByteString` (`Vec<u8>`).
  #
  # Both halves are asserted: accepting it in the validator alone yields a
  # property that validates and then loses its default, because
  # `_extract_literal_value` returns nil for a call node.
  # ---------------------------------------------------------------------------

  TO_BYTE_STRING_INIT = <<~TS
    import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

    class Wrapped extends SmartContract {
      readonly prefix: ByteString = toByteString('1976a914');
      readonly owner: Addr;

      constructor(owner: Addr) {
        super(owner);
        this.owner = owner;
      }

      public unlock(x: ByteString): void {
        assert(x === this.prefix);
      }
    }
  TS

  def test_accepts_to_byte_string_literal_property_initializer
    result = validate_source(TO_BYTE_STRING_INIT)
    assert_empty result.error_strings
  end

  def test_unwraps_to_byte_string_literal_initializer_in_anf
    require "runar_compiler/cli"
    require "json"

    anf_of = lambda do |src|
      parsed = RunarCompiler.send(:_parse_source, src, "Test.runar.ts")
      refute_nil parsed.contract, "expected a contract from parsing"
      RunarCompiler::Frontend.lower_to_anf(parsed.contract)
    end

    wrapped = anf_of.call(TO_BYTE_STRING_INIT)
    bare = anf_of.call(TO_BYTE_STRING_INIT.sub("toByteString('1976a914')", "'1976a914'"))

    # Half two: a bare value, not a call node and not a dropped default.
    assert_equal "1976a914", wrapped.properties[0].initial_value

    # ...and the whole program is indistinguishable from the bare spelling,
    # which is what keeps expected-ir.json from moving.
    assert_equal JSON.generate(RunarCompiler::CLI.send(:_anf_to_camel_dict, bare)),
                 JSON.generate(RunarCompiler::CLI.send(:_anf_to_camel_dict, wrapped)),
                 "wrapped ANF must be byte-identical to the bare-literal ANF"
  end

  def test_rejects_to_byte_string_non_literal_property_initializer
    # Not the ByteStringLiteral production -- a real call, and a call is not a
    # literal. Guards the accept from widening into "any toByteString call".
    source = <<~TS
      import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

      class Bad3 extends SmartContract {
        readonly prefix: ByteString = toByteString(someIdent);
        readonly owner: Addr;

        constructor(owner: Addr) {
          super(owner);
          this.owner = owner;
        }

        public unlock(x: ByteString): void {
          assert(x === this.prefix);
        }
      }
    TS
    assert_non_literal_init_error(validate_source(source))
  end
end
