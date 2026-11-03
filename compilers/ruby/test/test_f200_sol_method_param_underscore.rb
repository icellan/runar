# frozen_string_literal: true

require_relative "test_helper"

require "digest"
require "tmpdir"
require "runar_compiler/compiler"
require "runar_compiler/frontend/parser_sol"

# F-200 (CL-BUG-208..213) -- .runar.sol leading-underscore stripping applies
# to CONSTRUCTOR params only. Port of
# compilers/python/tests/test_f200_sol_method_param_underscore.py.
#
# parse_sol_params stripped a leading `_` from every parameter, so a METHOD
# param `_x` was declared as `x` while its body still read `_x`:
#   * unbound: `function check(bigint _x) public { require(_x == target); }`
#     failed typecheck with "Undefined variable '_x'" (TS compiles it);
#   * silent: `function inc(bigint _count) public { count++; }` declared a
#     param named `count` that shadowed the property, so `count++` bumped the
#     param and the state write was dropped -- a different script.
# The rule is the TS reference's (01-parse-sol.ts): parseConstructor strips
# `_` and renames the body; parseFunction keeps param names verbatim.
#
# Proves: in the Ruby tier, method params keep their `_` name, the constructor
# still strips it, and both shapes compile (fold-ON default) to the TS
# reference bytes (same pins as
# conformance/negatives/sol-method-param-underscore-parity.test.ts).
# Does NOT prove: other tiers (that conformance test) or on-chain behaviour.
class TestF200SolMethodParamUnderscore < Minitest::Test
  UNBOUND = <<~SOL
    pragma runar ^0.1.0;

    contract F200Unbound is SmartContract {
        bigint immutable target;

        constructor(bigint _target) {
            target = _target;
        }

        function check(bigint _x) public {
            require(_x == target);
        }
    }
  SOL

  SILENT = <<~SOL
    pragma runar ^0.1.0;

    contract F200Silent is StatefulSmartContract {
        bigint count;

        constructor(bigint _count) {
            count = _count;
        }

        function inc(bigint _count) public {
            count++;
        }
    }
  SOL

  UNBOUND_HEX = "009c"
  SILENT_SHA256 = "3676c0b9030628828837696cad74c710bb225d151f5ba822be8b2ed302e3a342"

  def parse(source, file_name)
    result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty result.errors.map(&:format_message)
    result.contract
  end

  def script_hex(source, file_name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      RunarCompiler.compile_from_source(path).script
    end
  end

  def test_method_param_keeps_underscore_and_constructor_strips
    c = parse(UNBOUND, "F200Unbound.runar.sol")
    assert_equal ["_x"], c.methods.find { |m| m.name == "check" }.params.map(&:name)
    assert_equal ["target"], c.constructor.params.map(&:name)
  end

  def test_unbound_shape_compiles_to_ts_bytes
    assert_equal UNBOUND_HEX, script_hex(UNBOUND, "F200Unbound.runar.sol")
  end

  def test_silent_shape_writes_state
    c = parse(SILENT, "F200Silent.runar.sol")
    m = c.methods.find { |x| x.name == "inc" }
    assert_equal ["_count"], m.params.map(&:name)
    assert_kind_of RunarCompiler::Frontend::PropertyAccessExpr, m.body[0].expr.operand
    assert_equal SILENT_SHA256, Digest::SHA256.hexdigest(script_hex(SILENT, "F200Silent.runar.sol"))
  end
end
