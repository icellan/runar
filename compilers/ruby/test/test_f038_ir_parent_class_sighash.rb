# frozen_string_literal: true

# F-038 / F-065 / F-066 / F-070 / F-088: --emit-ir -> --ir is lossless for the
# two fields the SDK signs by.
#
# Before: +parent_class+ and the method +sighash_type+ were in-memory carriers
# excluded from the ANF wire format, so an artifact compiled with --ir had no
# +parentClass+ (the SDK then skips the issue-#44 subscript trim for a
# StatefulSmartContract with zero mutable fields) and no
# +abi.methods[].sigHashType+ (the SDK then builds an ALL|FORKID preimage for a
# covenant asserting another mode). Same script bytes, unspendable contract.
#
# Proves: the emitted IR carries +parentClass+ and a non-default
# +sigHashType+ (and omits the default), and the --ir artifact equals the
# --source artifact on script, parentClass, abi and stateFields for a
# zero-mutable stateful contract, a FixedArray stateful contract and a
# @sighash covenant. Does not prove: the SDK spend (conformance/ir-roundtrip
# drives the TS SDK on this tier's artifacts) or the loader's refusal of
# malformed values (test_n069_ir_required_fields.rb, shared corpus).

require_relative "test_helper"
require "json"
require "open3"
require "tmpdir"

class TestF038IRParentClassSighash < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path("..", __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, "bin/runar-compiler-ruby")
  REPO_ROOT = File.expand_path("../..", RUBY_COMPILER_DIR)

  ZERO_MUTABLE = File.join(REPO_ROOT, "examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts")
  FIXED_ARRAY = File.join(REPO_ROOT, "examples/ts/fixed-array-write/ArrayWrite.runar.ts")

  SIGHASH_COUNTER = <<~TS
    import { StatefulSmartContract, assert } from 'runar-lang';

    class SighashCounter extends StatefulSmartContract {
      count: bigint;

      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      /** @sighash ALL|ANYONECANPAY|FORKID */
      public increment(): void {
        this.count = this.count + 1n;
        assert(true);
      }

      public reset(): void {
        this.count = 0n;
        assert(true);
      }
    }
  TS

  def run_cli(*args)
    out, err, st = Open3.capture3("ruby", "-I", File.join(RUBY_COMPILER_DIR, "lib"), RUBY_CLI, *args)
    assert st.success?, "ruby #{args.join(' ')} failed: #{err}"
    out
  end

  # [direct_artifact, via_ir_artifact, emitted_ir]
  def round_trip(path)
    Dir.mktmpdir("f038") do |dir|
      direct = JSON.parse(run_cli("--source", path))
      ir = run_cli("--source", path, "--emit-ir")
      ir_path = File.join(dir, "ir.json")
      File.write(ir_path, ir)
      return [direct, JSON.parse(run_cli("--ir", ir_path)), JSON.parse(ir)]
    end
  end

  def with_counter
    Dir.mktmpdir("f038src") do |dir|
      path = File.join(dir, "SighashCounter.runar.ts")
      File.write(path, SIGHASH_COUNTER)
      yield path
    end
  end

  def assert_same_artifact(direct, via_ir)
    # Compared as [present?, value] so an absent key on both sides is equal
    # without assert_equal(nil, ...) and a key dropped on one side is not.
    %w[script parentClass abi stateFields].each do |k|
      assert_equal [direct.key?(k), direct[k]], [via_ir.key?(k), via_ir[k]], "artifact #{k} differs"
    end
  end

  def test_zero_mutable_stateful_keeps_parent_class
    direct, via_ir, ir = round_trip(ZERO_MUTABLE)
    assert_equal "StatefulSmartContract", ir["parentClass"]
    assert_equal "StatefulSmartContract", direct["parentClass"]
    assert_same_artifact(direct, via_ir)
  end

  def test_fixed_array_stateful_round_trips
    direct, via_ir, ir = round_trip(FIXED_ARRAY)
    assert_equal "StatefulSmartContract", ir["parentClass"]
    assert_same_artifact(direct, via_ir)
  end

  def test_non_default_sighash_rides_on_the_method
    with_counter do |path|
      direct, via_ir, ir = round_trip(path)
      by_name = ir["methods"].to_h { |m| [m["name"], m] }
      assert_equal 0xc1, by_name["increment"]["sigHashType"]
      refute by_name["reset"].key?("sigHashType"), "the default ALL|FORKID must be omitted"
      refute by_name["increment"].key?("sighash_type")
      assert_equal 0xc1, direct["abi"]["methods"].find { |m| m["name"] == "increment" }["sigHashType"]
      assert_same_artifact(direct, via_ir)
    end
  end
end
