# frozen_string_literal: true

# N-011 — which class in a .runar.ts file is the contract.
#
# The TS reference (packages/runar-compiler/src/passes/01-parse.ts) walks EVERY
# class and keeps only one whose `extends` names a valid base
# (SmartContract / StatefulSmartContract / UnsafeSmartContract):
#   * classes with no `extends` or another base are ignored, wherever they sit;
#   * several valid classes -> "Only one SmartContract subclass is allowed per
#     file" at each valid class after the first (the LAST one is kept);
#   * no valid class -> "No class extending SmartContract,
#     StatefulSmartContract, or UnsafeSmartContract found" at 1:0.
#
# Pre-fix this parser returned on the FIRST `class` token and defaulted a
# missing `extends` to SmartContract, so a leading helper was compiled as the
# contract. In DECOY_FIRST the helper's `unlock` accepts every preimage EXCEPT
# the real one. The real-engine proof is
# packages/runar-testing/src/__tests__/n011-ts-class-selection-vm.test.ts.
#
# Expected values were captured by running the TS reference on the same shapes
# (remediation-logs/F-016/ts-reference-testshapes.txt), not read from its code.
#
# What this proves: the Ruby .runar.ts parser picks the same class and parent
# and emits the same diagnostics (message + line:column) as the TS reference on
# the seven F-016 shapes. What it does NOT prove: the other Ruby-tier surfaces.

require_relative 'test_helper'
require 'runar_compiler/frontend/parser_ts'

class TestN011TsContractClassSelection < Minitest::Test
  NO_CLASS = 'No class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found'
  ONLY_ONE = 'Only one SmartContract subclass is allowed per file'

  IMPORTS = "import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';\n\n"

  HASHLOCK = <<~TS
    export class HashLock extends SmartContract {
      readonly hashValue: Sha256;

      constructor(hashValue: Sha256) {
        super(hashValue);
        this.hashValue = hashValue;
      }

      public unlock(preimage: ByteString) {
        assert(sha256(preimage) === this.hashValue);
      }
    }
  TS

  DECOY = <<~TS
    class Helper {
      readonly hashValue: Sha256;

      constructor(hashValue: Sha256) {
        super(hashValue);
        this.hashValue = hashValue;
      }

      public unlock(preimage: ByteString) {
        assert(sha256(preimage) !== this.hashValue);
      }
    }
  TS

  FOREIGN = DECOY.sub('class Helper {', 'class Helper extends Base {')

  TWO_VALID = IMPORTS + <<~TS + "\n" + HASHLOCK
    export class First extends SmartContract {
      constructor() {
        super();
      }

      public unlock(preimage: ByteString) {
        assert(true);
      }
    }
  TS

  THREE_VALID = <<~TS
    import { SmartContract, assert } from 'runar-lang';

    export class A extends SmartContract {
      constructor() { super(); }
      public unlock(x: bigint) { assert(x === 1n); }
    }
    export class B extends SmartContract {
      constructor() { super(); }
      public unlock(x: bigint) { assert(x === 2n); }
    }
    export class C extends SmartContract {
      constructor() { super(); }
      public unlock(x: bigint) { assert(x === 3n); }
    }
  TS

  def parse(src)
    RunarCompiler::Frontend.parse_ts(src, 'Probe.runar.ts')
  end

  def diags(res)
    res.errors.map { |e| [e.message, e.loc&.line, e.loc&.column] }
  end

  def assert_selects_hashlock(src)
    res = parse(src)
    assert_empty res.errors.map(&:message)
    refute_nil res.contract
    assert_equal 'HashLock', res.contract.name
    assert_equal 'SmartContract', res.contract.parent_class
  end

  def test_decoy_first_selects_the_extending_class
    assert_selects_hashlock(IMPORTS + DECOY + "\n" + HASHLOCK)
  end

  def test_foreign_base_first_selects_the_extending_class
    assert_selects_hashlock(IMPORTS + FOREIGN + "\n" + HASHLOCK)
  end

  def test_contract_first_then_helper
    assert_selects_hashlock(IMPORTS + HASHLOCK + "\n" + DECOY)
  end

  def test_no_extends_only_is_refused
    res = parse(IMPORTS + DECOY)
    assert_nil res.contract
    assert_equal [[NO_CLASS, 1, 0]], diags(res)
  end

  def test_foreign_base_only_is_refused
    res = parse(IMPORTS + FOREIGN)
    assert_nil res.contract
    assert_equal [[NO_CLASS, 1, 0]], diags(res)
  end

  def test_two_valid_reports_the_second_and_keeps_the_last
    res = parse(TWO_VALID)
    assert_equal [[ONLY_ONE, 13, 0]], diags(res)
    assert_equal 'HashLock', res.contract&.name
  end

  def test_three_valid_reports_each_extra_class
    res = parse(THREE_VALID)
    assert_equal [[ONLY_ONE, 7, 0], [ONLY_ONE, 11, 0]], diags(res)
    assert_equal 'C', res.contract&.name
  end
end
