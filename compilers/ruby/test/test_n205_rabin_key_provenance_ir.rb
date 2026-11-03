# frozen_string_literal: true

# N-205 (b): the IR loader refuses a verifyRabinSig key the spender supplies
# (a load_param), with the diagnostic shared by all 7 tiers
# (conformance/negatives/ir-rabin-key-provenance.test.ts holds the corpus,
# including the update_prop / add_output write cases and the helper / alias /
# if-phi accept cases).
#
# Proves: the F-286 attack on IR (oracle-price with its key binding swapped for
# a public load_param) is refused at load time with the shared words, and the
# oracle-price golden still loads. Does not prove the rest of the rule, which
# the conformance corpus covers in every tier.

require_relative "test_helper"
require "json"
require "runar_compiler/ir/loader"

class TestN205RabinKeyProvenanceIR < Minitest::Test
  REPO_ROOT = File.expand_path("../../..", __dir__)

  def golden
    JSON.parse(File.read(File.join(REPO_ROOT, "conformance", "tests", "oracle-price", "expected-ir.json")))
  end

  def test_public_load_param_key_is_refused_with_the_shared_diagnostic
    ir = golden
    settle = ir["methods"].find { |m| m["name"] == "settle" }
    settle["params"] << { "name" => "n", "type" => "RabinPubKey" }
    settle["body"].find { |b| b["name"] == "t5" }["value"] = { "kind" => "load_param", "name" => "n" }
    err = assert_raises(ArgumentError) { RunarCompiler::IR.load_ir(JSON.generate(ir)) }
    assert_equal "IR validation: method 'settle': verifyRabinSig public key (4th argument) must be a " \
                 "contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature",
                 err.message
  end

  def test_oracle_price_golden_still_loads
    RunarCompiler::IR.load_ir(JSON.generate(golden))
  end
end
