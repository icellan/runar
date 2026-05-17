# frozen_string_literal: true

require_relative "test_helper"

require "tmpdir"
require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/anf_lower"
require "runar_compiler/frontend/parser_go"

# Tests for the BSVM Phase 13 intent sub-covenant intrinsics in the Ruby
# compiler tier. Direct port of compilers/go/frontend/intent_intrinsics_test.go.
# All three intrinsics are pure frontend sugar that desugars to existing ANF
# primitives + auto-injected method params; no new ANF kinds or Stack-IR
# changes. See docs/cross-covenant-pattern.md.
class TestIntentIntrinsics < Minitest::Test
  # Parse + validate + typecheck + lower a Go-DSL source. Fails the test on
  # any error. Returns the lowered ANF program.
  def must_lower_go(source)
    parse_result = RunarCompiler::Frontend.parse_go(source, "Test.runar.go")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract

    val_result = RunarCompiler::Frontend.validate(parse_result.contract)
    assert_empty val_result.errors.map(&:format_message), "unexpected validation errors"

    tc_result = RunarCompiler::Frontend.type_check(parse_result.contract)
    assert_empty tc_result.errors.map(&:format_message), "unexpected typecheck errors"

    RunarCompiler::Frontend.lower_to_anf(parse_result.contract)
  end

  # Assert that the source produces a typecheck error containing substr.
  def expect_typecheck_error(source, substr)
    parse_result = RunarCompiler::Frontend.parse_go(source, "Test.runar.go")
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract

    tc_result = RunarCompiler::Frontend.type_check(parse_result.contract)
    msgs = tc_result.errors.map(&:format_message)
    assert msgs.any? { |m| m.include?(substr) },
           "expected typecheck error containing #{substr.inspect}, got: #{msgs.inspect}"
  end

  def find_method(prog, name)
    m = prog.methods.find { |meth| meth.name == name }
    refute_nil m, "method #{name.inspect} not found; got: #{prog.methods.map(&:name).inspect}"
    m
  end

  def param_names(method)
    method.params.map(&:name)
  end

  # ---------------------------------------------------------------------------
  # extractPrevOutputScript
  # ---------------------------------------------------------------------------

  def test_extract_prev_output_script_auto_injects_witness_param
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type IntentCov struct {
      \trunar.StatefulSmartContract
      \tStateCovScriptHash runar.ByteString `runar:"readonly"`
      }

      func (c *IntentCov) CoSpend() {
      \tstateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
      \t_ = stateCovScript
      }
    GO
    prog = must_lower_go(source)
    m = find_method(prog, "coSpend")
    names = param_names(m)
    assert_includes names, "_prevOutScript_0", "expected auto-injected witness param"
    assert_includes names, "txPreimage", "expected txPreimage"
  end

  def test_extract_prev_output_script_two_indices_produce_two_params
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type IntentCov struct {
      \trunar.StatefulSmartContract
      \tH0 runar.ByteString `runar:"readonly"`
      \tH1 runar.ByteString `runar:"readonly"`
      }

      func (c *IntentCov) CoSpend() {
      \ta := runar.ExtractPrevOutputScript(0, c.H0)
      \tb := runar.ExtractPrevOutputScript(1, c.H1)
      \t_ = a
      \t_ = b
      }
    GO
    prog = must_lower_go(source)
    m = find_method(prog, "coSpend")
    names = param_names(m)
    %w[_prevOutScript_0 _prevOutScript_1].each do |want|
      assert_includes names, want, "expected auto-injected param #{want}"
    end
  end

  def test_extract_prev_output_script_same_index_is_idempotent
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type IntentCov struct {
      \trunar.StatefulSmartContract
      \tH0 runar.ByteString `runar:"readonly"`
      }

      func (c *IntentCov) CoSpend() {
      \ta := runar.ExtractPrevOutputScript(0, c.H0)
      \tb := runar.ExtractPrevOutputScript(0, c.H0)
      \t_ = a
      \t_ = b
      }
    GO
    prog = must_lower_go(source)
    m = find_method(prog, "coSpend")
    count = m.params.count { |p| p.name == "_prevOutScript_0" }
    assert_equal 1, count, "expected exactly one _prevOutScript_0 param"
  end

  def test_extract_prev_output_script_non_literal_index_errors
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type IntentCov struct {
      \trunar.StatefulSmartContract
      \tH0 runar.ByteString `runar:"readonly"`
      }

      func (c *IntentCov) CoSpend(idx runar.Bigint) {
      \t_ = runar.ExtractPrevOutputScript(idx, c.H0)
      }
    GO
    expect_typecheck_error(source, "must be an integer literal")
  end

  # ---------------------------------------------------------------------------
  # requireOutputP2PKH
  # ---------------------------------------------------------------------------

  def test_require_output_p2pkh_auto_injects_serialised_outputs
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tBondPKH runar.ByteString `runar:"readonly"`
      \tBond    runar.Bigint     `runar:"readonly"`
      }

      func (c *Cov) PayBond() {
      \trunar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
      }
    GO
    prog = must_lower_go(source)
    m = find_method(prog, "payBond")
    assert_includes param_names(m), "_serialisedOutputs",
                    "expected auto-injected _serialisedOutputs param"
  end

  def test_require_output_p2pkh_multiple_calls_one_serialised_outputs_param
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tBondPKH runar.ByteString `runar:"readonly"`
      \tBond    runar.Bigint     `runar:"readonly"`
      }

      func (c *Cov) PayMulti() {
      \trunar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
      \trunar.RequireOutputP2PKH(1, c.BondPKH, c.Bond)
      }
    GO
    prog = must_lower_go(source)
    m = find_method(prog, "payMulti")
    count = m.params.count { |p| p.name == "_serialisedOutputs" }
    assert_equal 1, count,
                 "expected exactly one _serialisedOutputs param across multiple intrinsic calls"
  end

  def test_require_output_p2pkh_non_literal_index_errors
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tBondPKH runar.ByteString `runar:"readonly"`
      \tBond    runar.Bigint     `runar:"readonly"`
      }

      func (c *Cov) PayBond(idx runar.Bigint) {
      \trunar.RequireOutputP2PKH(idx, c.BondPKH, c.Bond)
      }
    GO
    expect_typecheck_error(source, "must be an integer literal")
  end

  # ---------------------------------------------------------------------------
  # currentBlockHeight
  # ---------------------------------------------------------------------------

  def test_current_block_height_desugars_to_extract_locktime
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tDeadline runar.Bigint `runar:"readonly"`
      }

      func (c *Cov) Spend() {
      \th := runar.CurrentBlockHeight()
      \trunar.Assert(h <= c.Deadline)
      }
    GO
    prog = must_lower_go(source)
    m = find_method(prog, "spend")
    saw_extract_locktime = m.body.any? do |b|
      b.value.kind == "call" && b.value.func == "extractLocktime"
    end
    assert saw_extract_locktime,
           "expected currentBlockHeight() to desugar to extractLocktime call in #{m.name}"
  end

  def test_current_block_height_stateless_contract_errors
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Sl struct {
      \trunar.SmartContract
      \tDeadline runar.Bigint `runar:"readonly"`
      }

      func (c *Sl) Spend() bool {
      \th := runar.CurrentBlockHeight()
      \treturn h > c.Deadline
      }
    GO
    expect_typecheck_error(source, "StatefulSmartContract")
  end

  # ---------------------------------------------------------------------------
  # Crit-2 -- prefix-hash 3-arg form
  # ---------------------------------------------------------------------------

  def test_extract_prev_output_script_prefix_form_lowers_with_substr
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type IntentTemplate struct {
      \trunar.StatefulSmartContract
      \tExpectedPolicyPrefixHash runar.ByteString `runar:"readonly"`
      }

      func (c *IntentTemplate) Bind() {
      \ts := runar.ExtractPrevOutputScript(0, c.ExpectedPolicyPrefixHash, 600)
      \t_ = s
      }
    GO
    prog = must_lower_go(source)
    m = find_method(prog, "bind")
    # Expect a substr call inside the method body (the prefix extraction
    # preceding the hash256). Distinguish from any other substr by checking it
    # consumes a load_param ref for _prevOutScript_0.
    saw_prefix_substr = false
    m.body.each_with_index do |b, i|
      next unless b.value.kind == "call" && b.value.func == "substr" && b.value.args.length == 3

      ref = b.value.args[0]
      (0...i).each do |j|
        if m.body[j].name == ref &&
           m.body[j].value.kind == "load_param" &&
           m.body[j].value.name == "_prevOutScript_0"
          saw_prefix_substr = true
          break
        end
      end
      break if saw_prefix_substr
    end
    assert saw_prefix_substr,
           "expected substr(load_param(_prevOutScript_0), ...) for 3-arg prefix form"
  end

  def test_extract_prev_output_script_prefix_form_non_literal_prefix_len_errors
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tH runar.ByteString `runar:"readonly"`
      }

      func (c *Cov) Bind(n runar.Bigint) {
      \t_ = runar.ExtractPrevOutputScript(0, c.H, n)
      }
    GO
    expect_typecheck_error(source, "prefixLen) must be an integer literal")
  end

  def test_extract_prev_output_script_too_many_args_errors
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tH runar.ByteString `runar:"readonly"`
      }

      func (c *Cov) Bind() {
      \t_ = runar.ExtractPrevOutputScript(0, c.H, 600, 999)
      }
    GO
    expect_typecheck_error(source, "expects 2 or 3 arguments")
  end

  # ---------------------------------------------------------------------------
  # Crit-3 -- addDataOutput + requireOutputP2PKH mix rejection
  # ---------------------------------------------------------------------------

  def test_require_output_p2pkh_mixed_with_add_data_output_errors
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tBondPKH runar.ByteString `runar:"readonly"`
      \tBond    runar.Bigint     `runar:"readonly"`
      \tTag     runar.ByteString `runar:"readonly"`
      }

      func (c *Cov) PayBondAndAnnounce() {
      \tc.AddDataOutput(0, c.Tag)
      \trunar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
      }
    GO
    expect_typecheck_error(source, "mixes requireOutputP2PKH() with addDataOutput()")
  end

  def test_require_output_p2pkh_without_add_data_output_ok
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type Cov struct {
      \trunar.StatefulSmartContract
      \tBondPKH runar.ByteString `runar:"readonly"`
      \tBond    runar.Bigint     `runar:"readonly"`
      }

      func (c *Cov) PayBond() {
      \trunar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
      }
    GO
    must_lower_go(source) # must not error
  end

  # ---------------------------------------------------------------------------
  # End-to-end compile test (mirrors Go's intent_intrinsics_compile_test.go)
  # ---------------------------------------------------------------------------

  def test_intent_intrinsics_end_to_end_compile
    source = <<~GO
      package x

      import runar "github.com/icellan/runar/packages/runar-go"

      type IntentDemo struct {
      \trunar.StatefulSmartContract
      \tStateCovScriptHash runar.ByteString `runar:"readonly"`
      \tBondPKH            runar.ByteString `runar:"readonly"`
      \tBondAmount         runar.Bigint     `runar:"readonly"`
      \tDeadline           runar.Bigint     `runar:"readonly"`
      }

      func (c *IntentDemo) CoSpendPrivileged() {
      \tstateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
      \t_ = stateCovScript

      \th := runar.CurrentBlockHeight()
      \trunar.Assert(h <= c.Deadline)

      \trunar.RequireOutputP2PKH(0, c.BondPKH, c.BondAmount)
      }
    GO
    artifact = nil
    Dir.mktmpdir do |dir|
      path = File.join(dir, "IntentDemo.runar.go")
      File.write(path, source)
      artifact = RunarCompiler.compile_from_source(path)
    end
    refute_nil artifact, "expected non-nil compiled artifact"
    refute_empty artifact.script, "expected non-empty script hex"

    # Auto-injected witness params must appear in the public method's ABI.
    method_abi = artifact.abi.methods.find { |m| m.name == "coSpendPrivileged" }
    refute_nil method_abi, "method coSpendPrivileged not found in artifact ABI"
    abi_param_names = method_abi.params.map(&:name)
    %w[_prevOutScript_0 _serialisedOutputs txPreimage].each do |want|
      assert_includes abi_param_names, want,
                      "expected param #{want} in coSpendPrivileged ABI; got: #{abi_param_names.inspect}"
    end
  end
end
