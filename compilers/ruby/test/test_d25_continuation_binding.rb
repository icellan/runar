# frozen_string_literal: true

# D25 -- the contract-level continuation binding (continuation_binding.rb):
# classification, the SINGLE default, the hidden spent-outpoint field, the
# diagnostics, and the --ir check. Port of
# packages/runar-compiler/src/__tests__/d25-continuation-binding.test.ts.
#
# Proves: the Ruby frontend classifies each contract as TS does (ABI modes,
# change params, the hidden field's position / type / initializer, the
# reserved name, the error and warning texts), and the --ir loader refuses a
# program that drops or fakes the binding. Does not prove: byte parity (the
# conformance goldens do) or the executed twin-input theft (the TS / Go / Py
# SDK tests on a real interpreter do; the Ruby tier has no Script VM).

require_relative "test_helper"
require "json"
require "tmpdir"

class TestD25ContinuationBinding < Minitest::Test
  FIELD = RunarCompiler::Frontend::ContinuationBinding::TWIN_BINDING_FIELD

  STATEFUL = <<~TS
    import { StatefulSmartContract, assert, checkSig, extractAmount, extractOutputHash, hash256 } from 'runar-lang';
    import type { PubKey, Sig, Sha256 } from 'runar-lang';
  TS

  def counter(inc_directive = "", dec_directive = "")
    <<~TS
      #{STATEFUL}
      class Counter extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        #{inc_directive}
        public increment() { this.count++; }
        #{dec_directive}
        public decrement() { assert(this.count > 0n); this.count--; }
      }
    TS
  end

  MIXED = <<~TS
    #{STATEFUL}
    class MixedPot extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) { super(count); this.count = count; }
      public increment() { this.count++; }
      public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
    }
  TS

  def pot(body)
    <<~TS
      #{STATEFUL}
      class Pot extends StatefulSmartContract {
        count: bigint;
        readonly owner: PubKey;
        constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
        public bump(sig: Sig) { #{body} }
      }
    TS
  end

  def with_source(src, name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "#{name}.runar.ts")
      File.write(path, src)
      yield path
    end
  end

  # [artifact, warnings]
  def ok(src, name)
    with_source(src, name) do |path|
      RunarCompiler.compile_from_source_collecting_warnings(path, disable_constant_folding: true)
    end
  end

  def fail_message(src, name)
    with_source(src, name) do |path|
      e = assert_raises(RunarCompiler::CompilationError) do
        RunarCompiler.compile_from_source(path, disable_constant_folding: true)
      end
      e.message
    end
  end

  def anf_of(src, name)
    with_source(src, name) do |path|
      program = RunarCompiler.compile_source_to_ir(path, disable_constant_folding: true)
      JSON.parse(JSON.generate(RunarCompiler::CLI._anf_to_camel_dict(program)))
    end
  end

  def compile_ir(program)
    RunarCompiler.compile_from_ir_bytes(JSON.generate(program))
  end

  def method_of(artifact, name)
    artifact.abi.methods.find { |m| m.name == name }
  end

  def abi_mode(artifact, name)
    method_of(artifact, name).sig_hash_type
  end

  def state_names(artifact)
    artifact.state_fields.map(&:name)
  end

  def walk(bindings, &blk)
    bindings.each do |b|
      blk.call(b)
      v = b["value"]
      %w[then else body].each { |k| walk(v[k], &blk) if v[k].is_a?(Array) }
    end
  end

  # -- class 1 ---------------------------------------------------------------

  def test_class1_defaults_every_continuation_method_to_single_and_drops_change_params
    a, = ok(counter, "Counter")
    assert_equal 0x43, abi_mode(a, "increment")
    assert_equal 0x43, abi_mode(a, "decrement")
    assert_equal ["count"], state_names(a)
    assert_equal %w[_newAmount txPreimage], method_of(a, "increment").params.map(&:name)
  end

  def test_class1_maps_all_acp_to_single_acp
    d = "/** @sighash ALL|ANYONECANPAY|FORKID */"
    a, = ok(counter(d, d), "Counter")
    assert_equal 0xC3, abi_mode(a, "increment")
  end

  def test_class1_keeps_explicit_single_acp
    a, = ok(counter("/** @sighash SINGLE|ANYONECANPAY|FORKID */"), "Counter")
    assert_equal 0xC3, abi_mode(a, "increment")
  end

  def test_class1_refuses_explicit_all_sibling
    msg = fail_message(counter("", "/** @sighash ALL|FORKID */"), "Counter")
    assert_includes msg, "method 'decrement': @sighash ALL|FORKID"
    assert_includes msg, RunarCompiler::Frontend::ContinuationBinding.explicit_all_sibling_message("decrement")
  end

  def test_class1_terminal_method_keeps_all
    src = <<~TS
      #{STATEFUL}
      class Box extends StatefulSmartContract {
        count: bigint;
        readonly owner: PubKey;
        constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
        public bump() { this.count++; }
        public close(sig: Sig) { assert(checkSig(sig, this.owner)); }
      }
    TS
    a, = ok(src, "Box")
    assert_equal 0x43, abi_mode(a, "bump")
    assert_nil abi_mode(a, "close")
  end

  # -- class 2 ---------------------------------------------------------------

  def test_class2_appends_zero_initialised_sha256_field_last_outside_ctor_abi
    a, = ok(MIXED, "MixedPot")
    assert_equal ["count", FIELD], state_names(a)
    assert_equal ["count"], a.abi.constructor.params.map(&:name)
    sf = a.state_fields.last
    assert_equal "Sha256", sf.type
    assert_equal "00" * 32, sf.initial_value
    # Every method keeps ALL: no blending of SINGLE and the field.
    assert_nil abi_mode(a, "increment")
    assert_nil abi_mode(a, "bump")
  end

  def test_class2_writes_outpoint_hash_in_auto_continuation_and_appends_it_to_add_output
    p = anf_of(MIXED, "MixedPot")
    prop = p["properties"].last
    assert_equal [FIELD, "Sha256", false, "00" * 32], [prop["name"], prop["type"], prop["readonly"], prop["initialValue"]]
    inc = p["methods"].find { |m| m["name"] == "increment" }
    writes = []
    walk(inc["body"]) { |b| writes << b["value"]["name"] if b["value"]["kind"] == "update_prop" }
    assert_includes writes, FIELD
    bump = p["methods"].find { |m| m["name"] == "bump" }
    outs = []
    walk(bump["body"]) { |b| outs << b if b["value"]["kind"] == "add_output" }
    assert_equal 1, outs.length
    assert_equal 2, outs[0]["value"]["stateValues"].length
  end

  def test_class2_mutate_only_reading_extract_output_hash_is_bound
    src = <<~TS
      #{STATEFUL}
      class Peek extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        public bump(h: Sha256) { assert(extractOutputHash(this.txPreimage) !== h); this.count++; }
      }
    TS
    a, = ok(src, "Peek")
    assert_nil abi_mode(a, "bump")
    assert_equal ["count", FIELD], state_names(a)
  end

  def test_class2_field_name_is_reserved
    src = <<~TS
      #{STATEFUL}
      class X extends StatefulSmartContract {
        _spentOutpointHash: bigint;
        constructor(_spentOutpointHash: bigint) { super(_spentOutpointHash); this._spentOutpointHash = _spentOutpointHash; }
        public bump() { this._spentOutpointHash++; }
      }
    TS
    assert_includes fail_message(src, "X"), "'_spentOutpointHash' is reserved"
  end

  # -- class 3 ---------------------------------------------------------------

  def test_class3_warns_on_unsigned_add_output_extract_amount
    a, warnings = ok(pot("this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot")
    w = warnings.select { |x| x.include?("twin-input aliasing") }
    assert_equal 1, w.length
    assert_includes w[0], RunarCompiler::Frontend::ContinuationBinding.unsigned_add_output_message("bump")
    assert_equal ["count"], state_names(a)
    assert_nil abi_mode(a, "bump")
  end

  def test_class3_follows_a_local_initialised_from_extract_amount
    _, warnings = ok(pot("const v: bigint = extractAmount(this.txPreimage); this.addOutput(v, this.count + 1n);"), "Pot")
    assert(warnings.any? { |x| x.include?("twin-input aliasing") })
  end

  def test_class3_no_warning_when_method_checks_a_signature
    _, warnings = ok(pot("assert(checkSig(sig, this.owner)); this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot")
    refute(warnings.any? { |x| x.include?("twin-input aliasing") })
  end

  # -- --ir check ------------------------------------------------------------

  def test_ir_accepts_frontend_ir_of_every_class
    compile_ir(anf_of(counter, "Counter"))
    compile_ir(anf_of(MIXED, "MixedPot"))
  end

  def test_ir_refuses_mutate_only_program_whose_continuation_commits_under_all
    p = anf_of(counter, "Counter")
    p["methods"].find { |m| m["name"] == "decrement" }.delete("sigHashType")
    e = assert_raises(ArgumentError) { compile_ir(p) }
    assert_includes e.message, "IR validation"
  end

  def test_ir_refuses_mixed_program_without_binding_field
    plain = anf_of(MIXED, "MixedPot")
    plain["properties"] = plain["properties"].reject { |x| x["name"] == FIELD }
    plain["methods"].each do |m|
      drop = Set.new
      walk(m["body"]) do |b|
        v = b["value"]
        drop << b["name"] if v["kind"] == "update_prop" && v["name"] == FIELD
        drop << v["stateValues"].pop if v["kind"] == "add_output"
      end
      by_name = {}
      walk(m["body"]) { |b| by_name[b["name"]] = b }
      drop.to_a.each do |n|
        v = by_name[n]["value"]
        src = v["kind"] == "update_prop" ? v["value"] : n
        sha = by_name[src]["value"]
        eo = by_name[sha["args"][0]]["value"]
        drop.merge([src, sha["args"][0], eo["args"][0]])
      end
      m["body"] = m["body"].reject { |b| drop.include?(b["name"]) }
    end
    e = assert_raises(ArgumentError) { compile_ir(plain) }
    assert_includes e.message, "not bound to its input"
  end

  def test_ir_refuses_add_output_whose_last_state_value_is_not_the_outpoint_hash
    p = anf_of(MIXED, "MixedPot")
    bump = p["methods"].find { |m| m["name"] == "bump" }
    walk(bump["body"]) do |b|
      sv = b["value"]["stateValues"]
      sv[1] = sv[0] if b["value"]["kind"] == "add_output"
    end
    e = assert_raises(ArgumentError) { compile_ir(p) }
    assert_includes e.message, "every add_output must carry"
  end

  def test_ir_refuses_binding_field_that_is_not_last_or_not_zero
    p = anf_of(MIXED, "MixedPot")
    p["properties"].last["initialValue"] = "11" * 32
    e = assert_raises(ArgumentError) { compile_ir(p) }
    assert_includes e.message, "must be the last property"
  end
end
