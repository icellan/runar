# frozen_string_literal: true

require_relative "test_helper"

require "tmpdir"
require "runar_compiler/compiler"

# F-024 (CL-BUG-079, user decision R14) -- Ruby-tier port of
# packages/runar-compiler/src/__tests__/f024-continuation-amount.test.ts.
#
# Proves (Ruby tier, TS surface): every default single-output continuation
# carries the injected `assert(_newAmount >= extractAmount(txPreimage))` ANF
# (load_param txPreimage; call extractAmount; load_param _newAmount; bin_op >=;
# assert) after the body; addOutput and terminal methods do not;
# `continuationAmount()` lowers to load_param _newAmount where that witness
# exists and is refused everywhere else; a write to it is refused.
# Does NOT prove on-chain rejection of a drain (the TS Spend test does) or
# cross-tier byte parity (conformance).
class TestF024ContinuationAmount < Minitest::Test
  COUNTER = <<~SRC
    class Counter extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) { super(count); this.count = count; }
      public increment() { this.count = this.count + 1n; }
      public addTo(amount: bigint) { this.addOutput(1000n, this.count + amount); }
      public close() { assert(this.count > 0n); }
      public log(payload: ByteString) { this.addDataOutput(0n, payload); }
    }
  SRC

  READ_ONLY = "continuationAmount() is read-only and cannot be assigned"
  UNAVAILABLE = "continuationAmount() is only available in a public StatefulSmartContract method whose state " \
                "continues through the default single-output continuation"

  def pot(body)
    "class Pot extends StatefulSmartContract {\n  count: bigint;\n" \
      "  constructor(count: bigint) { super(count); this.count = count; }\n  #{body}\n}\n"
  end

  def lower(src)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "C.runar.ts")
      File.write(path, src)
      RunarCompiler.compile_source_to_ir(path, disable_constant_folding: true)
    end
  end

  def refusal(src)
    lower(src)
    flunk("expected a refusal, it compiled")
  rescue Minitest::Assertion
    raise
  rescue StandardError => e
    e.message
  end

  def public_method(prog, name)
    prog.methods.find { |m| m.name == name && m.is_public } || flunk("no public method #{name}")
  end

  def kinds(body)
    body.map { |b| b.value.kind == "call" ? "call:#{b.value.func}" : b.value.kind }
  end

  def injected_check_at(body)
    (0..(body.length - 5)).select do |i|
      a, b, c, d, e = body[i, 5]
      a.value.kind == "load_param" && a.value.name == "txPreimage" &&
        b.value.kind == "call" && b.value.func == "extractAmount" && b.value.args == [a.name] &&
        c.value.kind == "load_param" && c.value.name == "_newAmount" &&
        d.value.kind == "bin_op" && d.value.op == ">=" && d.value.left == c.name && d.value.right == b.name &&
        e.value.kind == "assert" && e.value.value_ref == d.name && !e.value.is_auto_injected_state_check
    end
  end

  def test_default_continuation_carries_the_value_check
    prog = lower(COUNTER)
    body = public_method(prog, "increment").body
    hits = injected_check_at(body)
    assert_equal 1, hits.length, kinds(body).inspect
    k = kinds(body)
    assert_includes k[0...hits[0]], "update_prop"
    %w[if get_state_script call:computeStateOutput].each { |w| assert_includes k[(hits[0] + 5)..], w }
    assert_equal 1, injected_check_at(public_method(prog, "log").body).length
    %w[addTo close].each do |name|
      m = public_method(prog, name)
      refute_includes m.params.map(&:name), "_newAmount"
      refute_includes kinds(m.body), "call:extractAmount"
    end
  end

  def test_continuation_amount_read_lowers_to_new_amount
    prog = lower(pot("public join(bet: bigint) {\n    assert(continuationAmount() == extractAmount(this.txPreimage) + bet);\n" \
                     "    this.count = this.count + 1n;\n  }"))
    body = public_method(prog, "join").body
    hits = injected_check_at(body)
    assert_equal 1, hits.length
    first = body.index { |b| b.value.kind == "load_param" && b.value.name == "_newAmount" }
    assert first && first < hits[0]
  end

  STATELESS = <<~SRC
    class P extends SmartContract {
      readonly x: bigint;
      constructor(x: bigint) { super(x); this.x = x; }
      public unlock() { assert(continuationAmount() > this.x); }
    }
  SRC

  def test_continuation_amount_refusals
    cases = {
      "write" => [pot("public join() { continuationAmount() = 5n; this.count = this.count + 1n; }"), READ_ONLY],
      "increment" => [pot("public join() { continuationAmount()++; this.count = this.count + 1n; }"), READ_ONLY],
      "stateless" => [STATELESS, "continuationAmount() is only available in StatefulSmartContract methods"],
      "terminal" => [pot("public close() { assert(continuationAmount() > 0n); }"), UNAVAILABLE],
      "addOutput" => [pot("public split() { this.addOutput(continuationAmount(), this.count); }"), UNAVAILABLE],
      "private" => [pot("private amt(): bigint { return continuationAmount(); }\n  " \
                        "public bump() { this.count = this.count + this.amt(); }"), UNAVAILABLE],
    }
    cases.each do |name, (src, want)|
      msg = refusal(src)
      assert_includes msg, want, "#{name}: #{msg}"
    end
  end
end
