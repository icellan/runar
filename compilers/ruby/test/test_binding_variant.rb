# frozen_string_literal: true

require_relative "test_helper"
require "tmpdir"
require "json"
require "runar_compiler"
require "runar_compiler/cli"

# Ports #170 (original design: brendan-elas, #167): the C=1 Any-S binding and
# the @bindingVariant directive in the Ruby tier. The two blobs are pinned here
# as literals so a Ruby-only drift fails this file; execution of the same bytes
# through @bsv/sdk Spend lives in
# packages/runar-testing/src/__tests__/binding-variant.test.ts.
class TestBindingVariant < Minitest::Test
  # 422 bytes: s = lowS((z+1) mod n), C=1 key 038ff83d...
  LOWS_HEX = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"
  # 376 bytes: s = z+1, no mod-n, no low-S (nVersion != 1 only).
  ALL_HEX = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

  def counter(directive)
    "class C extends StatefulSmartContract {\n" \
      "  count: bigint;\n" \
      "  constructor(count: bigint) { super(count); this.count = count; }\n" \
      "  #{directive}\n" \
      "  public bump() { this.count++; }\n" \
      "}\n"
  end

  def with_file(src, name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, name)
      File.write(path, src)
      yield path
    end
  end

  def script(src, name = "C.runar.ts")
    with_file(src, name) { |p| RunarCompiler.compile_from_source(p, disable_constant_folding: true).script }
  end

  def error_of(src, name = "C.runar.ts")
    with_file(src, name) do |p|
      RunarCompiler.compile_from_source(p, disable_constant_folding: true)
      flunk("#{name} compiled, expected an error")
    rescue StandardError => e
      e.message
    end
  end

  def test_pinned_sizes
    assert_equal 422, LOWS_HEX.length / 2
    assert_equal 376, ALL_HEX.length / 2
  end

  def test_default_and_explicit_lows_emit_the_c1_blob
    ["", "/** @bindingVariant lowS */"].each do |d|
      s = script(counter(d))
      assert_equal 1, s.scan(LOWS_HEX).length, d
      refute_includes s, "02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0"
    end
  end

  def test_all_emits_the_compact_blob
    s = script(counter("/** @bindingVariant all */"))
    assert_equal 1, s.scan(ALL_HEX).length
    refute_includes s, LOWS_HEX
  end

  def test_nested_arm_inherits
    src = "class G extends SmartContract {\n  constructor() { super(); }\n  /** @bindingVariant all */\n" \
          "  public unlock(a: SigHashPreimage, b: SigHashPreimage, c: boolean) {\n" \
          "    if (c) { assert(checkPreimage(a)); } else { assert(checkPreimage(b)); }\n  }\n}\n"
    s = script(src, "G.runar.ts")
    assert_equal 2, s.scan(ALL_HEX).length
    refute_includes s, LOWS_HEX
  end

  def test_directive_errors
    {
      "/** @bindingVariant: all */" =>
        "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`",
      "/** @bindingVariant high */" => '@bindingVariant: unknown variant "high" (valid: lowS, all)',
      "/** @bindingVariant all */\n  // @bindingVariant lowS" =>
        "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one"
    }.each do |d, want|
      assert_includes error_of(counter(d)), want, d
    end
    priv = counter("/** @bindingVariant all */").sub("public bump", "private bump")
    assert_includes error_of(priv), "@bindingVariant directive on non-public method 'bump' has no effect"
  end

  def test_non_ts_surfaces_refuse
    {
      "C.runar.sol" => "Solidity", "C.runar.move" => "Move", "C.runar.py" => "Python", "C.runar.go" => "Go DSL",
      "C.runar.rs" => "Rust", "C.runar.rb" => "Ruby", "C.runar.zig" => "Zig", "C.runar.java" => "Java"
    }.each do |file, surface|
      want = "@bindingVariant directive is not supported by the #{surface} surface parser; " \
             "write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured"
      assert_includes error_of("// @bindingVariant all\n", file), want, file
    end
  end

  def test_ir_loader_refuses_unknown_variant
    json = with_file(counter("/** @bindingVariant all */"), "C.runar.ts") do |p|
      JSON.generate(RunarCompiler::CLI._anf_to_camel_dict(RunarCompiler.compile_source_to_ir(p, disable_constant_folding: true)))
    end
    assert_includes json, '"bindingVariant":"all"'
    RunarCompiler.compile_from_ir_bytes(json)
    bad = json.sub('"bindingVariant":"all"', '"bindingVariant":"high"')
    err = assert_raises(StandardError) { RunarCompiler.compile_from_ir_bytes(bad) }
    assert_includes err.message, 'bindingVariant must be "lowS" or "all"'
  end
end
