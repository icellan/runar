# frozen_string_literal: true

# N-028 -- an EC scalar-fusing rewrite must emit its folded constant as a real
# binding.
#
# The EC optimizer (pass 4.5) rewrites +ecAdd(ecMulGen(k1), ecMulGen(k2))+ into
# +ecMulGen(k1 + k2 mod n)+. The folded scalar is a *new* value, so it needs a
# binding of its own in the method body -- the rewritten call references it by
# name and stack lowering walks the body linearly.
#
# The Ruby optimizer used to register that constant only in the optimizer's
# internal value map, never in the body, so every contract in which a fusing
# rule fired died in stack lowering with:
#
#     Compilation error: value "__ec_opt_1" not found on stack
#
# Both the Go engine (+buildOpHelper+ in
# compilers/go/frontend/ec_rules_engine.go) and the TypeScript optimizer
# (packages/runar-compiler/src/optimizer/anf-ec.ts) insert the helper binding
# immediately before the rewritten binding. Ruby must do the same, and must
# emit the same script bytes.

require_relative "test_helper"
require "runar_compiler/frontend/anf_optimize"
require "digest"
require "tmpdir"

class TestN028ECFreshConstBinding < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path("..", __dir__)

  # Both references below are the SHA-256 of the lowercase script hex (no
  # trailing newline) produced by the Go and TypeScript compilers for these
  # sources, with constant folding at its default setting. Regenerate with:
  #
  #   cd compilers/go && go run . --source <src> --hex | tr -d '\n' | shasum -a 256
  EC_LINEAR_SOURCE = <<~TS
    import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';

    class ECLinear extends SmartContract {
        constructor() {
            super();
        }

        public spend(a: bigint, b: bigint) {
            assert(ecOnCurve(ecAdd(ecMulGen(5n), ecMulGen(7n))));
        }
    }
  TS
  # Re-stamped for R-052 / CL-BUG-095, the Point width gate: +184 hex chars
  # (+92 bytes) from the OP_SIZE/OP_NUMEQUALVERIFY checks this contract's
  # ecAdd / ecMulGen / ecOnCurve call sites now carry. Was
  # efcff80d2f183358... / 2_548_856. The replacement was derived from the
  # TYPESCRIPT tier and cross-checked against Ruby's own output, not copied
  # from this tier — the whole point of the pin is that it is another tier's
  # opinion of these bytes.
  EC_LINEAR_REFERENCE_SHA256 = "7214cad88783e09e484fe15f57c3d45fdf4443960c7f7a45731e052065b1bcad"
  EC_LINEAR_REFERENCE_HEX_LEN = 2_554_314

  # Control: no EC calls at all, so +optimize_ec+ returns early. Pinned so the
  # fix above cannot be "achieved" by disabling the optimizer.
  NO_EC_SOURCE = <<~TS
    import { SmartContract, assert } from 'runar-lang';

    class NoEC extends SmartContract {
        constructor() {
            super();
        }

        public spend(a: bigint, b: bigint) {
            assert(a + b == 42n);
        }
    }
  TS
  NO_EC_REFERENCE_HEX = "93012a9c"

  def compile_hex(file_name, source)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      out = nil
      Dir.chdir(RUBY_COMPILER_DIR) do
        out = `ruby -Ilib bin/runar-compiler-ruby --source #{path} --hex 2>&1`
        assert_equal 0, $?.exitstatus,
                     "ruby compiler failed for #{file_name}: #{out[0, 2000]}"
      end
      out = out.strip
      refute_match(/error/i, out[0, 400], "compiler reported an error: #{out[0, 400]}")
      return out
    end
  end

  # -------------------------------------------------------------------
  # Unit level: the folded scalar is a real binding in the body
  # -------------------------------------------------------------------

  def load_const_int(name, n)
    v = RunarCompiler::IR::ANFValue.new(kind: "load_const")
    v.const_big_int = n
    v.const_int = n
    v.raw_value = n
    RunarCompiler::IR::ANFBinding.new(name: name, value: v)
  end

  def call_binding(name, func, args)
    v = RunarCompiler::IR::ANFValue.new(kind: "call")
    v.func = func
    v.args = args
    RunarCompiler::IR::ANFBinding.new(name: name, value: v)
  end

  def test_fused_scalar_is_bound_in_the_method_body
    program = RunarCompiler::IR::ANFProgram.new(
      contract_name: "Test",
      properties: [],
      methods: [
        RunarCompiler::IR::ANFMethod.new(
          name: "test",
          params: [],
          is_public: true,
          body: [
            load_const_int("t0", 5),
            call_binding("t1", "ecMulGen", ["t0"]),
            load_const_int("t2", 7),
            call_binding("t3", "ecMulGen", ["t2"]),
            call_binding("t4", "ecAdd", %w[t1 t3]),
            call_binding("t5", "assert", ["t4"])
          ]
        )
      ]
    )

    body = RunarCompiler::Frontend::ANFOptimize.optimize_ec(program).methods[0].body
    names = body.map(&:name)

    t4 = body.find { |b| b.name == "t4" }
    assert_equal "call", t4.value.kind
    assert_equal "ecMulGen", t4.value.func,
                 "expected t4 to be rewritten to ecMulGen"
    scalar_name = t4.value.args[0]

    assert_includes names, scalar_name,
                    "folded scalar #{scalar_name.inspect} is referenced by t4 but " \
                    "has no binding in the method body: #{names.inspect}"
    scalar = body.find { |b| b.name == scalar_name }
    assert_equal "load_const", scalar.value.kind
    assert_equal (5 + 7) % RunarCompiler::Frontend::ANFOptimize::CURVE_N,
                 scalar.value.const_big_int
    assert_operator names.index(scalar_name), :<, names.index("t4"),
                    "folded scalar must be bound before the binding that references it: " \
                    "#{names.inspect}"
  end

  # -------------------------------------------------------------------
  # End to end: compiles, and to the same bytes as Go / TypeScript
  # -------------------------------------------------------------------

  def test_ec_fusing_contract_compiles
    hex_out = compile_hex("ECLinear.runar.ts", EC_LINEAR_SOURCE)
    assert_equal EC_LINEAR_REFERENCE_HEX_LEN, hex_out.length
  end

  def test_ec_fusing_hex_matches_go_and_ts_reference
    hex_out = compile_hex("ECLinear.runar.ts", EC_LINEAR_SOURCE)
    digest = Digest::SHA256.hexdigest(hex_out)
    assert_equal EC_LINEAR_REFERENCE_SHA256, digest,
                 "Ruby script hex diverges from the Go/TS reference for ECLinear " \
                 "(len=#{hex_out.length}, want len=#{EC_LINEAR_REFERENCE_HEX_LEN})"
  end

  def test_non_ec_contract_bytes_unchanged
    hex_out = compile_hex("NoEC.runar.ts", NO_EC_SOURCE)
    assert_equal NO_EC_REFERENCE_HEX, hex_out,
                 "non-EC control script changed"
  end

  # -------------------------------------------------------------------
  # The folded constant must survive the IR JSON round-trip
  # -------------------------------------------------------------------

  # A folded scalar is a value mod n, so it is routinely far beyond
  # Number.MAX_SAFE_INTEGER. +_bigint_json_value+ is the tier's canonical
  # encoding for exactly that case: bare JSON number when a double carries it
  # losslessly, else the decimal digits with the JS BigInt `n` suffix, as a
  # string.
  EC_BIG_SOURCE = <<~TS
    import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';

    class ECBig extends SmartContract {
        constructor() {
            super();
        }

        public spend(a: bigint, b: bigint) {
            assert(ecOnCurve(ecAdd(ecMulGen(123456789012345678901234567890n), ecMulGen(7n))));
        }
    }
  TS

  def test_folded_scalar_uses_canonical_bigint_json_encoding
    # A bare number is read as an IEEE-754 double by every JS consumer (and by
    # Go's encoding/json into interface{}), so an unquoted 96-bit scalar loses
    # precision the moment the IR crosses a tier boundary.
    Dir.mktmpdir do |dir|
      path = File.join(dir, "ECBig.runar.ts")
      File.write(path, EC_BIG_SOURCE)
      out = nil
      Dir.chdir(RUBY_COMPILER_DIR) do
        out = `ruby -Ilib bin/runar-compiler-ruby --source #{path} --emit-ir 2>&1`
        assert_equal 0, $?.exitstatus, "--emit-ir failed: #{out[0, 2000]}"
      end
      ir = JSON.parse(out)
      folded = ir["methods"].flat_map { |m| m["body"] }
                            .select { |b| b["name"].start_with?("__ec_opt_") }
      refute_empty folded, "expected the EC optimizer to emit a folded-scalar binding"
      value = folded[0]["value"]["value"]
      assert_equal "123456789012345678901234567897n", value,
                   "folded scalar emitted as #{value.inspect} (#{value.class}); expected " \
                   "the canonical BigInt spelling"
    end
  end
end
