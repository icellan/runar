# frozen_string_literal: true

# N-248: Ruby `--ir` on Go's `merkleRootPoseidon2KB` IR failed in three ways:
#
# 1. `_lower_merkle_root_poseidon2_kb` (codegen/stack.rb) gated depth at
#    1..64, but the emitter it calls into
#    (`Poseidon2Merkle.emit_poseidon2_merkle_root`, codegen/poseidon2_merkle.rb)
#    is bounded at 32 (its own `raise` says so). A depth of 33..64 passed the
#    gate and then died inside the emitter under a message naming
#    `emit_poseidon2_merkle_root`, not the builtin `merkleRootPoseidon2KB` a
#    caller actually wrote -- the same gate-vs-emitter mismatch fixed in Go
#    (R-172), Rust (N-237) and Python (F-260), whose policy is depth 1..32.
#
# 2. Worse: depth 1 -- the only depth Go's own go-only-parity probe
#    (conformance/go-only-parity/GoOnlyPoseidon2Merkle.runar.ts) exercises --
#    never reached either diagnostic. `Poseidon2Merkle.emit_poseidon2_merkle_root`
#    calls `make_stack_op` and `big_int_push`, but (unlike every sibling
#    codegen module -- merkle.rb, koalabear.rb, babybear.rb, ec.rb, bn254.rb --
#    each of which defines its own copy) `poseidon2_merkle.rb` never defines
#    either helper. Every call, at any depth, raised `NoMethodError`, which
#    `lower_to_stack`'s catch-all (R-171, stack.rb `self.lower_to_stack`)
#    reports as "internal error (NoMethodError): ... this is a compiler bug" --
#    exactly the "internal error" the go-only-parity test's F-092 comment
#    flags for this tier, instead of a deliberate, named refusal or a
#    successful compile matching Go's bytes.
#
# 3. With (1) and (2) fixed, depth 1 compiled but to the WRONG bytes:
#    `_lower_merkle_root_poseidon2_kb` reconciled the emitter's eight
#    root_0..root_7 stack elements into stack.rb's result with seven OP_NIPs,
#    keeping root_7 alone and discarding root_0..root_6 -- so
#    `assert(merkleRootPoseidon2KB(...) === expected)` authenticated against
#    a single ~31-bit KoalaBear limb, not the whole root (CL-BUG-099 / R-056,
#    ported to Go and Rust N-237 but never to Ruby). Fixed by porting Go's
#    `EmitPoseidon2RootPack` as `Poseidon2Merkle.emit_poseidon2_root_pack`.
#
# What this proves: with all three bugs fixed, Ruby `--ir` on Go's own
# `--emit-ir` output for the go-only-parity probe at depth 1 compiles to hex
# BYTE-IDENTICAL to Go's (verified by `cmp` against Go's `--ir --hex` on the
# same input, outside this test -- the F-092 `--ir` leg of
# conformance/go-only-parity/go-only-parity.test.ts is the standing oracle for
# that), with all eight root limbs reaching the final comparison, not root_7
# alone; and an out-of-range depth (33, or 64 -- within the old, too-wide
# gate) is refused by a RuntimeError naming the builtin
# `merkleRootPoseidon2KB` and the 1..32 bound -- not `emit_poseidon2_merkle_root`,
# and not an internal error.
#
# What this does NOT prove: depths other than 1 and 33/64, nor on-chain
# execution (Ruby ships no ScriptVM -- see CLAUDE.md -- so byte-identity to Go
# plus Go's own poseidon2_merkle_root_binding_test.go, which executes the
# packed root against Plonky3 vectors, is the acceptance oracle here).

require_relative "test_helper"
require "json"

class TestN248MerkleRootPoseidon2KBIR < Minitest::Test
  # ANF IR for `assert(merkleRootPoseidon2KB(l0..l7, s0_0..s0_7, idx, depth) === expected)`
  # -- the shape Go's `--emit-ir` produces for
  # conformance/go-only-parity/GoOnlyPoseidon2Merkle.runar.ts. Mirrors the Rust
  # N-237 probe builder (compilers/rust/tests/n237_merkle_root_poseidon2kb_ir_tests.rs).
  def probe_ir(depth:, extra_args: 0)
    names = (0..7).map { |i| "l#{i}" } + (0..7).map { |i| "s0_#{i}" } + (0...extra_args).map { |i| "x#{i}" } + ["idx"]
    params = names.map { |n| { "name" => n, "type" => "bigint" } }
    params << { "name" => "expected", "type" => "bigint" }

    body = names.each_with_index.map do |n, i|
      { "name" => "t#{i}", "value" => { "kind" => "load_param", "name" => n } }
    end
    k = names.length
    body << { "name" => "t#{k}", "value" => { "kind" => "load_const", "value" => depth } }
    call_args = (0..k).map { |i| "t#{i}" }
    body << { "name" => "t#{k + 1}", "value" => { "kind" => "call", "func" => "merkleRootPoseidon2KB", "args" => call_args } }
    body << { "name" => "t#{k + 2}", "value" => { "kind" => "load_param", "name" => "expected" } }
    body << { "name" => "t#{k + 3}", "value" => { "kind" => "bin_op", "op" => "===", "left" => "t#{k + 1}", "right" => "t#{k + 2}" } }
    body << { "name" => "t#{k + 4}", "value" => { "kind" => "assert", "value" => "t#{k + 3}" } }

    JSON.generate(
      "contractName" => "P2KBRootBinding",
      "parentClass" => "SmartContract",
      "properties" => [],
      "methods" => [
        {
          "name" => "constructor", "isPublic" => false, "params" => [],
          "body" => [{ "name" => "t0", "value" => { "kind" => "call", "func" => "super", "args" => [] } }]
        },
        { "name" => "verify", "isPublic" => true, "params" => params, "body" => body }
      ]
    )
  end

  # Depth 1 is the only depth Go's go-only-parity probe exercises. Before the
  # fix this raised NoMethodError (missing make_stack_op/big_int_push in
  # poseidon2_merkle.rb), wrapped by lower_to_stack into "internal error
  # (NoMethodError): ... this is a compiler bug" -- neither a successful
  # compile nor a deliberate, named refusal.
  def test_go_ir_for_depth_1_compiles
    artifact = RunarCompiler.compile_from_ir_bytes(probe_ir(depth: 1))
    refute_nil artifact.script
    refute_empty artifact.script
  end

  # CL-BUG-099 / R-056, ported to Go and Rust (N-237) but never to Ruby: the
  # codegen leaves root_0..root_7 on the stack, and the only type the compiler
  # can return is a single `bigint`, so whatever reconciles those eight
  # elements into one value must make every limb load-bearing. The pre-fix
  # Ruby lowering reconciled them with seven OP_NIPs ("7777777"), keeping
  # root_7 alone and discarding root_0..root_6 -- authenticating
  # `assert(merkleRootPoseidon2KB(...) === expected)` against a single ~31-bit
  # KoalaBear element instead of the whole root. Go's
  # fix (EmitPoseidon2RootPack) packs all eight limbs base-2^32 instead; this
  # asserts Ruby's compiled tail matches that shape byte for byte.
  def test_all_eight_root_limbs_are_packed_into_the_comparison
    script = RunarCompiler.compile_from_ir_bytes(probe_ir(depth: 1)).script
    # Go's EmitPoseidon2RootPack: 7 x (push 2^32 = `05 0000000001`, OP_MUL,
    # OP_ADD), then the terminal OP_SWAP OP_NUMEQUAL ("7c9c") for this probe.
    root_pack_hex = "0500000000019593"
    tail = (root_pack_hex * 7) + "7c9c"
    assert script.end_with?(tail),
           "script must end with the 8-limb base-2^32 pack feeding the equality; " \
           "tail was ...#{script[-(tail.length + 16)..]}"
    # The pre-fix truncation shape (seven OP_NIPs straight into the compare)
    # must be absent.
    refute script.end_with?(("77" * 7) + "7c9c")
  end

  # Go R-172 / Rust N-237 / Python F-260: the emitter's own bound is 32, so
  # the lowering gate must be 32, not 64. Depth 33 must be refused by a
  # diagnostic naming the BUILTIN the caller wrote (merkleRootPoseidon2KB),
  # not the internal emitter function (emit_poseidon2_merkle_root) and not an
  # "internal error" wrapper.
  def test_depth_above_32_is_refused_by_name
    err = assert_raises(RuntimeError) do
      RunarCompiler.compile_from_ir_bytes(probe_ir(depth: 33))
    end
    assert_includes err.message, "merkleRootPoseidon2KB",
                     "diagnostic must name the builtin, got: #{err.message}"
    assert_includes err.message, "between 1 and 32",
                     "diagnostic must state the 1..32 bound, got: #{err.message}"
    refute_match(/internal error/, err.message,
                 "must be a deliberate refusal, not the internal-error wrapper: #{err.message}")
  end

  # A depth within the old (wrong) 1..64 gate but above the emitter's real
  # bound of 32 must be refused the same way -- this is exactly the range the
  # old 1..64 gate let through into the emitter.
  def test_depth_64_within_old_wrong_gate_is_still_refused_by_name
    err = assert_raises(RuntimeError) do
      RunarCompiler.compile_from_ir_bytes(probe_ir(depth: 64))
    end
    assert_includes err.message, "merkleRootPoseidon2KB"
    assert_includes err.message, "between 1 and 32"
  end

  # Arity not matching the depth the last argument claims must still be
  # refused by name (unchanged behavior; guards against a regression in the
  # gate rewrite).
  def test_arity_not_matching_depth_is_refused_by_name
    err = assert_raises(RuntimeError) do
      RunarCompiler.compile_from_ir_bytes(probe_ir(depth: 1, extra_args: 8))
    end
    assert_includes err.message, "merkleRootPoseidon2KB"
    assert_includes err.message, "expected 18 arguments"
  end
end
