# frozen_string_literal: true

require_relative 'codegen_helper'
require 'runar_compiler/codegen/sha256'

# Unit-vector tests for the Ruby SHA-256 codegen module
# (compilers/ruby/lib/runar_compiler/codegen/sha256.rb).
#
# The Go peer codegen module emits the same opcode shape, exercised in
# integration via integration/go/sha256_compress_test.go etc. The tests
# here lock down the *shape* of the emitted script (hallmark opcodes
# present, script size in a sensible band) so a regression in stack-
# lowering or emit will be caught at the unit level rather than only via
# the regtest suite.

class TestSha256Codegen < Minitest::Test
  include CodegenTestHelpers

  # ---------------------------------------------------------------------------
  # sha256Compress: 64-byte block + 32-byte chaining value -> 32-byte hash
  # ---------------------------------------------------------------------------

  def test_sha256_compress_emits_hash_opcodes
    source = <<~TS
      import { SmartContract, assert, sha256Compress } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Sha256CompressTest extends SmartContract {
        readonly expected: ByteString;

        constructor(expected: ByteString) {
          super(expected);
          this.expected = expected;
        }

        public verify(state: ByteString, block: ByteString) {
          const result = sha256Compress(state, block);
          assert(result === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'Sha256CompressTest.runar.ts')
    assert_equal 'Sha256CompressTest', artifact.contract_name
    assert artifact.script.length.positive?, 'script must be non-empty'

    # SHA-256 compression unrolls 64 rounds in script. The emitted ASM
    # must include arithmetic + bitwise operators to compute the round
    # function inline.
    asm = artifact.asm
    assert_includes asm, 'OP_ADD',     'expected ADD ops for round arithmetic'
    assert_includes asm, 'OP_AND',     'expected AND ops for sigma functions'
    assert_includes asm, 'OP_XOR',     'expected XOR ops for sigma functions'

    # Script must be substantially larger than a vanilla P2PKH (~25 bytes).
    # SHA-256 compression in script is multi-KB.
    assert_operator artifact.script.length / 2, :>, 1_000,
                    'sha256Compress should produce a multi-KB script'
  end

  # ---------------------------------------------------------------------------
  # sha256Finalize: padding + length encoding for variable-length messages
  # ---------------------------------------------------------------------------

  def test_sha256_finalize_emits_padding_logic
    source = <<~TS
      import { SmartContract, assert, sha256Finalize } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Sha256FinalizeTest extends SmartContract {
        readonly expected: ByteString;

        constructor(expected: ByteString) {
          super(expected);
          this.expected = expected;
        }

        public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
          const result = sha256Finalize(state, remaining, msgBitLen);
          assert(result === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'Sha256FinalizeTest.runar.ts')
    assert_equal 'Sha256FinalizeTest', artifact.contract_name
    assert artifact.script.length.positive?

    # The finalize path adds 0x80 padding + 8-byte big-endian length, then
    # invokes the same compression rounds, so the script is at least as
    # large as the compress-only variant.
    assert_operator artifact.script.length / 2, :>, 1_000,
                    'sha256Finalize should produce a multi-KB script'
    asm = artifact.asm
    assert_includes asm, 'OP_ADD'
    assert_includes asm, 'OP_AND'
  end

  # ---------------------------------------------------------------------------
  # T-11: Op-count goldens for the SHA-256 emitters.
  #
  # The ASM-substring tests above catch a gross regression but not byte-level
  # codegen drift. Numbers mirror the Python peer
  # (compilers/python/tests/codegen/test_sha256.py) and the Java reference
  # at the same commit. Final hex is byte-identical across all 7 tiers
  # (enforced by the conformance harness); these goldens are an in-process
  # localized-regression gate.
  # ---------------------------------------------------------------------------

  def test_sha256_compress_op_count_golden
    ops = []
    RunarCompiler::Codegen::SHA256Codegen.emit_sha256_compress(->(op) { ops << op })
    assert_equal 21292, ops.length, "sha256Compress op count drift"
  end

  def test_sha256_finalize_op_count_golden
    ops = []
    RunarCompiler::Codegen::SHA256Codegen.emit_sha256_finalize(->(op) { ops << op })
    assert_equal 63941, ops.length, "sha256Finalize op count drift"
  end
end
