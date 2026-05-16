# frozen_string_literal: true

require_relative 'codegen_helper'
require 'runar_compiler/codegen/blake3'

# Unit-vector tests for the Ruby BLAKE3 codegen module
# (compilers/ruby/lib/runar_compiler/codegen/blake3.rb).

class TestBlake3Codegen < Minitest::Test
  include CodegenTestHelpers

  def test_blake3_compress_emits_round_function
    source = <<~TS
      import { SmartContract, assert, blake3Compress } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Blake3CompressTest extends SmartContract {
        readonly expected: ByteString;

        constructor(expected: ByteString) {
          super(expected);
          this.expected = expected;
        }

        public verify(cv: ByteString, block: ByteString) {
          const result = blake3Compress(cv, block);
          assert(result === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'Blake3CompressTest.runar.ts')
    assert_equal 'Blake3CompressTest', artifact.contract_name
    assert artifact.script.length.positive?, 'script must be non-empty'

    asm = artifact.asm
    # 7 rounds × 8 G mixings — we expect a lot of ADD / XOR ops for the
    # 32-bit ARX core.
    assert_includes asm, 'OP_ADD'
    assert_includes asm, 'OP_XOR'

    # Inlined BLAKE3 compression is multi-KB.
    assert_operator artifact.script.length / 2, :>, 1_000
  end

  def test_blake3_hash_emits_padding_and_compress
    source = <<~TS
      import { SmartContract, assert, blake3Hash } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class Blake3HashTest extends SmartContract {
        readonly expected: ByteString;

        constructor(expected: ByteString) {
          super(expected);
          this.expected = expected;
        }

        public verify(message: ByteString) {
          const result = blake3Hash(message);
          assert(result === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'Blake3HashTest.runar.ts')
    assert_equal 'Blake3HashTest', artifact.contract_name

    asm = artifact.asm
    assert_includes asm, 'OP_ADD'
    assert_includes asm, 'OP_XOR'
    assert_operator artifact.script.length / 2, :>, 1_000
  end

  # ---------------------------------------------------------------------------
  # T-11: Op-count goldens for the BLAKE3 emitters.
  #
  # The ASM-substring tests above catch a gross regression but not byte-level
  # codegen drift. Numbers mirror the Python peer
  # (compilers/python/tests/codegen/test_blake3.py) and the Java reference at
  # the same commit. Final hex is byte-identical across all 7 tiers
  # (enforced by the conformance harness); these goldens are an in-process
  # localized-regression gate.
  # ---------------------------------------------------------------------------

  def test_blake3_compress_op_count_golden
    ops = []
    RunarCompiler::Codegen::Blake3.emit_blake3_compress(->(op) { ops << op })
    assert_equal 10819, ops.length, "blake3Compress op count drift"
  end

  def test_blake3_hash_op_count_golden
    ops = []
    RunarCompiler::Codegen::Blake3.emit_blake3_hash(->(op) { ops << op })
    assert_equal 10829, ops.length, "blake3Hash op count drift"
  end
end
