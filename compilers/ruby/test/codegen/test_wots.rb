# frozen_string_literal: true

require 'digest'
require_relative 'codegen_helper'
require 'runar_compiler/codegen/wots'

# Unit-vector test for the Ruby WOTS+ codegen. `verifyWOTS` lowers to a
# fully-unrolled chain-walk over WOTS_LEN positions, each running the
# F-function (a 1-block SHA-256). The test compiles a stub contract and
# asserts the emitted ASM contains the hallmark of that loop.

class TestWotsCodegen < Minitest::Test
  include CodegenTestHelpers

  # Frozen pre-extraction baseline captured against
  # `RunarCompiler::Codegen::SLHDSA.emit_verify_wots` BEFORE the WOTS+ helpers
  # were extracted into `RunarCompiler::Codegen::WOTS`. Any drift in the
  # post-extraction `WOTS.emit_verify_wots` opcode stream will trip both the
  # length and the Marshal.dump SHA-256 fingerprint.
  WOTS_VERIFY_OPS_LENGTH       = 5438
  WOTS_VERIFY_OPS_FINGERPRINT  = 'b5799f1077059f19b8aea3bc39aa6b9d4a0a82c6603d1b38506ef7c7fdcf51dc'

  def test_verify_wots_emits_unrolled_chain
    source = <<~TS
      import { SmartContract, assert, verifyWOTS } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class WotsVerifyTest extends SmartContract {
        readonly pkRoot: ByteString;

        constructor(pkRoot: ByteString) {
          super(pkRoot);
          this.pkRoot = pkRoot;
        }

        public verify(message: ByteString, signature: ByteString) {
          assert(verifyWOTS(message, signature, this.pkRoot));
        }
      }
    TS

    artifact = compile_ts_source(source, 'WotsVerifyTest.runar.ts')
    assert_equal 'WotsVerifyTest', artifact.contract_name
    assert artifact.script.length.positive?

    asm = artifact.asm
    # WOTS+ verification is dominated by SHA-256 calls inside the chain.
    assert_includes asm, 'OP_SHA256'

    # WOTS+ scripts are large — comments in `compilers/ruby/lib/runar_compiler/codegen`
    # peg the verifyWOTS script at ~10 KB.
    assert_operator artifact.script.length / 2, :>, 5_000,
                    'verifyWOTS should produce a ≥5 KB script'
  end

  # Probe specifically for the WOTS+ extraction (audit GAP-002):
  # - WOTS lives in its own module, not inside SLHDSA.
  # - The byte stream emitted by the standalone entry point is byte-identical
  #   to the pre-extraction baseline.
  def test_wots_module_extracted_from_slh_dsa
    assert RunarCompiler::Codegen.const_defined?(:WOTS),
           'expected RunarCompiler::Codegen::WOTS to exist after extraction'
    assert RunarCompiler::Codegen::WOTS.respond_to?(:emit_verify_wots),
           'expected WOTS.emit_verify_wots to be the public entry point'

    ops = []
    emit = ->(op) { ops << op }
    RunarCompiler::Codegen::WOTS.emit_verify_wots(emit)

    assert_equal WOTS_VERIFY_OPS_LENGTH, ops.length,
                 'WOTS.emit_verify_wots must emit the same number of ops as pre-extraction'
    assert_equal WOTS_VERIFY_OPS_FINGERPRINT,
                 Digest::SHA256.hexdigest(Marshal.dump(ops)),
                 'WOTS.emit_verify_wots opcode fingerprint must match the pre-extraction baseline'
  end
end
