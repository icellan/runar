# frozen_string_literal: true

require_relative 'codegen_helper'

# Unit-vector test for the Ruby WOTS+ codegen. `verifyWOTS` lowers to a
# fully-unrolled chain-walk over WOTS_LEN positions, each running the
# F-function (a 1-block SHA-256). The test compiles a stub contract and
# asserts the emitted ASM contains the hallmark of that loop.

class TestWotsCodegen < Minitest::Test
  include CodegenTestHelpers

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
end
