# frozen_string_literal: true

require_relative 'codegen_helper'

# Unit-vector test for Rabin signature verification codegen — the
# `verifyRabinSig` builtin is consumed by the Ruby stack-lower module
# (no dedicated rabin.rb codegen file exists; it lowers via the generic
# bigint stack ops + an inline modular-arithmetic sequence). These
# assertions lock down the emitted-script shape.

class TestRabinCodegen < Minitest::Test
  include CodegenTestHelpers

  def test_verify_rabin_sig_emits_modular_check
    source = <<~TS
      import { SmartContract, assert, verifyRabinSig } from 'runar-lang';
      import type { ByteString, RabinSig, RabinPubKey } from 'runar-lang';

      class RabinVerifyTest extends SmartContract {
        readonly expectedHash: ByteString;

        constructor(expectedHash: ByteString) {
          super(expectedHash);
          this.expectedHash = expectedHash;
        }

        public verify(msg: ByteString, sig: RabinSig, padding: ByteString, pubKey: RabinPubKey) {
          assert(verifyRabinSig(msg, sig, padding, pubKey));
        }
      }
    TS

    artifact = compile_ts_source(source, 'RabinVerifyTest.runar.ts')
    assert_equal 'RabinVerifyTest', artifact.contract_name
    assert artifact.script.length.positive?, 'script must be non-empty'

    asm = artifact.asm
    # Rabin verify computes (sig^2 + padding) mod n and compares to the
    # message hash. We expect MUL / ADD / MOD opcodes for the modular
    # arithmetic and a hash op for the message.
    assert_includes asm, 'OP_MUL'
    assert_includes asm, 'OP_ADD'
    assert_includes asm, 'OP_MOD'
    assert_includes asm, 'OP_SHA256'
  end
end
