# frozen_string_literal: true

require_relative 'codegen_helper'
require 'runar_compiler/codegen/rabin'

# Unit-vector test for Rabin signature verification codegen. The
# `verifyRabinSig` builtin lowers via the standalone
# `RunarCompiler::Codegen::Rabin` module (extracted from stack.rb under
# GAP-M1). These assertions lock down both the extracted module's
# byte-frozen opcode sequence and the emitted-script shape.

class TestRabinCodegen < Minitest::Test
  include CodegenTestHelpers

  # Byte-frozen golden: the fixed 15-opcode Rabin verification sequence
  # (sig^2 + padding) mod pubKey == SHA256(msg) AND 0 <= padding < 65536.
  # Mirrored across all 7 tiers. Position 9 is a push of 65536 (the BUG-010
  # padding limit), not an opcode — nil here means "skip opcode-code check,
  # validate as push below".
  RABIN_GOLDEN = [
    nil, # F-144: pubKey sign byte (0x00)
    'OP_CAT',
    'OP_BIN2NUM',
    'OP_SWAP',
    nil, # F-144: padding sign byte (0x00)
    'OP_CAT',
    'OP_BIN2NUM',
    'OP_DUP',
    'OP_0',
    nil, # push 65536
    'OP_WITHIN',
    'OP_VERIFY',
    'OP_ROT',
    nil, # F-144: sig sign byte (0x00)
    'OP_CAT',
    'OP_BIN2NUM',
    'OP_DUP',
    'OP_MUL',
    'OP_ADD',
    'OP_OVER', # F-047: keep pubKey for the digest reduction
    'OP_MOD',
    'OP_ROT',
    'OP_SHA256',
    nil, # BUG-011 digest sign byte (0x00)
    'OP_CAT',
    'OP_BIN2NUM',
    'OP_ROT', # F-047
    'OP_MOD', # F-047: SHA256(msg) mod pubKey
    'OP_NUMEQUAL'
  ].freeze

  def test_rabin_module_emits_byte_frozen_golden
    ops = []
    RunarCompiler::Codegen::Rabin.emit_verify_rabin_sig(->(op) { ops << op })

    assert_equal RABIN_GOLDEN.length, ops.length
    ops.each_with_index do |op, i|
      expected = RABIN_GOLDEN[i]
      if expected.nil? && i == 9
        assert_equal 'push', op[:op], "op #{i}: expected push"
        assert_equal 'bigint', op[:value][:kind], "op #{i}: push kind"
        assert_equal 65_536, op[:value][:big_int], "op #{i}: BUG-010 padding limit"
      elsif expected.nil?
        # F-144 operand sign bytes (0, 4, 13) and the BUG-011 digest sign byte
        # (23): each makes the item below it read as a NON-NEGATIVE Script number.
        assert_equal 'push', op[:op], "op #{i}: expected push"
        assert_equal 'bytes', op[:value][:kind], "op #{i}: push kind"
        assert_equal "\x00".b, op[:value][:bytes_val], "op #{i}: sign byte"
      else
        assert_equal 'opcode', op[:op], "op #{i}: expected opcode"
        assert_equal expected, op[:code], "op #{i}"
      end
    end
  end

  def test_verify_rabin_sig_emits_modular_check
    source = <<~TS
      import { SmartContract, assert, verifyRabinSig } from 'runar-lang';
      import type { ByteString, RabinSig, RabinPubKey } from 'runar-lang';

      class RabinVerifyTest extends SmartContract {
        readonly pubKey: RabinPubKey;

        constructor(pubKey: RabinPubKey) {
          super(pubKey);
          this.pubKey = pubKey;
        }

        // F-286: the modulus is a contract property. A spending-method
        // argument would let the spender pick it, and is refused.
        public verify(msg: ByteString, sig: RabinSig, padding: ByteString) {
          assert(verifyRabinSig(msg, sig, padding, this.pubKey));
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
