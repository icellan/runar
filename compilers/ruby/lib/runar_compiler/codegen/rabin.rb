# frozen_string_literal: true

# Standalone Rabin signature verification Bitcoin Script codegen for the
# Runar Ruby stack lowerer.
#
# emit_verify_rabin_sig: [msg, sig, padding, pubKey] -> [bool]
#
# Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg)
# AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010).
# The emission is a fixed 15-opcode sequence:
#
#   OP_SWAP
#   OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   # 0 <= padding < 65536 (BUG-010)
#   OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
#
# The caller must bring the 4 arguments to the top of the stack in argument
# order (msg sig padding pubKey, pubKey on top) before calling.
#
# Direct port of packages/runar-compiler/src/passes/rabin-codegen.ts.

module RunarCompiler
  module Codegen
    module Rabin
      # Exclusive upper bound on the Rabin `padding` parameter, enforced on-chain.
      # The legitimate signer (packages/runar-go/rabin.go::RabinSign) produces
      # padding < 1000; the on-chain bound is 65536 (16-bit) for slack.
      # See _review/BUG-010-rfc.md.
      RABIN_PADDING_LIMIT = 65_536

      # Emit the Rabin signature verification opcode sequence.
      #
      # Stack on entry (bottom->top): msg sig padding pubKey
      # Stack on exit:                bool (1 = valid, 0 = invalid)
      #
      # @param emit_fn [Proc] callback invoked with each StackOp hash
      def self.emit_verify_rabin_sig(emit_fn)
        emit_fn.call({ op: "opcode", code: "OP_SWAP" })
        # BUG-010 padding range check: assert 0 <= padding < 65536.
        emit_fn.call({ op: "opcode", code: "OP_DUP" })
        emit_fn.call({ op: "opcode", code: "OP_0" })
        emit_fn.call({ op: "push", value: { kind: "bigint", big_int: RABIN_PADDING_LIMIT } })
        emit_fn.call({ op: "opcode", code: "OP_WITHIN" })
        emit_fn.call({ op: "opcode", code: "OP_VERIFY" })
        emit_fn.call({ op: "opcode", code: "OP_ROT" })
        emit_fn.call({ op: "opcode", code: "OP_DUP" })
        emit_fn.call({ op: "opcode", code: "OP_MUL" })
        emit_fn.call({ op: "opcode", code: "OP_ADD" })
        emit_fn.call({ op: "opcode", code: "OP_SWAP" })
        emit_fn.call({ op: "opcode", code: "OP_MOD" })
        emit_fn.call({ op: "opcode", code: "OP_SWAP" })
        emit_fn.call({ op: "opcode", code: "OP_SHA256" })
        emit_fn.call({ op: "opcode", code: "OP_EQUAL" })
      end

    end
  end
end
