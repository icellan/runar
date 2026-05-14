# frozen_string_literal: true

# Standalone Rabin signature verification Bitcoin Script codegen for the
# Runar Ruby stack lowerer.
#
# emit_verify_rabin_sig: [msg, sig, padding, pubKey] -> [bool]
#
# Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg).
# The emission is a fixed 10-opcode sequence:
#
#   OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
#
# The caller must bring the 4 arguments to the top of the stack in argument
# order (msg sig padding pubKey, pubKey on top) before calling.
#
# Direct port of packages/runar-compiler/src/passes/rabin-codegen.ts.

module RunarCompiler
  module Codegen
    module Rabin
      # The fixed 10-opcode Rabin verification sequence.
      OPCODE_SEQUENCE = %w[
        OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD
        OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
      ].freeze

      # Emit the Rabin signature verification opcode sequence.
      #
      # Stack on entry (bottom->top): msg sig padding pubKey
      # Stack on exit:                bool (1 = valid, 0 = invalid)
      #
      # @param emit_fn [Proc] callback invoked with each StackOp hash
      def self.emit_verify_rabin_sig(emit_fn)
        OPCODE_SEQUENCE.each do |code|
          emit_fn.call({ op: "opcode", code: code })
        end
      end
    end
  end
end
