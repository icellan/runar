# frozen_string_literal: true

# Standalone Rabin signature verification Bitcoin Script codegen for the
# Runar Ruby stack lowerer.
#
# emit_verify_rabin_sig: [msg, sig, padding, pubKey] -> [bool]
#
# Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg) mod pubKey
# AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010)
# AND sig is in [0, pubKey) — also enforced on-chain (F-368; sig >= 0 holds
# after F-144, so only sig < pubKey costs opcodes).
# The emission is a fixed 34-opcode sequence:
#
#   <push 0x00> OP_CAT OP_BIN2NUM                   # pubKey as unsigned (F-144)
#   OP_SWAP
#   <push 0x00> OP_CAT OP_BIN2NUM                   # padding as unsigned (F-144)
#   OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   # 0 <= padding < 65536 (BUG-010)
#   OP_ROT
#   <push 0x00> OP_CAT OP_BIN2NUM                   # sig as unsigned (F-144)
#   OP_DUP OP_3 OP_PICK OP_LESSTHAN OP_VERIFY      # sig < pubKey (F-368)
#   OP_DUP OP_MUL OP_ADD OP_OVER OP_MOD
#   OP_ROT OP_SHA256 <push 0x00> OP_CAT OP_BIN2NUM
#   OP_ROT OP_MOD OP_NUMEQUAL                       # digest mod pubKey (F-047)
#
# OPERAND SIGN (F-144): off-chain verifiers read padding (and the native
# Go/Rust/Python/Ruby/Zig layers also sig and pubKey) as UNSIGNED
# little-endian bytes; OP_WITHIN / OP_MUL / OP_MOD read a Script number,
# whose last byte's high bit is the sign. Each operand gets an explicit
# 0x00 sign byte and OP_BIN2NUM, so a raw unsigned push keeps its unsigned
# value and a non-negative Script number is unchanged.
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
        emit_fn.call({ op: "push", value: { kind: "bytes", bytes_val: "\x00".b } }) # F-144: pubKey as unsigned
        emit_fn.call({ op: "opcode", code: "OP_CAT" })
        emit_fn.call({ op: "opcode", code: "OP_BIN2NUM" })
        emit_fn.call({ op: "opcode", code: "OP_SWAP" })
        emit_fn.call({ op: "push", value: { kind: "bytes", bytes_val: "\x00".b } }) # F-144: padding as unsigned
        emit_fn.call({ op: "opcode", code: "OP_CAT" })
        emit_fn.call({ op: "opcode", code: "OP_BIN2NUM" })
        # BUG-010 padding range check: assert 0 <= padding < 65536.
        emit_fn.call({ op: "opcode", code: "OP_DUP" })
        emit_fn.call({ op: "opcode", code: "OP_0" })
        emit_fn.call({ op: "push", value: { kind: "bigint", big_int: RABIN_PADDING_LIMIT } })
        emit_fn.call({ op: "opcode", code: "OP_WITHIN" })
        emit_fn.call({ op: "opcode", code: "OP_VERIFY" })
        emit_fn.call({ op: "opcode", code: "OP_ROT" })
        emit_fn.call({ op: "push", value: { kind: "bytes", bytes_val: "\x00".b } }) # F-144: sig as unsigned
        emit_fn.call({ op: "opcode", code: "OP_CAT" })
        emit_fn.call({ op: "opcode", code: "OP_BIN2NUM" })
        # F-368: assert sig < pubKey (sig >= 0 already holds after F-144), so the
        # sig + k*pubKey re-encodings of one signature are refused.
        emit_fn.call({ op: "opcode", code: "OP_DUP" })
        emit_fn.call({ op: "push", value: { kind: "bigint", big_int: 3 } })
        emit_fn.call({ op: "opcode", code: "OP_PICK" })
        emit_fn.call({ op: "opcode", code: "OP_LESSTHAN" })
        emit_fn.call({ op: "opcode", code: "OP_VERIFY" })
        emit_fn.call({ op: "opcode", code: "OP_DUP" })
        emit_fn.call({ op: "opcode", code: "OP_MUL" })
        emit_fn.call({ op: "opcode", code: "OP_ADD" })
        emit_fn.call({ op: "opcode", code: "OP_OVER" }) # F-047: keep pubKey for the digest reduction
        emit_fn.call({ op: "opcode", code: "OP_MOD" })
        emit_fn.call({ op: "opcode", code: "OP_ROT" })
        emit_fn.call({ op: "opcode", code: "OP_SHA256" })
        # BUG-011 digest-encoding normalization: OP_MOD leaves a MINIMAL Script
        # number, which carries a trailing 0x00 sign byte whenever the digest's
        # most-significant byte has its high bit set (~50% of messages), while
        # OP_SHA256 pushes exactly 32 raw bytes. A bare OP_EQUAL is a BYTE
        # compare and refused about half of all honest signatures on a real
        # consensus VM. Give the digest an explicit 0x00 sign byte, collapse to
        # minimal form, and compare NUMERICALLY. OP_NUMEQUAL never aborts, so
        # the any-of-N pattern still yields false rather than killing the script.
        emit_fn.call({ op: "push", value: { kind: "bytes", bytes_val: "\x00".b } })
        emit_fn.call({ op: "opcode", code: "OP_CAT" })
        emit_fn.call({ op: "opcode", code: "OP_BIN2NUM" })
        # F-047: reduce the digest mod pubKey, matching every off-chain verifier.
        emit_fn.call({ op: "opcode", code: "OP_ROT" })
        emit_fn.call({ op: "opcode", code: "OP_MOD" })
        emit_fn.call({ op: "opcode", code: "OP_NUMEQUAL" })
      end

    end
  end
end
