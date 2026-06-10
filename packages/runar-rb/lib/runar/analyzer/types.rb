# frozen_string_literal: true

module Runar
  module Analyzer
    # Severity ranks (lower = sorts earlier).
    SEVERITY_RANK = {
      'error' => 0,
      'warning' => 1,
      'info' => 2
    }.freeze

    LARGE_SCRIPT_THRESHOLD = 500_000
    MAX_PATHS = 256

    # Stack effect table per spec §8.1. Default for unlisted is [0,0].
    STACK_EFFECTS = {
      0x61 => [0, 0],   # OP_NOP
      0x63 => [1, 0],   # OP_IF
      0x64 => [1, 0],   # OP_NOTIF
      0x67 => [0, 0],   # OP_ELSE
      0x68 => [0, 0],   # OP_ENDIF
      0x69 => [1, 0],   # OP_VERIFY
      0x6a => [0, 0],   # OP_RETURN
      0x6b => [1, 0],   # OP_TOALTSTACK
      0x6c => [0, 1],   # OP_FROMALTSTACK
      0x6d => [2, 0],   # OP_2DROP
      0x6e => [2, 4],   # OP_2DUP
      0x6f => [3, 6],   # OP_3DUP
      0x70 => [4, 6],   # OP_2OVER
      0x71 => [6, 6],   # OP_2ROT
      0x72 => [4, 4],   # OP_2SWAP
      0x73 => [1, 1],   # OP_IFDUP
      0x74 => [0, 1],   # OP_DEPTH
      0x75 => [1, 0],   # OP_DROP
      0x76 => [1, 2],   # OP_DUP
      0x77 => [2, 1],   # OP_NIP
      0x78 => [2, 3],   # OP_OVER
      0x79 => [1, 1],   # OP_PICK
      0x7a => [1, 0],   # OP_ROLL
      0x7b => [3, 3],   # OP_ROT
      0x7c => [2, 2],   # OP_SWAP
      0x7d => [2, 3],   # OP_TUCK
      0x7e => [2, 1],   # OP_CAT
      0x7f => [2, 2],   # OP_SPLIT
      0x80 => [2, 1],   # OP_NUM2BIN
      0x81 => [1, 1],   # OP_BIN2NUM
      0x82 => [1, 2],   # OP_SIZE
      0x83 => [1, 1],   # OP_INVERT
      0x84 => [2, 1],   # OP_AND
      0x85 => [2, 1],   # OP_OR
      0x86 => [2, 1],   # OP_XOR
      0x87 => [2, 1],   # OP_EQUAL
      0x88 => [2, 0],   # OP_EQUALVERIFY
      0x8b => [1, 1],   # OP_1ADD
      0x8c => [1, 1],   # OP_1SUB
      0x8f => [1, 1],   # OP_NEGATE
      0x90 => [1, 1],   # OP_ABS
      0x91 => [1, 1],   # OP_NOT
      0x92 => [1, 1],   # OP_0NOTEQUAL
      0x93 => [2, 1],   # OP_ADD
      0x94 => [2, 1],   # OP_SUB
      0x95 => [2, 1],   # OP_MUL
      0x96 => [2, 1],   # OP_DIV
      0x97 => [2, 1],   # OP_MOD
      0x98 => [2, 1],   # OP_LSHIFT
      0x99 => [2, 1],   # OP_RSHIFT
      0x9a => [2, 1],   # OP_BOOLAND
      0x9b => [2, 1],   # OP_BOOLOR
      0x9c => [2, 1],   # OP_NUMEQUAL
      0x9d => [2, 0],   # OP_NUMEQUALVERIFY
      0x9e => [2, 1],   # OP_NUMNOTEQUAL
      0x9f => [2, 1],   # OP_LESSTHAN
      0xa0 => [2, 1],   # OP_GREATERTHAN
      0xa1 => [2, 1],   # OP_LESSTHANOREQUAL
      0xa2 => [2, 1],   # OP_GREATERTHANOREQUAL
      0xa3 => [2, 1],   # OP_MIN
      0xa4 => [2, 1],   # OP_MAX
      0xa5 => [3, 1],   # OP_WITHIN
      0xa6 => [1, 1],   # OP_RIPEMD160
      0xa7 => [1, 1],   # OP_SHA1
      0xa8 => [1, 1],   # OP_SHA256
      0xa9 => [1, 1],   # OP_HASH160
      0xaa => [1, 1],   # OP_HASH256
      0xac => [2, 1],   # OP_CHECKSIG
      0xad => [2, 0],   # OP_CHECKSIGVERIFY
      0xae => [3, 1],   # OP_CHECKMULTISIG
      0xaf => [3, 0]    # OP_CHECKMULTISIGVERIFY
    }.freeze

    # Verification opcodes (cause path to NOT be UNCONDITIONALLY_SUCCEEDS).
    VERIFICATION_OPCODES = [
      0x69, # OP_VERIFY
      0x6a, # OP_RETURN
      0x88, # OP_EQUALVERIFY
      0x9d, # OP_NUMEQUALVERIFY
      0xac, # OP_CHECKSIG
      0xad, # OP_CHECKSIGVERIFY
      0xae, # OP_CHECKMULTISIG
      0xaf  # OP_CHECKMULTISIGVERIFY
    ].freeze

    SIG_OPCODES = [0xac, 0xad, 0xae, 0xaf].freeze
  end
end
