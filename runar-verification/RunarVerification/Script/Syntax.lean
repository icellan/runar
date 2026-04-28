/-!
# Bitcoin Script — Syntax

A Lean model of Bitcoin Script that is rich enough to express the
full BSV consensus opcode set (codes `0x00..0xff`) while staying
small enough to keep proofs tractable.

We represent an opcode as a `UInt8` (the on-wire byte value). Named
constants are defined for the ~80 opcodes that Rúnar emits or that
appear in the standard set; other byte values are valid `Opcode`
values but lack a textual name in the disassembler.

A `Script` is a flat list of `ScriptElem`s. `ScriptElem` is either an
opcode byte, or a pushdata payload (the consensus interpreter splits
this internally; we keep the high-level form so emit / parse can
round-trip cleanly).

Mirrors `OPCODES` in `packages/runar-compiler/src/passes/06-emit.ts:20–123`.
-/

namespace RunarVerification.Script

/-- An opcode is just its on-wire byte value. -/
abbrev Opcode := UInt8

namespace Opcode

/-! ## Push opcodes (0x00..0x4f) -/

def OP_0           : Opcode := 0x00
def OP_FALSE       : Opcode := 0x00
def OP_PUSHDATA1   : Opcode := 0x4c
def OP_PUSHDATA2   : Opcode := 0x4d
def OP_PUSHDATA4   : Opcode := 0x4e
def OP_1NEGATE     : Opcode := 0x4f
def OP_1           : Opcode := 0x51
def OP_TRUE        : Opcode := 0x51
def OP_2           : Opcode := 0x52
def OP_3           : Opcode := 0x53
def OP_4           : Opcode := 0x54
def OP_5           : Opcode := 0x55
def OP_6           : Opcode := 0x56
def OP_7           : Opcode := 0x57
def OP_8           : Opcode := 0x58
def OP_9           : Opcode := 0x59
def OP_10          : Opcode := 0x5a
def OP_11          : Opcode := 0x5b
def OP_12          : Opcode := 0x5c
def OP_13          : Opcode := 0x5d
def OP_14          : Opcode := 0x5e
def OP_15          : Opcode := 0x5f
def OP_16          : Opcode := 0x60

/-! ## Control flow (0x61..0x6a) -/

def OP_NOP             : Opcode := 0x61
def OP_IF              : Opcode := 0x63
def OP_NOTIF           : Opcode := 0x64
def OP_ELSE            : Opcode := 0x67
def OP_ENDIF           : Opcode := 0x68
def OP_VERIFY          : Opcode := 0x69
def OP_RETURN          : Opcode := 0x6a

/-! ## Stack ops (0x6b..0x7d) -/

def OP_TOALTSTACK      : Opcode := 0x6b
def OP_FROMALTSTACK    : Opcode := 0x6c
def OP_2DROP           : Opcode := 0x6d
def OP_2DUP            : Opcode := 0x6e
def OP_3DUP            : Opcode := 0x6f
def OP_2OVER           : Opcode := 0x70
def OP_2ROT            : Opcode := 0x71
def OP_2SWAP           : Opcode := 0x72
def OP_IFDUP           : Opcode := 0x73
def OP_DEPTH           : Opcode := 0x74
def OP_DROP            : Opcode := 0x75
def OP_DUP             : Opcode := 0x76
def OP_NIP             : Opcode := 0x77
def OP_OVER            : Opcode := 0x78
def OP_PICK            : Opcode := 0x79
def OP_ROLL            : Opcode := 0x7a
def OP_ROT             : Opcode := 0x7b
def OP_SWAP            : Opcode := 0x7c
def OP_TUCK            : Opcode := 0x7d

/-! ## Splice ops (0x7e..0x82) -/

def OP_CAT             : Opcode := 0x7e
def OP_SPLIT           : Opcode := 0x7f
def OP_NUM2BIN         : Opcode := 0x80
def OP_BIN2NUM         : Opcode := 0x81
def OP_SIZE            : Opcode := 0x82

/-! ## Bitwise (0x83..0x86) -/

def OP_INVERT          : Opcode := 0x83
def OP_AND             : Opcode := 0x84
def OP_OR              : Opcode := 0x85
def OP_XOR             : Opcode := 0x86

/-! ## Equality (0x87..0x88) -/

def OP_EQUAL           : Opcode := 0x87
def OP_EQUALVERIFY     : Opcode := 0x88

/-! ## Arithmetic (0x8b..0x9b) -/

def OP_1ADD            : Opcode := 0x8b
def OP_1SUB            : Opcode := 0x8c
def OP_2MUL            : Opcode := 0x8d   -- Chronicle
def OP_2DIV            : Opcode := 0x8e   -- Chronicle
def OP_NEGATE          : Opcode := 0x8f
def OP_ABS             : Opcode := 0x90
def OP_NOT             : Opcode := 0x91
def OP_0NOTEQUAL       : Opcode := 0x92
def OP_ADD             : Opcode := 0x93
def OP_SUB             : Opcode := 0x94
def OP_MUL             : Opcode := 0x95
def OP_DIV             : Opcode := 0x96
def OP_MOD             : Opcode := 0x97
def OP_LSHIFT          : Opcode := 0x98
def OP_RSHIFT          : Opcode := 0x99
def OP_BOOLAND         : Opcode := 0x9a
def OP_BOOLOR          : Opcode := 0x9b

/-! ## Comparison (0x9c..0xa5) -/

def OP_NUMEQUAL        : Opcode := 0x9c
def OP_NUMEQUALVERIFY  : Opcode := 0x9d
def OP_NUMNOTEQUAL     : Opcode := 0x9e
def OP_LESSTHAN        : Opcode := 0x9f
def OP_GREATERTHAN     : Opcode := 0xa0
def OP_LESSTHANOREQUAL : Opcode := 0xa1
def OP_GREATERTHANOREQUAL : Opcode := 0xa2
def OP_MIN             : Opcode := 0xa3
def OP_MAX             : Opcode := 0xa4
def OP_WITHIN          : Opcode := 0xa5

/-! ## Crypto (0xa6..0xaf) -/

def OP_RIPEMD160          : Opcode := 0xa6
def OP_SHA1               : Opcode := 0xa7
def OP_SHA256             : Opcode := 0xa8
def OP_HASH160            : Opcode := 0xa9
def OP_HASH256            : Opcode := 0xaa
def OP_CODESEPARATOR      : Opcode := 0xab
def OP_CHECKSIG           : Opcode := 0xac
def OP_CHECKSIGVERIFY     : Opcode := 0xad
def OP_CHECKMULTISIG      : Opcode := 0xae
def OP_CHECKMULTISIGVERIFY: Opcode := 0xaf

/-! ## Chronicle string ops (0xb3..0xb7) -/

def OP_SUBSTR             : Opcode := 0xb3
def OP_LEFT               : Opcode := 0xb4
def OP_RIGHT              : Opcode := 0xb5
def OP_LSHIFTNUM          : Opcode := 0xb6
def OP_RSHIFTNUM          : Opcode := 0xb7

end Opcode

/-! ## Script element

The interpreter consumes either an opcode byte or pushdata bytes.
We model the high-level form so emit/parse round-trip cleanly.
-/

inductive ScriptElem where
  /-- A bare opcode byte. -/
  | op (code : Opcode) : ScriptElem
  /--
  A push instruction. The *script-coding* byte is determined by the
  emit pass according to the minimal-pushdata rules
  (`06-emit.ts:228-269`); we carry just the payload here so the
  byte-level encoding can be derived deterministically.
  -/
  | push (data : ByteArray) : ScriptElem
  deriving Inhabited

/-- A complete Bitcoin Script is a flat list of script elements. -/
abbrev Script := List ScriptElem

/-! ## Name lookup

`opcodeName?` returns the canonical textual name of an opcode byte for
disassembly. Mirrors `OPCODE_NAMES` in `06-emit.ts:130–137`, which
prefers the numeric name (`OP_0`, `OP_1`) over the boolean alias
(`OP_FALSE`, `OP_TRUE`).
-/

def opcodeName? (b : UInt8) : Option String :=
  match b.toNat with
  | 0x00 => some "OP_0"
  | 0x4c => some "OP_PUSHDATA1"
  | 0x4d => some "OP_PUSHDATA2"
  | 0x4e => some "OP_PUSHDATA4"
  | 0x4f => some "OP_1NEGATE"
  | 0x51 => some "OP_1"
  | 0x52 => some "OP_2"
  | 0x53 => some "OP_3"
  | 0x54 => some "OP_4"
  | 0x55 => some "OP_5"
  | 0x56 => some "OP_6"
  | 0x57 => some "OP_7"
  | 0x58 => some "OP_8"
  | 0x59 => some "OP_9"
  | 0x5a => some "OP_10"
  | 0x5b => some "OP_11"
  | 0x5c => some "OP_12"
  | 0x5d => some "OP_13"
  | 0x5e => some "OP_14"
  | 0x5f => some "OP_15"
  | 0x60 => some "OP_16"
  | 0x61 => some "OP_NOP"
  | 0x63 => some "OP_IF"
  | 0x64 => some "OP_NOTIF"
  | 0x67 => some "OP_ELSE"
  | 0x68 => some "OP_ENDIF"
  | 0x69 => some "OP_VERIFY"
  | 0x6a => some "OP_RETURN"
  | 0x6b => some "OP_TOALTSTACK"
  | 0x6c => some "OP_FROMALTSTACK"
  | 0x6d => some "OP_2DROP"
  | 0x6e => some "OP_2DUP"
  | 0x6f => some "OP_3DUP"
  | 0x70 => some "OP_2OVER"
  | 0x71 => some "OP_2ROT"
  | 0x72 => some "OP_2SWAP"
  | 0x73 => some "OP_IFDUP"
  | 0x74 => some "OP_DEPTH"
  | 0x75 => some "OP_DROP"
  | 0x76 => some "OP_DUP"
  | 0x77 => some "OP_NIP"
  | 0x78 => some "OP_OVER"
  | 0x79 => some "OP_PICK"
  | 0x7a => some "OP_ROLL"
  | 0x7b => some "OP_ROT"
  | 0x7c => some "OP_SWAP"
  | 0x7d => some "OP_TUCK"
  | 0x7e => some "OP_CAT"
  | 0x7f => some "OP_SPLIT"
  | 0x80 => some "OP_NUM2BIN"
  | 0x81 => some "OP_BIN2NUM"
  | 0x82 => some "OP_SIZE"
  | 0x83 => some "OP_INVERT"
  | 0x84 => some "OP_AND"
  | 0x85 => some "OP_OR"
  | 0x86 => some "OP_XOR"
  | 0x87 => some "OP_EQUAL"
  | 0x88 => some "OP_EQUALVERIFY"
  | 0x8b => some "OP_1ADD"
  | 0x8c => some "OP_1SUB"
  | 0x8d => some "OP_2MUL"
  | 0x8e => some "OP_2DIV"
  | 0x8f => some "OP_NEGATE"
  | 0x90 => some "OP_ABS"
  | 0x91 => some "OP_NOT"
  | 0x92 => some "OP_0NOTEQUAL"
  | 0x93 => some "OP_ADD"
  | 0x94 => some "OP_SUB"
  | 0x95 => some "OP_MUL"
  | 0x96 => some "OP_DIV"
  | 0x97 => some "OP_MOD"
  | 0x98 => some "OP_LSHIFT"
  | 0x99 => some "OP_RSHIFT"
  | 0x9a => some "OP_BOOLAND"
  | 0x9b => some "OP_BOOLOR"
  | 0x9c => some "OP_NUMEQUAL"
  | 0x9d => some "OP_NUMEQUALVERIFY"
  | 0x9e => some "OP_NUMNOTEQUAL"
  | 0x9f => some "OP_LESSTHAN"
  | 0xa0 => some "OP_GREATERTHAN"
  | 0xa1 => some "OP_LESSTHANOREQUAL"
  | 0xa2 => some "OP_GREATERTHANOREQUAL"
  | 0xa3 => some "OP_MIN"
  | 0xa4 => some "OP_MAX"
  | 0xa5 => some "OP_WITHIN"
  | 0xa6 => some "OP_RIPEMD160"
  | 0xa7 => some "OP_SHA1"
  | 0xa8 => some "OP_SHA256"
  | 0xa9 => some "OP_HASH160"
  | 0xaa => some "OP_HASH256"
  | 0xab => some "OP_CODESEPARATOR"
  | 0xac => some "OP_CHECKSIG"
  | 0xad => some "OP_CHECKSIGVERIFY"
  | 0xae => some "OP_CHECKMULTISIG"
  | 0xaf => some "OP_CHECKMULTISIGVERIFY"
  | 0xb3 => some "OP_SUBSTR"
  | 0xb4 => some "OP_LEFT"
  | 0xb5 => some "OP_RIGHT"
  | 0xb6 => some "OP_LSHIFTNUM"
  | 0xb7 => some "OP_RSHIFTNUM"
  | _    => none

/--
Inverse: textual name → byte. Returns `none` for unrecognised names.
Mirrors the `OPCODES` table in `06-emit.ts:20–123` exactly.
-/
def opcodeByName? (name : String) : Option UInt8 :=
  match name with
  | "OP_0" | "OP_FALSE"  => some 0x00
  | "OP_PUSHDATA1"       => some 0x4c
  | "OP_PUSHDATA2"       => some 0x4d
  | "OP_PUSHDATA4"       => some 0x4e
  | "OP_1NEGATE"         => some 0x4f
  | "OP_1" | "OP_TRUE"   => some 0x51
  | "OP_2" => some 0x52 | "OP_3" => some 0x53 | "OP_4" => some 0x54
  | "OP_5" => some 0x55 | "OP_6" => some 0x56 | "OP_7" => some 0x57
  | "OP_8" => some 0x58 | "OP_9" => some 0x59 | "OP_10" => some 0x5a
  | "OP_11" => some 0x5b | "OP_12" => some 0x5c | "OP_13" => some 0x5d
  | "OP_14" => some 0x5e | "OP_15" => some 0x5f | "OP_16" => some 0x60
  | "OP_NOP"             => some 0x61
  | "OP_IF"              => some 0x63
  | "OP_NOTIF"           => some 0x64
  | "OP_ELSE"            => some 0x67
  | "OP_ENDIF"           => some 0x68
  | "OP_VERIFY"          => some 0x69
  | "OP_RETURN"          => some 0x6a
  | "OP_TOALTSTACK"      => some 0x6b
  | "OP_FROMALTSTACK"    => some 0x6c
  | "OP_2DROP"           => some 0x6d
  | "OP_2DUP"            => some 0x6e
  | "OP_3DUP"            => some 0x6f
  | "OP_2OVER"           => some 0x70
  | "OP_2ROT"            => some 0x71
  | "OP_2SWAP"           => some 0x72
  | "OP_IFDUP"           => some 0x73
  | "OP_DEPTH"           => some 0x74
  | "OP_DROP"            => some 0x75
  | "OP_DUP"             => some 0x76
  | "OP_NIP"             => some 0x77
  | "OP_OVER"            => some 0x78
  | "OP_PICK"            => some 0x79
  | "OP_ROLL"            => some 0x7a
  | "OP_ROT"             => some 0x7b
  | "OP_SWAP"            => some 0x7c
  | "OP_TUCK"            => some 0x7d
  | "OP_CAT"             => some 0x7e
  | "OP_SPLIT"           => some 0x7f
  | "OP_NUM2BIN"         => some 0x80
  | "OP_BIN2NUM"         => some 0x81
  | "OP_SIZE"            => some 0x82
  | "OP_INVERT"          => some 0x83
  | "OP_AND"             => some 0x84
  | "OP_OR"              => some 0x85
  | "OP_XOR"             => some 0x86
  | "OP_EQUAL"           => some 0x87
  | "OP_EQUALVERIFY"     => some 0x88
  | "OP_1ADD"            => some 0x8b
  | "OP_1SUB"            => some 0x8c
  | "OP_2MUL"            => some 0x8d
  | "OP_2DIV"            => some 0x8e
  | "OP_NEGATE"          => some 0x8f
  | "OP_ABS"             => some 0x90
  | "OP_NOT"             => some 0x91
  | "OP_0NOTEQUAL"       => some 0x92
  | "OP_ADD"             => some 0x93
  | "OP_SUB"             => some 0x94
  | "OP_MUL"             => some 0x95
  | "OP_DIV"             => some 0x96
  | "OP_MOD"             => some 0x97
  | "OP_LSHIFT"          => some 0x98
  | "OP_RSHIFT"          => some 0x99
  | "OP_BOOLAND"         => some 0x9a
  | "OP_BOOLOR"          => some 0x9b
  | "OP_NUMEQUAL"        => some 0x9c
  | "OP_NUMEQUALVERIFY"  => some 0x9d
  | "OP_NUMNOTEQUAL"     => some 0x9e
  | "OP_LESSTHAN"        => some 0x9f
  | "OP_GREATERTHAN"     => some 0xa0
  | "OP_LESSTHANOREQUAL" => some 0xa1
  | "OP_GREATERTHANOREQUAL" => some 0xa2
  | "OP_MIN"             => some 0xa3
  | "OP_MAX"             => some 0xa4
  | "OP_WITHIN"          => some 0xa5
  | "OP_RIPEMD160"       => some 0xa6
  | "OP_SHA1"            => some 0xa7
  | "OP_SHA256"          => some 0xa8
  | "OP_HASH160"         => some 0xa9
  | "OP_HASH256"         => some 0xaa
  | "OP_CODESEPARATOR"   => some 0xab
  | "OP_CHECKSIG"        => some 0xac
  | "OP_CHECKSIGVERIFY"  => some 0xad
  | "OP_CHECKMULTISIG"   => some 0xae
  | "OP_CHECKMULTISIGVERIFY" => some 0xaf
  | "OP_SUBSTR"          => some 0xb3
  | "OP_LEFT"            => some 0xb4
  | "OP_RIGHT"           => some 0xb5
  | "OP_LSHIFTNUM"       => some 0xb6
  | "OP_RSHIFTNUM"       => some 0xb7
  | _                    => none

end RunarVerification.Script
