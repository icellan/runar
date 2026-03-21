package codegen

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// ---------------------------------------------------------------------------
// Opcode table — complete BSV opcode set
// ---------------------------------------------------------------------------

var opcodes = map[string]byte{
	"OP_0":                    0x00,
	"OP_FALSE":                0x00,
	"OP_PUSHDATA1":            0x4c,
	"OP_PUSHDATA2":            0x4d,
	"OP_PUSHDATA4":            0x4e,
	"OP_1NEGATE":              0x4f,
	"OP_1":                    0x51,
	"OP_TRUE":                 0x51,
	"OP_2":                    0x52,
	"OP_3":                    0x53,
	"OP_4":                    0x54,
	"OP_5":                    0x55,
	"OP_6":                    0x56,
	"OP_7":                    0x57,
	"OP_8":                    0x58,
	"OP_9":                    0x59,
	"OP_10":                   0x5a,
	"OP_11":                   0x5b,
	"OP_12":                   0x5c,
	"OP_13":                   0x5d,
	"OP_14":                   0x5e,
	"OP_15":                   0x5f,
	"OP_16":                   0x60,
	"OP_NOP":                  0x61,
	"OP_IF":                   0x63,
	"OP_NOTIF":                0x64,
	"OP_ELSE":                 0x67,
	"OP_ENDIF":                0x68,
	"OP_VERIFY":               0x69,
	"OP_RETURN":               0x6a,
	"OP_TOALTSTACK":           0x6b,
	"OP_FROMALTSTACK":         0x6c,
	"OP_2DROP":                0x6d,
	"OP_2DUP":                 0x6e,
	"OP_3DUP":                 0x6f,
	"OP_2OVER":                0x70,
	"OP_2ROT":                 0x71,
	"OP_2SWAP":                0x72,
	"OP_IFDUP":                0x73,
	"OP_DEPTH":                0x74,
	"OP_DROP":                 0x75,
	"OP_DUP":                  0x76,
	"OP_NIP":                  0x77,
	"OP_OVER":                 0x78,
	"OP_PICK":                 0x79,
	"OP_ROLL":                 0x7a,
	"OP_ROT":                  0x7b,
	"OP_SWAP":                 0x7c,
	"OP_TUCK":                 0x7d,
	"OP_CAT":                  0x7e,
	"OP_SPLIT":                0x7f,
	"OP_NUM2BIN":              0x80,
	"OP_BIN2NUM":              0x81,
	"OP_SIZE":                 0x82,
	"OP_INVERT":               0x83,
	"OP_AND":                  0x84,
	"OP_OR":                   0x85,
	"OP_XOR":                  0x86,
	"OP_EQUAL":                0x87,
	"OP_EQUALVERIFY":          0x88,
	"OP_1ADD":                 0x8b,
	"OP_1SUB":                 0x8c,
	"OP_NEGATE":               0x8f,
	"OP_ABS":                  0x90,
	"OP_NOT":                  0x91,
	"OP_0NOTEQUAL":            0x92,
	"OP_ADD":                  0x93,
	"OP_SUB":                  0x94,
	"OP_MUL":                  0x95,
	"OP_DIV":                  0x96,
	"OP_MOD":                  0x97,
	"OP_LSHIFT":               0x98,
	"OP_RSHIFT":               0x99,
	"OP_BOOLAND":              0x9a,
	"OP_BOOLOR":               0x9b,
	"OP_NUMEQUAL":             0x9c,
	"OP_NUMEQUALVERIFY":       0x9d,
	"OP_NUMNOTEQUAL":          0x9e,
	"OP_LESSTHAN":             0x9f,
	"OP_GREATERTHAN":          0xa0,
	"OP_LESSTHANOREQUAL":      0xa1,
	"OP_GREATERTHANOREQUAL":   0xa2,
	"OP_MIN":                  0xa3,
	"OP_MAX":                  0xa4,
	"OP_WITHIN":               0xa5,
	"OP_RIPEMD160":            0xa6,
	"OP_SHA1":                 0xa7,
	"OP_SHA256":               0xa8,
	"OP_HASH160":              0xa9,
	"OP_HASH256":              0xaa,
	"OP_CODESEPARATOR":        0xab,
	"OP_CHECKSIG":             0xac,
	"OP_CHECKSIGVERIFY":       0xad,
	"OP_CHECKMULTISIG":        0xae,
	"OP_CHECKMULTISIGVERIFY":  0xaf,
}

// ---------------------------------------------------------------------------
// ConstructorSlot
// ---------------------------------------------------------------------------

// ConstructorSlot records the byte offset of a constructor parameter placeholder
// in the emitted script. The SDK uses these offsets to splice in real values at
// deployment time.
type ConstructorSlot struct {
	ParamIndex int `json:"paramIndex"`
	ByteOffset int `json:"byteOffset"`
}

// ---------------------------------------------------------------------------
// EmitResult
// ---------------------------------------------------------------------------

// EmitResult holds the outputs of the emission pass.
type EmitResult struct {
	ScriptHex              string
	ScriptAsm              string
	ConstructorSlots       []ConstructorSlot
	CodeSeparatorIndex     int   // -1 if no OP_CODESEPARATOR was emitted
	CodeSeparatorIndices   []int // per-method byte offsets
}

// ---------------------------------------------------------------------------
// Emit context
// ---------------------------------------------------------------------------

type emitContext struct {
	hexParts               []string
	asmParts               []string
	byteLength             int
	constructorSlots       []ConstructorSlot
	codeSeparatorIndex     int
	codeSeparatorIndices   []int
}

func newEmitContext() *emitContext {
	return &emitContext{codeSeparatorIndex: -1}
}

func (ctx *emitContext) appendHex(h string) {
	ctx.hexParts = append(ctx.hexParts, h)
	ctx.byteLength += len(h) / 2
}

func (ctx *emitContext) appendAsm(a string) {
	ctx.asmParts = append(ctx.asmParts, a)
}

func (ctx *emitContext) emitOpcode(name string) error {
	b, ok := opcodes[name]
	if !ok {
		return fmt.Errorf("unknown opcode: %s", name)
	}
	if name == "OP_CODESEPARATOR" {
		ctx.codeSeparatorIndex = ctx.byteLength
		ctx.codeSeparatorIndices = append(ctx.codeSeparatorIndices, ctx.byteLength)
	}
	ctx.appendHex(fmt.Sprintf("%02x", b))
	ctx.appendAsm(name)
	return nil
}

func (ctx *emitContext) emitPush(value PushValue) {
	h, a := encodePushValue(value)
	ctx.appendHex(h)
	ctx.appendAsm(a)
}

func (ctx *emitContext) emitPlaceholder(paramIndex int) {
	byteOffset := ctx.byteLength
	ctx.appendHex("00") // OP_0 placeholder byte
	ctx.appendAsm("OP_0")
	ctx.constructorSlots = append(ctx.constructorSlots, ConstructorSlot{
		ParamIndex: paramIndex,
		ByteOffset: byteOffset,
	})
}

func (ctx *emitContext) getHex() string {
	return strings.Join(ctx.hexParts, "")
}

func (ctx *emitContext) getAsm() string {
	return strings.Join(ctx.asmParts, " ")
}

// ---------------------------------------------------------------------------
// Script number encoding
// ---------------------------------------------------------------------------

// encodeScriptNumber encodes an integer as a Bitcoin Script number
// (little-endian, sign-magnitude with sign bit in MSB).
func encodeScriptNumber(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{}
	}

	negative := n.Sign() < 0
	abs := new(big.Int).Abs(n)

	var bytes []byte
	for abs.Sign() > 0 {
		b := new(big.Int).And(abs, big.NewInt(0xff))
		bytes = append(bytes, byte(b.Int64()))
		abs.Rsh(abs, 8)
	}

	lastByte := bytes[len(bytes)-1]
	if lastByte&0x80 != 0 {
		if negative {
			bytes = append(bytes, 0x80)
		} else {
			bytes = append(bytes, 0x00)
		}
	} else if negative {
		bytes[len(bytes)-1] = lastByte | 0x80
	}

	return bytes
}

// ---------------------------------------------------------------------------
// Push data encoding
// ---------------------------------------------------------------------------

// encodePushData encodes raw bytes as a Bitcoin Script push-data operation.
func encodePushData(data []byte) []byte {
	length := len(data)

	if length == 0 {
		return []byte{0x00} // OP_0
	}

	// MINIMALDATA: single-byte values 1-16 must use OP_1..OP_16, 0x81 must use OP_1NEGATE.
	// Note: 0x00 is NOT converted to OP_0 because OP_0 pushes empty [] not [0x00].
	if length == 1 {
		b := data[0]
		if b >= 1 && b <= 16 {
			return []byte{0x50 + b} // OP_1 through OP_16
		}
		if b == 0x81 {
			return []byte{0x4f} // OP_1NEGATE
		}
	}

	if length >= 1 && length <= 75 {
		result := make([]byte, 1+length)
		result[0] = byte(length)
		copy(result[1:], data)
		return result
	}

	if length >= 76 && length <= 255 {
		result := make([]byte, 2+length)
		result[0] = 0x4c // OP_PUSHDATA1
		result[1] = byte(length)
		copy(result[2:], data)
		return result
	}

	if length >= 256 && length <= 65535 {
		result := make([]byte, 3+length)
		result[0] = 0x4d // OP_PUSHDATA2
		result[1] = byte(length & 0xff)
		result[2] = byte((length >> 8) & 0xff)
		copy(result[3:], data)
		return result
	}

	// OP_PUSHDATA4
	result := make([]byte, 5+length)
	result[0] = 0x4e
	result[1] = byte(length & 0xff)
	result[2] = byte((length >> 8) & 0xff)
	result[3] = byte((length >> 16) & 0xff)
	result[4] = byte((length >> 24) & 0xff)
	copy(result[5:], data)
	return result
}

// encodePushValue converts a PushValue to hex and asm strings.
func encodePushValue(value PushValue) (hexStr string, asmStr string) {
	switch value.Kind {
	case "bool":
		if value.Bool {
			return "51", "OP_TRUE"
		}
		return "00", "OP_FALSE"

	case "bigint":
		return encodePushBigInt(value.BigInt)

	case "bytes":
		encoded := encodePushData(value.Bytes)
		h := hex.EncodeToString(encoded)
		if len(value.Bytes) == 0 {
			return h, "OP_0"
		}
		return h, fmt.Sprintf("<%s>", hex.EncodeToString(value.Bytes))

	default:
		return "00", "OP_0"
	}
}

// EncodePushBigInt encodes a big.Int as a push operation, using small-integer
// opcodes (OP_0..OP_16, OP_1NEGATE) where possible.
// Exported for testing.
func EncodePushBigInt(n *big.Int) (hexStr string, asmStr string) {
	return encodePushBigInt(n)
}

func encodePushBigInt(n *big.Int) (hexStr string, asmStr string) {
	if n.Sign() == 0 {
		return "00", "OP_0"
	}

	if n.Cmp(big.NewInt(-1)) == 0 {
		return "4f", "OP_1NEGATE"
	}

	if n.Sign() > 0 && n.Cmp(big.NewInt(16)) <= 0 {
		opcode := 0x50 + int(n.Int64())
		return fmt.Sprintf("%02x", opcode), fmt.Sprintf("OP_%d", n.Int64())
	}

	numBytes := encodeScriptNumber(n)
	encoded := encodePushData(numBytes)
	return hex.EncodeToString(encoded), fmt.Sprintf("<%s>", hex.EncodeToString(numBytes))
}

// ---------------------------------------------------------------------------
// Emit a single StackOp
// ---------------------------------------------------------------------------

func emitStackOp(op *StackOp, ctx *emitContext) error {
	switch op.Op {
	case "push":
		ctx.emitPush(op.Value)
	case "dup":
		return ctx.emitOpcode("OP_DUP")
	case "swap":
		return ctx.emitOpcode("OP_SWAP")
	case "roll":
		return ctx.emitOpcode("OP_ROLL")
	case "pick":
		return ctx.emitOpcode("OP_PICK")
	case "drop":
		return ctx.emitOpcode("OP_DROP")
	case "nip":
		return ctx.emitOpcode("OP_NIP")
	case "over":
		return ctx.emitOpcode("OP_OVER")
	case "rot":
		return ctx.emitOpcode("OP_ROT")
	case "tuck":
		return ctx.emitOpcode("OP_TUCK")
	case "opcode":
		return ctx.emitOpcode(op.Code)
	case "if":
		return emitIf(op.Then, op.Else, ctx)
	case "placeholder":
		ctx.emitPlaceholder(op.ParamIndex)
	case "push_codesep_index":
		// Push the codeSeparatorIndex as a numeric constant.
		// This value is known at emit time (set when OP_CODESEPARATOR was emitted).
		idx := ctx.codeSeparatorIndex
		if idx < 0 {
			idx = 0
		}
		ctx.emitPush(PushValue{Kind: "bigint", BigInt: big.NewInt(int64(idx))})
	default:
		return fmt.Errorf("unknown stack op: %s", op.Op)
	}
	return nil
}

// emitIf emits an OP_IF / OP_ELSE / OP_ENDIF structure.
func emitIf(thenOps []StackOp, elseOps []StackOp, ctx *emitContext) error {
	if err := ctx.emitOpcode("OP_IF"); err != nil {
		return err
	}

	for i := range thenOps {
		if err := emitStackOp(&thenOps[i], ctx); err != nil {
			return err
		}
	}

	if len(elseOps) > 0 {
		if err := ctx.emitOpcode("OP_ELSE"); err != nil {
			return err
		}
		for i := range elseOps {
			if err := emitStackOp(&elseOps[i], ctx); err != nil {
				return err
			}
		}
	}

	return ctx.emitOpcode("OP_ENDIF")
}

// ---------------------------------------------------------------------------
// Peephole optimization
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Emit converts a slice of StackMethods into Bitcoin Script hex and ASM.
// For contracts with multiple public methods, it generates a method dispatch
// preamble using OP_IF/OP_ELSE chains.
// Note: peephole optimization (VERIFY combinations, SWAP elimination) is
// handled by OptimizeStackOps in optimizer.go, which runs before Emit.
func Emit(methods []StackMethod) (*EmitResult, error) {
	ctx := newEmitContext()

	// Filter to public methods (exclude constructor)
	var publicMethods []StackMethod
	for _, m := range methods {
		if m.Name != "constructor" {
			publicMethods = append(publicMethods, m)
		}
	}

	if len(publicMethods) == 0 {
		return &EmitResult{ScriptHex: "", ScriptAsm: "", ConstructorSlots: nil, CodeSeparatorIndex: -1}, nil
	}

	if len(publicMethods) == 1 {
		// Single public method — no dispatch needed
		for i := range publicMethods[0].Ops {
			if err := emitStackOp(&publicMethods[0].Ops[i], ctx); err != nil {
				return nil, err
			}
		}
	} else {
		// Multiple public methods — emit dispatch table
		if err := emitMethodDispatch(publicMethods, ctx); err != nil {
			return nil, err
		}
	}

	return &EmitResult{
		ScriptHex:            ctx.getHex(),
		ScriptAsm:            ctx.getAsm(),
		ConstructorSlots:     ctx.constructorSlots,
		CodeSeparatorIndex:   ctx.codeSeparatorIndex,
		CodeSeparatorIndices: ctx.codeSeparatorIndices,
	}, nil
}

// emitMethodDispatch emits a method selector preamble for multi-method contracts.
func emitMethodDispatch(methods []StackMethod, ctx *emitContext) error {
	for i, method := range methods {
		isLast := i == len(methods)-1

		if !isLast {
			if err := ctx.emitOpcode("OP_DUP"); err != nil {
				return err
			}
			ctx.emitPush(bigIntPush(int64(i)))
			if err := ctx.emitOpcode("OP_NUMEQUAL"); err != nil {
				return err
			}
			if err := ctx.emitOpcode("OP_IF"); err != nil {
				return err
			}
			if err := ctx.emitOpcode("OP_DROP"); err != nil {
				return err
			}
		} else {
			// Last method — verify the index matches (fail-closed for invalid selectors)
			ctx.emitPush(bigIntPush(int64(i)))
			if err := ctx.emitOpcode("OP_NUMEQUALVERIFY"); err != nil {
				return err
			}
		}

		for j := range method.Ops {
			if err := emitStackOp(&method.Ops[j], ctx); err != nil {
				return err
			}
		}

		if !isLast {
			if err := ctx.emitOpcode("OP_ELSE"); err != nil {
				return err
			}
		}
	}

	// Close all nested OP_IF/OP_ELSE blocks
	for i := 0; i < len(methods)-1; i++ {
		if err := ctx.emitOpcode("OP_ENDIF"); err != nil {
			return err
		}
	}

	return nil
}

// EmitMethod emits a single method's ops. Useful for testing.
func EmitMethod(method *StackMethod) (*EmitResult, error) {
	ctx := newEmitContext()
	for i := range method.Ops {
		if err := emitStackOp(&method.Ops[i], ctx); err != nil {
			return nil, err
		}
	}
	return &EmitResult{
		ScriptHex:            ctx.getHex(),
		ScriptAsm:            ctx.getAsm(),
		ConstructorSlots:     ctx.constructorSlots,
		CodeSeparatorIndex:   ctx.codeSeparatorIndex,
		CodeSeparatorIndices: ctx.codeSeparatorIndices,
	}, nil
}
