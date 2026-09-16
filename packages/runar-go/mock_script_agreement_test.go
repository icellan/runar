package runar

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	gocompiler "github.com/icellan/runar/compilers/go/compiler"
)

// ---------------------------------------------------------------------------
// N-090 — the off-chain mock and the emitted script must agree.
//
// packages/runar-go ships a Go mock for (nearly) every codegen builtin. A
// contract written in the `.runar.go` DSL is BOTH native Go (run by `go test`
// against these mocks) AND Rúnar source (compiled to Script). Nothing in the
// repo forced the two to produce the same value: the mock is hand-maintained
// here, the emitter is hand-maintained in compilers/go/codegen, and a compile
// test — the only test BasefoldVerifier had — cannot see a value mismatch at
// all.
//
// That is how CL-BUG-099 / R-056 survived: `MerkleRootPoseidon2KBv` returned
// root[0] while the script kept root[7]. Two different limbs of the same
// digest, for as long as nobody executed the script.
//
// This file is the missing oracle. For each builtin it compiles
//
//	assert(<builtin>(args...) === expected)
//
// with the Go MOCK's output as `expected`, and runs the result through the
// go-sdk Script interpreter. Accepted => mock and emitter agree on the value.
// Every case also runs a TAMPERED expected and requires rejection, so a
// builtin whose script happens to accept anything cannot fake agreement.
//
// The oracle is the executed script. Comparing the mock against itself, or
// against a second Go reimplementation, would prove nothing.
// ---------------------------------------------------------------------------

// scriptNum encodes n in Bitcoin Script number form (little-endian,
// sign-magnitude).
func scriptNum(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{}
	}
	neg := n.Sign() < 0
	be := new(big.Int).Abs(n).Bytes()
	le := make([]byte, len(be))
	for i := range be {
		le[i] = be[len(be)-1-i]
	}
	if le[len(le)-1]&0x80 != 0 {
		le = append(le, 0)
	}
	if neg {
		le[len(le)-1] |= 0x80
	}
	return le
}

func numI(v int64) []byte     { return scriptNum(big.NewInt(v)) }
func numB(v *big.Int) []byte  { return scriptNum(v) }
func bs(v ByteString) []byte  { return []byte(v) }
func boolean(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{}
}

// agreementCase is one builtin under differential test.
type agreementCase struct {
	// builtin is the Rúnar name, as imported from 'runar-lang' and called.
	builtin string
	// mock names the packages/runar-go function under test (report only).
	mock string
	// argTys are the Rúnar types of the call arguments, in order.
	argTys []string
	// args are those arguments, encoded as Script stack items.
	args [][]byte
	// retTy is the Rúnar return type; `expected` is declared with it.
	retTy string
	// want is the MOCK's result, encoded as a Script stack item.
	want []byte
	// tamper is a value distinct from want, for the non-vacuity control.
	tamper []byte
	// callExtra are literal arguments appended AFTER the parameters, for
	// builtins whose trailing argument must be a compile-time constant
	// (merkleRoot* depth, for instance).
	callExtra []string
	// knownDivergent, when non-empty, records that the mock is ALREADY known
	// to disagree with the emitter and why. Such a case inverts: the test
	// requires the disagreement to still be there, so the mismatch stays
	// recorded rather than silently tolerated, and the entry has to be deleted
	// (not quietly kept) the day the mock is fixed.
	//
	// NO CASE CARRIES ONE TODAY. The three that did -- bin2num, ecPointX and
	// ecPointY, all of them "int64 return truncates" -- were fixed and their
	// entries deleted, which is what the inversion above is for. The field
	// stays because the next divergence found before it is fixed belongs here
	// rather than in a comment.
	knownDivergent string
	// slow marks cases whose script takes seconds to build or run.
	slow bool
}

func (c agreementCase) source() string {
	params := make([]string, 0, len(c.argTys)+1)
	callArgs := make([]string, 0, len(c.argTys))
	for i, ty := range c.argTys {
		params = append(params, fmt.Sprintf("p%d: %s", i, ty))
		callArgs = append(callArgs, fmt.Sprintf("p%d", i))
	}
	callArgs = append(callArgs, c.callExtra...)
	params = append(params, "expected: "+c.retTy)
	return fmt.Sprintf(`
import { SmartContract, assert, %s } from 'runar-lang';

class Diff extends SmartContract {
  constructor() {
    super();
  }
  public verify(%s) {
    assert(%s(%s) === expected);
  }
}
`, c.builtin, strings.Join(params, ", "), c.builtin, strings.Join(callArgs, ", "))
}

// runAgreement compiles the case and spends it with `expected`. It returns the
// interpreter's verdict; nil means the script accepted.
func runAgreement(t *testing.T, lock *script.Script, c agreementCase, expected []byte) error {
	t.Helper()
	unlock := &script.Script{}
	for _, a := range c.args {
		if err := unlock.AppendPushData(a); err != nil {
			t.Fatalf("append arg: %v", err)
		}
	}
	if err := unlock.AppendPushData(expected); err != nil {
		t.Fatalf("append expected: %v", err)
	}
	return interpreter.NewEngine().Execute(
		interpreter.WithScripts(lock, unlock),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
}

func compileAgreement(t *testing.T, c agreementCase) *script.Script {
	t.Helper()
	res := gocompiler.CompileFromSourceStrWithResult(c.source(), "Diff.runar.ts")
	if res.Artifact == nil || res.Artifact.Script == "" {
		var msgs []string
		for _, d := range res.Diagnostics {
			msgs = append(msgs, d.FormatMessage())
		}
		t.Fatalf("compile %s: %s", c.builtin, strings.Join(msgs, "; "))
	}
	lock, err := script.NewFromHex(res.Artifact.Script)
	if err != nil {
		t.Fatalf("%s: parse locking script: %v", c.builtin, err)
	}
	return lock
}

// checkAgreement is the whole protocol for one builtin.
func checkAgreement(t *testing.T, c agreementCase) {
	t.Helper()
	lock := compileAgreement(t, c)
	t.Logf("%s: %d script bytes; mock %s returned %s",
		c.builtin, len(*lock), c.mock, hex.EncodeToString(c.want))

	// Control FIRST: a value the mock did NOT produce must be rejected.
	// Without this, a builtin whose script leaves a truthy constant would
	// "agree" with anything and the test would be vacuous.
	if err := runAgreement(t, lock, c, c.tamper); err == nil {
		t.Fatalf("%s: VACUOUS — the script ACCEPTED a value the mock did not "+
			"produce (%s). No conclusion about mock/emitter agreement is possible.",
			c.builtin, hex.EncodeToString(c.tamper))
	}

	err := runAgreement(t, lock, c, c.want)

	if c.knownDivergent != "" {
		if err == nil {
			t.Fatalf("%s: runar.%s now AGREES with the emitter, but this case is "+
				"still on the known-divergent list (%s). Delete the knownDivergent "+
				"entry — a stale allowlist is how the next divergence hides.",
				c.builtin, c.mock, c.knownDivergent)
		}
		t.Logf("%s: KNOWN DIVERGENCE still present (%s): %v", c.builtin, c.knownDivergent, err)
		return
	}

	if err != nil {
		t.Errorf("%s: MOCK/EMITTER DISAGREE — the compiled script REJECTED the "+
			"value runar.%s returned for the same inputs: %v",
			c.builtin, c.mock, err)
	}
}

// ---------------------------------------------------------------------------
// The case table: one row per mock that corresponds to a codegen builtin.
// ---------------------------------------------------------------------------

func mathCases() []agreementCase {
	i := func(builtin, mock string, want int64, args ...int64) agreementCase {
		c := agreementCase{builtin: builtin, mock: mock, retTy: "bigint",
			want: numI(want), tamper: numI(want + 1)}
		for _, a := range args {
			c.argTys = append(c.argTys, "bigint")
			c.args = append(c.args, numI(a))
		}
		return c
	}
	b := func(builtin, mock string, want bool, args ...int64) agreementCase {
		c := agreementCase{builtin: builtin, mock: mock, retTy: "boolean",
			want: boolean(want), tamper: boolean(!want)}
		for _, a := range args {
			c.argTys = append(c.argTys, "bigint")
			c.args = append(c.args, numI(a))
		}
		return c
	}
	return []agreementCase{
		i("abs", "Abs", Abs(-7), -7),
		i("min", "Min", Min(7, 3), 7, 3),
		i("max", "Max", Max(7, 3), 7, 3),
		i("safediv", "Safediv", Safediv(17, 5), 17, 5),
		i("safemod", "Safemod", Safemod(17, 5), 17, 5),
		i("clamp", "Clamp", Clamp(15, 1, 10), 15, 1, 10),
		i("sign", "Sign", Sign(-9), -9),
		i("pow", "Pow", Pow(3, 5), 3, 5),
		i("mulDiv", "MulDiv", MulDiv(7, 11, 3), 7, 11, 3),
		i("percentOf", "PercentOf", PercentOf(1000, 250), 1000, 250),
		i("sqrt", "Sqrt", Sqrt(1000), 1000),
		i("gcd", "Gcd", Gcd(462, 1071), 462, 1071),
		i("divmod", "Divmod", Divmod(17, 5), 17, 5),
		i("log2", "Log2", Log2(1000), 1000),
		b("within", "Within", Within(5, 1, 10), 5, 1, 10),
		b("bool", "ToBool", ToBool(5), 5),
	}
}

func byteStringCases() []agreementCase {
	src := ByteString("\xde\xad\xbe\xef\xca\xfe\xba\xbe")
	// A value that does not fit in an int64, so the *Big rows below actually
	// exercise the width their existence is justified by.
	wideVal, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	tamperBS := func(v ByteString) []byte {
		b := append([]byte(nil), []byte(v)...)
		if len(b) == 0 {
			return []byte{0x01}
		}
		b[0] ^= 0xff
		return b
	}
	return []agreementCase{
		{builtin: "len", mock: "Len", argTys: []string{"ByteString"},
			args: [][]byte{bs(src)}, retTy: "bigint",
			want: numI(Len(src)), tamper: numI(Len(src) + 1)},
		{builtin: "cat", mock: "Cat", argTys: []string{"ByteString", "ByteString"},
			args: [][]byte{bs("\xde\xad"), bs("\xbe\xef")}, retTy: "ByteString",
			want: bs(Cat("\xde\xad", "\xbe\xef")), tamper: tamperBS(Cat("\xde\xad", "\xbe\xef"))},
		{builtin: "substr", mock: "Substr", argTys: []string{"ByteString", "bigint", "bigint"},
			args: [][]byte{bs(src), numI(1), numI(3)}, retTy: "ByteString",
			want: bs(Substr(src, 1, 3)), tamper: tamperBS(Substr(src, 1, 3))},
		{builtin: "num2bin", mock: "Num2Bin", argTys: []string{"bigint", "bigint"},
			args: [][]byte{numI(1000), numI(8)}, retTy: "ByteString",
			want: bs(Num2Bin(1000, 8)), tamper: tamperBS(Num2Bin(1000, 8))},
		{builtin: "bin2num", mock: "Bin2Num", argTys: []string{"ByteString"},
			args: [][]byte{bs("\xe8\x03")}, retTy: "bigint",
			want: numI(Bin2Num("\xe8\x03")), tamper: numI(Bin2Num("\xe8\x03") + 1)},
		// Num2BinBig / Bin2NumBig map to the SAME builtins as Num2Bin /
		// Bin2Num (see parser_gocontract.go mapGoBuiltin), so they are
		// separate mocks of the same emitter and get their own row — with a
		// value beyond int64, which is the reason they exist.
		{builtin: "num2bin", mock: "Num2BinBig", argTys: []string{"bigint", "bigint"},
			args: [][]byte{numB(wideVal), numI(16)}, retTy: "ByteString",
			want: bs(Num2BinBig(wideVal, 16)), tamper: tamperBS(Num2BinBig(wideVal, 16))},
		{builtin: "bin2num", mock: "Bin2NumBig", argTys: []string{"ByteString"},
			args: [][]byte{bs(Num2BinBig(wideVal, 16))}, retTy: "bigint",
			want: numB(Bin2NumBig(Num2BinBig(wideVal, 16))),
			tamper: numB(new(big.Int).Add(Bin2NumBig(Num2BinBig(wideVal, 16)), big.NewInt(1)))},
		// The same builtin through the int64 mock, on a push WIDER than int64
		// carrying a value that still fits it. This row used to carry a
		// `knownDivergent` entry because it decoded wideVal: Bin2Num
		// documented "graceful truncation ... return the low 64 bits", so it
		// returned -4362896299872285998 while OP_BIN2NUM left all 16 bytes.
		// Bin2Num panics on that input now, so the divergence is gone and the
		// entry with it; bin2num_width_test.go holds the refusal.
		//
		// What is left to check here is that the refusal keyed on the VALUE
		// and not on the push width. Script numbers need not be minimally
		// encoded, a 16-byte push of 1000 is 1000, and the emitted opcodes
		// accept it — so a guard that panicked on anything past 8 bytes would
		// satisfy the refusal test and fail this row.
		{builtin: "bin2num", mock: "Bin2Num (16-byte push, in-range value)",
			argTys: []string{"ByteString"},
			args:   [][]byte{bs(Num2BinBig(big.NewInt(1000), 16))}, retTy: "bigint",
			want:   numI(Bin2Num(Num2BinBig(big.NewInt(1000), 16))),
			tamper: numI(Bin2Num(Num2BinBig(big.NewInt(1000), 16)) + 1)},
		{builtin: "reverseBytes", mock: "ReverseBytes", argTys: []string{"ByteString"},
			args: [][]byte{bs(src)}, retTy: "ByteString",
			want: bs(ReverseBytes(src)), tamper: tamperBS(ReverseBytes(src))},

		// split / left / right / int2str / ripemd160 were absent from this
		// table until packages/runar-go declared them: the .runar.go surface
		// parser resolved all five, the SDK declared none, and a mock that
		// does not exist cannot disagree with an emitter. They are the reason
		// 32 of the 84 ports in examples/go carried `//go:build ignore`.
		//
		// split and left are the two halves of ONE cut and right measures its
		// offset from the far end, so all three take the same index against
		// the same string on purpose: an SDK that confused any pair of them
		// produces a different `want` here and the spend refuses it.
		{builtin: "split", mock: "Split", argTys: []string{"ByteString", "bigint"},
			args: [][]byte{bs(src), numI(2)}, retTy: "ByteString",
			want: bs(Split(src, 2)), tamper: tamperBS(Split(src, 2))},
		{builtin: "left", mock: "Left", argTys: []string{"ByteString", "bigint"},
			args: [][]byte{bs(src), numI(2)}, retTy: "ByteString",
			want: bs(Left(src, 2)), tamper: tamperBS(Left(src, 2))},
		{builtin: "right", mock: "Right", argTys: []string{"ByteString", "bigint"},
			args: [][]byte{bs(src), numI(2)}, retTy: "ByteString",
			want: bs(Right(src, 2)), tamper: tamperBS(Right(src, 2))},
		// Int2Str and Int2str are separate mocks of the SAME builtin -- both
		// spellings resolve to `int2str` in the Go surface -- so each gets its
		// own row, the way Num2Bin / Num2BinBig do above.
		{builtin: "int2str", mock: "Int2Str", argTys: []string{"bigint", "bigint"},
			args: [][]byte{numI(-1000), numI(8)}, retTy: "ByteString",
			want: bs(Int2Str(-1000, 8)), tamper: tamperBS(Int2Str(-1000, 8))},
		{builtin: "int2str", mock: "Int2str", argTys: []string{"bigint", "bigint"},
			args: [][]byte{numI(-1000), numI(8)}, retTy: "ByteString",
			want: bs(Int2str(-1000, 8)), tamper: tamperBS(Int2str(-1000, 8))},
		{builtin: "ripemd160", mock: "Ripemd160", argTys: []string{"ByteString"},
			args: [][]byte{bs(src)}, retTy: "ByteString",
			want: bs(ByteString(Ripemd160(src))), tamper: tamperBS(ByteString(Ripemd160(src)))},
	}
}

func hashCases() []agreementCase {
	msg := ByteString("runar mock/emitter agreement")
	state := Sha256(ByteString("initial state"))
	block := ByteString(strings.Repeat("\x5a", 64))
	cv := Sha256(ByteString("chaining value"))
	tamperBS := func(v ByteString) []byte {
		b := append([]byte(nil), []byte(v)...)
		b[0] ^= 0xff
		return b
	}
	h := func(builtin, mock, retTy string, argTys []string, args [][]byte, want ByteString) agreementCase {
		return agreementCase{builtin: builtin, mock: mock, argTys: argTys, args: args,
			retTy: retTy, want: bs(want), tamper: tamperBS(want)}
	}
	return []agreementCase{
		h("sha256", "Sha256", "Sha256", []string{"ByteString"}, [][]byte{bs(msg)}, Sha256(msg)),
		h("hash256", "Hash256", "Sha256", []string{"ByteString"}, [][]byte{bs(msg)}, Hash256(msg)),
		h("hash160", "Hash160", "Ripemd160", []string{"ByteString"}, [][]byte{bs(msg)}, Hash160(msg)),
		h("ripemd160", "Ripemd160Func", "Ripemd160", []string{"ByteString"}, [][]byte{bs(msg)}, Ripemd160Func(msg)),
		h("blake3Hash", "Blake3Hash", "ByteString", []string{"ByteString"}, [][]byte{bs(msg)}, Blake3Hash(msg)),
		h("blake3Compress", "Blake3Compress", "ByteString", []string{"ByteString", "ByteString"},
			[][]byte{bs(cv), bs(block)}, Blake3Compress(cv, block)),
		h("sha256Compress", "Sha256Compress", "ByteString", []string{"ByteString", "ByteString"},
			[][]byte{bs(state), bs(block)}, Sha256Compress(state, block)),
		h("sha256Finalize", "Sha256Finalize", "ByteString", []string{"ByteString", "ByteString", "bigint"},
			[][]byte{bs(state), bs("\x01\x02\x03\x04"), numI(1024 + 32)},
			Sha256Finalize(state, "\x01\x02\x03\x04", 1024+32)),
	}
}

func fieldCases() []agreementCase {
	// BabyBear p = 2^31 - 2^27 + 1, KoalaBear p = 2^31 - 2^24 + 1.
	a, b := int64(1234567), int64(7654321)
	e := []int64{11, 22, 33, 44}
	f := []int64{55, 66, 77, 88}
	i2 := func(builtin, mock string, want int64, args ...int64) agreementCase {
		c := agreementCase{builtin: builtin, mock: mock, retTy: "bigint",
			want: numI(want), tamper: numI(want + 1)}
		for _, v := range args {
			c.argTys = append(c.argTys, "bigint")
			c.args = append(c.args, numI(v))
		}
		return c
	}
	ext8 := append(append([]int64{}, e...), f...)
	return []agreementCase{
		i2("bbFieldAdd", "BbFieldAdd", BbFieldAdd(a, b), a, b),
		i2("bbFieldSub", "BbFieldSub", BbFieldSub(a, b), a, b),
		i2("bbFieldMul", "BbFieldMul", BbFieldMul(a, b), a, b),
		i2("bbFieldInv", "BbFieldInv", BbFieldInv(a), a),
		i2("bbExt4Mul0", "BbExt4Mul0", BbExt4Mul0(e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3]), ext8...),
		i2("bbExt4Mul1", "BbExt4Mul1", BbExt4Mul1(e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3]), ext8...),
		i2("bbExt4Mul2", "BbExt4Mul2", BbExt4Mul2(e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3]), ext8...),
		i2("bbExt4Mul3", "BbExt4Mul3", BbExt4Mul3(e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3]), ext8...),
		i2("bbExt4Inv0", "BbExt4Inv0", BbExt4Inv0(e[0], e[1], e[2], e[3]), e...),
		i2("bbExt4Inv1", "BbExt4Inv1", BbExt4Inv1(e[0], e[1], e[2], e[3]), e...),
		i2("bbExt4Inv2", "BbExt4Inv2", BbExt4Inv2(e[0], e[1], e[2], e[3]), e...),
		i2("bbExt4Inv3", "BbExt4Inv3", BbExt4Inv3(e[0], e[1], e[2], e[3]), e...),
		i2("kbFieldAdd", "KbFieldAdd", KbFieldAdd(a, b), a, b),
		i2("kbFieldSub", "KbFieldSub", KbFieldSub(a, b), a, b),
		i2("kbFieldMul", "KbFieldMul", KbFieldMul(a, b), a, b),
		i2("kbFieldInv", "KbFieldInv", KbFieldInv(a), a),
		i2("kbExt4Mul0", "KbExt4Mul0", KbExt4Mul0(e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3]), ext8...),
		i2("kbExt4Mul1", "KbExt4Mul1", KbExt4Mul1(e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3]), ext8...),
		i2("kbExt4Mul2", "KbExt4Mul2", KbExt4Mul2(e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3]), ext8...),
		i2("kbExt4Mul3", "KbExt4Mul3", KbExt4Mul3(e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3]), ext8...),
		i2("kbExt4Inv0", "KbExt4Inv0", KbExt4Inv0(e[0], e[1], e[2], e[3]), e...),
		i2("kbExt4Inv1", "KbExt4Inv1", KbExt4Inv1(e[0], e[1], e[2], e[3]), e...),
		i2("kbExt4Inv2", "KbExt4Inv2", KbExt4Inv2(e[0], e[1], e[2], e[3]), e...),
		i2("kbExt4Inv3", "KbExt4Inv3", KbExt4Inv3(e[0], e[1], e[2], e[3]), e...),
	}
}

func bn254Cases() []agreementCase {
	x := big.NewInt(123456789)
	y := big.NewInt(987654321)
	fb := func(builtin, mock string, want *big.Int, args ...*big.Int) agreementCase {
		c := agreementCase{builtin: builtin, mock: mock, retTy: "bigint",
			want: numB(want), tamper: numB(new(big.Int).Add(want, big.NewInt(1)))}
		for _, v := range args {
			c.argTys = append(c.argTys, "bigint")
			c.args = append(c.args, numB(v))
		}
		return c
	}
	g := Point(bn254EncodePoint(big.NewInt(1), big.NewInt(2)))
	g2 := Bn254G1AddP(g, g)
	tamperPt := func(p Point) []byte {
		b := append([]byte(nil), []byte(p)...)
		b[0] ^= 0xff
		return b
	}
	return []agreementCase{
		fb("bn254FieldAdd", "Bn254FieldAdd", Bn254FieldAdd(x, y), x, y),
		fb("bn254FieldSub", "Bn254FieldSub", Bn254FieldSub(x, y), x, y),
		fb("bn254FieldMul", "Bn254FieldMul", Bn254FieldMul(x, y), x, y),
		fb("bn254FieldInv", "Bn254FieldInv", Bn254FieldInv(x), x),
		fb("bn254FieldNeg", "Bn254FieldNeg", Bn254FieldNeg(x), x),
		{builtin: "bn254G1Add", mock: "Bn254G1AddP", argTys: []string{"Point", "Point"},
			args: [][]byte{bs(ByteString(g)), bs(ByteString(g2))}, retTy: "Point",
			want: bs(ByteString(Bn254G1AddP(g, g2))), tamper: tamperPt(Bn254G1AddP(g, g2))},
		{builtin: "bn254G1Negate", mock: "Bn254G1NegateP", argTys: []string{"Point"},
			args: [][]byte{bs(ByteString(g))}, retTy: "Point",
			want: bs(ByteString(Bn254G1NegateP(g))), tamper: tamperPt(Bn254G1NegateP(g))},
		{builtin: "bn254G1OnCurve", mock: "Bn254G1OnCurveP", argTys: []string{"Point"},
			args: [][]byte{bs(ByteString(g))}, retTy: "boolean",
			want: boolean(Bn254G1OnCurveP(g)), tamper: boolean(!Bn254G1OnCurveP(g))},
		{builtin: "bn254G1ScalarMul", mock: "Bn254G1ScalarMulP", argTys: []string{"Point", "bigint"},
			args: [][]byte{bs(ByteString(g)), numI(5)}, retTy: "Point", slow: true,
			want: bs(ByteString(Bn254G1ScalarMulP(g, 5))), tamper: tamperPt(Bn254G1ScalarMulP(g, 5))},
	}
}

func ecCases() []agreementCase {
	p := EcMulGen(5)
	q := EcMulGen(9)
	tamperPt := func(v Point) []byte {
		b := append([]byte(nil), []byte(v)...)
		b[0] ^= 0xff
		return b
	}
	return []agreementCase{
		{builtin: "ecAdd", mock: "EcAdd", argTys: []string{"Point", "Point"},
			args: [][]byte{bs(ByteString(p)), bs(ByteString(q))}, retTy: "Point",
			want: bs(ByteString(EcAdd(p, q))), tamper: tamperPt(EcAdd(p, q))},
		{builtin: "ecNegate", mock: "EcNegate", argTys: []string{"Point"},
			args: [][]byte{bs(ByteString(p))}, retTy: "Point",
			want: bs(ByteString(EcNegate(p))), tamper: tamperPt(EcNegate(p))},
		{builtin: "ecOnCurve", mock: "EcOnCurve", argTys: []string{"Point"},
			args: [][]byte{bs(ByteString(p))}, retTy: "boolean",
			want: boolean(EcOnCurve(p)), tamper: boolean(!EcOnCurve(p))},
		{builtin: "ecEncodeCompressed", mock: "EcEncodeCompressed", argTys: []string{"Point"},
			args: [][]byte{bs(ByteString(p))}, retTy: "ByteString",
			want: bs(EcEncodeCompressed(p)), tamper: tamperPt(Point(EcEncodeCompressed(p)))},
		// EcPointX / EcPointY returned `Bigint` (= int64) and reached it via
		// big.Int.Int64(), which truncates modulo 2^64. A secp256k1
		// coordinate is 256 bits, so the mock returned the low 8 bytes --
		// EcPointX(5G) as a negative int64 -- while the emitter
		// (codegen/ec.go EmitEcPointX) leaves the whole 32-byte coordinate.
		// Both accessors return BigintBig now and these two rows are the
		// proof: `p` is a real curve point, so `want` is a 256-bit number and
		// the spend only accepts if the mock produced exactly the value the
		// script left on the stack. The `knownDivergent` entries they used to
		// carry are gone.
		{builtin: "ecPointX", mock: "EcPointX", argTys: []string{"Point"},
			args: [][]byte{bs(ByteString(p))}, retTy: "bigint",
			want: numB(EcPointX(p)), tamper: numB(new(big.Int).Add(EcPointX(p), big.NewInt(1)))},
		{builtin: "ecPointY", mock: "EcPointY", argTys: []string{"Point"},
			args: [][]byte{bs(ByteString(p))}, retTy: "bigint",
			want: numB(EcPointY(p)), tamper: numB(new(big.Int).Add(EcPointY(p), big.NewInt(1)))},
		{builtin: "ecModReduce", mock: "EcModReduce", argTys: []string{"bigint", "bigint"},
			args: [][]byte{numI(1000003), numI(97)}, retTy: "bigint",
			want: numI(EcModReduce(1000003, 97)), tamper: numI(EcModReduce(1000003, 97) + 1)},
		{builtin: "ecMakePoint", mock: "EcMakePoint", argTys: []string{"bigint", "bigint"},
			args: [][]byte{numI(11), numI(22)}, retTy: "Point",
			want: bs(ByteString(EcMakePoint(big.NewInt(11), big.NewInt(22)))),
			tamper: tamperPt(EcMakePoint(big.NewInt(11), big.NewInt(22)))},
		// The same builtin at the width it actually gets used at. The row
		// above it passes 11 and 22, which is how a constructor that can only
		// take int64 coordinates looked correct: no curve point has an
		// 8-byte coordinate, so nothing the row covered was a point. This one
		// rebuilds a real point from its own accessors, which is the identity
		// examples/go/ec-unit asserts and could not run.
		{builtin: "ecMakePoint", mock: "EcMakePoint (wide)", argTys: []string{"bigint", "bigint"},
			args: [][]byte{numB(EcPointX(p)), numB(EcPointY(p))}, retTy: "Point",
			want: bs(ByteString(p)), tamper: tamperPt(p)},
		{builtin: "ecMulGen", mock: "EcMulGen", argTys: []string{"bigint"},
			args: [][]byte{numI(5)}, retTy: "Point", slow: true,
			want: bs(ByteString(EcMulGen(5))), tamper: tamperPt(EcMulGen(5))},
		{builtin: "ecMul", mock: "EcMul", argTys: []string{"Point", "bigint"},
			args: [][]byte{bs(ByteString(p)), numI(3)}, retTy: "Point", slow: true,
			want: bs(ByteString(EcMul(p, 3))), tamper: tamperPt(EcMul(p, 3))},
	}
}

func nistCases() []agreementCase {
	p2 := P256MulGen(big.NewInt(5))
	q2 := P256MulGen(big.NewInt(9))
	p3 := P384MulGen(big.NewInt(5))
	q3 := P384MulGen(big.NewInt(9))
	tamperBS := func(v ByteString) []byte {
		b := append([]byte(nil), []byte(v)...)
		b[0] ^= 0xff
		return b
	}
	return []agreementCase{
		{builtin: "p256Add", mock: "P256Add", argTys: []string{"P256Point", "P256Point"},
			args: [][]byte{bs(p2), bs(q2)}, retTy: "P256Point",
			want: bs(P256Add(p2, q2)), tamper: tamperBS(P256Add(p2, q2))},
		{builtin: "p256Negate", mock: "P256Negate", argTys: []string{"P256Point"},
			args: [][]byte{bs(p2)}, retTy: "P256Point",
			want: bs(P256Negate(p2)), tamper: tamperBS(P256Negate(p2))},
		{builtin: "p256OnCurve", mock: "P256OnCurve", argTys: []string{"P256Point"},
			args: [][]byte{bs(p2)}, retTy: "boolean",
			want: boolean(P256OnCurve(p2)), tamper: boolean(!P256OnCurve(p2))},
		{builtin: "p256EncodeCompressed", mock: "P256EncodeCompressed", argTys: []string{"P256Point"},
			args: [][]byte{bs(p2)}, retTy: "ByteString",
			want: bs(P256EncodeCompressed(p2)), tamper: tamperBS(P256EncodeCompressed(p2))},
		{builtin: "p256MulGen", mock: "P256MulGen", argTys: []string{"bigint"},
			args: [][]byte{numI(5)}, retTy: "P256Point", slow: true,
			want: bs(P256MulGen(big.NewInt(5))), tamper: tamperBS(P256MulGen(big.NewInt(5)))},
		{builtin: "p256Mul", mock: "P256Mul", argTys: []string{"P256Point", "bigint"},
			args: [][]byte{bs(p2), numI(3)}, retTy: "P256Point", slow: true,
			want: bs(P256Mul(p2, big.NewInt(3))), tamper: tamperBS(P256Mul(p2, big.NewInt(3)))},
		{builtin: "p384Add", mock: "P384Add", argTys: []string{"P384Point", "P384Point"},
			args: [][]byte{bs(p3), bs(q3)}, retTy: "P384Point",
			want: bs(P384Add(p3, q3)), tamper: tamperBS(P384Add(p3, q3))},
		{builtin: "p384Negate", mock: "P384Negate", argTys: []string{"P384Point"},
			args: [][]byte{bs(p3)}, retTy: "P384Point",
			want: bs(P384Negate(p3)), tamper: tamperBS(P384Negate(p3))},
		{builtin: "p384OnCurve", mock: "P384OnCurve", argTys: []string{"P384Point"},
			args: [][]byte{bs(p3)}, retTy: "boolean",
			want: boolean(P384OnCurve(p3)), tamper: boolean(!P384OnCurve(p3))},
		{builtin: "p384EncodeCompressed", mock: "P384EncodeCompressed", argTys: []string{"P384Point"},
			args: [][]byte{bs(p3)}, retTy: "ByteString",
			want: bs(P384EncodeCompressed(p3)), tamper: tamperBS(P384EncodeCompressed(p3))},
		{builtin: "p384MulGen", mock: "P384MulGen", argTys: []string{"bigint"},
			args: [][]byte{numI(5)}, retTy: "P384Point", slow: true,
			want: bs(P384MulGen(big.NewInt(5))), tamper: tamperBS(P384MulGen(big.NewInt(5)))},
		{builtin: "p384Mul", mock: "P384Mul", argTys: []string{"P384Point", "bigint"},
			args: [][]byte{bs(p3), numI(3)}, retTy: "P384Point", slow: true,
			want: bs(P384Mul(p3, big.NewInt(3))), tamper: tamperBS(P384Mul(p3, big.NewInt(3)))},
	}
}

func merkleByteStringCases() []agreementCase {
	leaf := Sha256(ByteString("leaf"))
	sib0 := Sha256(ByteString("sib0"))
	sib1 := Sha256(ByteString("sib1"))
	proof := Cat(sib0, sib1)
	tamperBS := func(v ByteString) []byte {
		b := append([]byte(nil), []byte(v)...)
		b[0] ^= 0xff
		return b
	}
	return []agreementCase{
		{builtin: "merkleRootSha256", mock: "MerkleRootSha256",
			argTys: []string{"ByteString", "ByteString", "bigint"},
			args:   [][]byte{bs(leaf), bs(proof), numI(2)}, callExtra: []string{"2n"}, retTy: "ByteString",
			want:   bs(MerkleRootSha256(leaf, proof, 2, 2)), tamper: tamperBS(MerkleRootSha256(leaf, proof, 2, 2))},
		{builtin: "merkleRootHash256", mock: "MerkleRootHash256",
			argTys: []string{"ByteString", "ByteString", "bigint"},
			args:   [][]byte{bs(leaf), bs(proof), numI(2)}, callExtra: []string{"2n"}, retTy: "ByteString",
			want:   bs(MerkleRootHash256(leaf, proof, 2, 2)), tamper: tamperBS(MerkleRootHash256(leaf, proof, 2, 2))},
	}
}

func allAgreementCases() []agreementCase {
	var out []agreementCase
	out = append(out, mathCases()...)
	out = append(out, byteStringCases()...)
	out = append(out, hashCases()...)
	out = append(out, fieldCases()...)
	out = append(out, bn254Cases()...)
	out = append(out, ecCases()...)
	out = append(out, nistCases()...)
	out = append(out, merkleByteStringCases()...)
	// N-090's own builtin, in the sweep as well as its dedicated test below.
	out = append(out, poseidon2KBDiffCase(1,
		[8]int64{2, 4, 6, 8, 10, 12, 14, 16},
		[]int64{31, 32, 33, 34, 35, 36, 37, 38}, 1))
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].builtin != out[j].builtin {
			return out[i].builtin < out[j].builtin
		}
		return out[i].mock < out[j].mock
	})
	return out
}

// TestMockAgreesWithEmitter is the cross-cutting sweep: every packages/runar-go
// mock whose builtin can be exercised by a one-line contract is compared
// against the value its own emitter leaves on the stack.
func TestMockAgreesWithEmitter(t *testing.T) {
	cases := allAgreementCases()
	if len(cases) == 0 {
		t.Fatal("empty case table — the sweep would pass vacuously")
	}
	t.Logf("%d builtins under differential test", len(cases))
	for _, c := range cases {
		c := c
		// Sub-test name is builtin_Mock: one row of the mock/emitter table.
		t.Run(c.builtin+"_"+c.mock, func(t *testing.T) {
			if c.slow && testing.Short() {
				t.Skip("slow script; run without -short")
			}
			checkAgreement(t, c)
		})
	}
}

// ---------------------------------------------------------------------------
// N-090 — merkleRootPoseidon2KB
// ---------------------------------------------------------------------------

// poseidon2KBDiffCase builds the differential case for merkleRootPoseidon2KB
// at the given depth. The builtin is variadic (8 leaf + 8*depth siblings +
// index + depth) and `depth` must be a compile-time literal, so the arguments
// are generated rather than written out.
//
// `want` is whatever runar.MerkleRootPoseidon2KBv returns for these inputs,
// encoded as a Script stack item — deliberately NOT the packing this test
// knows the emitter uses. The test must read the mock, not restate it;
// otherwise it grades the emitter against a second copy of the emitter and
// the mock stays free to drift.
func poseidon2KBDiffCase(depth int, leaf [8]int64, proof []int64, index int64) agreementCase {
	c := agreementCase{
		builtin: "merkleRootPoseidon2KB",
		mock:    "MerkleRootPoseidon2KBv",
		retTy:   "bigint",
	}
	for _, v := range leaf {
		c.argTys = append(c.argTys, "bigint")
		c.args = append(c.args, numI(v))
	}
	for _, v := range proof {
		c.argTys = append(c.argTys, "bigint")
		c.args = append(c.args, numI(v))
	}
	c.argTys = append(c.argTys, "bigint")
	c.args = append(c.args, numI(index))
	c.callExtra = []string{fmt.Sprintf("%dn", depth)}

	var args []int64
	args = append(args, leaf[:]...)
	args = append(args, proof...)
	args = append(args, index, int64(depth))
	got := mockPackedRoot(args...)

	c.want = numB(got)
	c.tamper = numB(new(big.Int).Add(got, big.NewInt(1)))
	return c
}

// TestMerkleRootPoseidon2KBv_AgreesWithEmittedScript is the N-090 regression.
//
// BasefoldVerifier.runar.go — the only contract that calls this builtin — had
// a COMPILE test and nothing else. A compile test cannot see a value
// mismatch, so the mock returning root[0] while the script kept root[7] (and,
// after R-056, the base-2^32 packing of all eight limbs) went unnoticed
// indefinitely. This test executes the compiled script.
func TestMerkleRootPoseidon2KBv_AgreesWithEmittedScript(t *testing.T) {
	cases := []struct {
		name  string
		depth int
		leaf  [8]int64
		proof []int64
		index int64
	}{
		{"depth1_index0", 1,
			[8]int64{1, 2, 3, 4, 5, 6, 7, 8},
			[]int64{11, 12, 13, 14, 15, 16, 17, 18}, 0},
		// index 1 exercises the emitter's conditional-swap arm.
		{"depth1_index1", 1,
			[8]int64{1, 2, 3, 4, 5, 6, 7, 8},
			[]int64{11, 12, 13, 14, 15, 16, 17, 18}, 1},
		// depth 2: the fold into a single bigint must run once, after the
		// last level, not once per level.
		{"depth2_index2", 2,
			[8]int64{1, 2, 3, 4, 5, 6, 7, 8},
			[]int64{11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28}, 2},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			checkAgreement(t, poseidon2KBDiffCase(tc.depth, tc.leaf, tc.proof, tc.index))
		})
	}
}

// TestMerkleRootPoseidon2KBv_CannotBeHeldInInt64 documents why the mock's
// return type had to widen rather than stay Bigint.
//
// The emitter folds the eight KoalaBear limbs into Σ root_i · (2^32)^i. Any
// root with a nonzero top limb exceeds 2^224, so `runar.Bigint` (= int64) can
// represent the correct answer for essentially no input at all. A narrow
// return type here is not a rounding concession — it is a guarantee of
// disagreement.
func TestMerkleRootPoseidon2KBv_CannotBeHeldInInt64(t *testing.T) {
	leaf := [8]int64{1, 2, 3, 4, 5, 6, 7, 8}
	proof := []int64{11, 12, 13, 14, 15, 16, 17, 18}
	var args []int64
	args = append(args, leaf[:]...)
	args = append(args, proof...)
	args = append(args, 0, 1)

	got := mockPackedRoot(args...)
	if got.IsInt64() {
		t.Fatalf("the packed root %s fits in an int64 — pick inputs whose top "+
			"limb is nonzero, or this test proves nothing", got.String())
	}
	t.Logf("packed root is %d bits; int64 holds 63", got.BitLen())
}

// mockPackedRoot is the single point where this test reads
// runar.MerkleRootPoseidon2KBv. It exists so the RED run (mock returning
// int64) and the GREEN run (mock returning *big.Int) differ in exactly one
// line, and so the rest of the test never restates what the emitter does.
func mockPackedRoot(args ...int64) *big.Int {
	return MerkleRootPoseidon2KBv(args...)
}
