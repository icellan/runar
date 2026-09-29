package frontend

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// F-026 — integer literals mean what their host language says they mean.
//
// A port of the TS reference (packages/runar-compiler/src/passes/int-literal.ts,
// user decision R15). Every hand-written tokenizer scans a number token over
// every [0-9A-Za-z_] character glued to its first digit, then validates the
// whole token against the surface's host-language grammar. The table every
// tier must reproduce is conformance/negatives/int-literal-cases.json.
//
// A lowercase `0x` on .runar.sol / .runar.move / .runar.rs is a Rúnar
// ByteString literal and is handled by those tokenizers before a number is
// scanned; on every other surface `0x` is a hexadecimal integer.

// intLiteral is a validated literal. NegOnly marks a literal that is valid only
// as the operand of a unary minus (Java `2147483648`, Rust `128i8`); Value is
// then the positive magnitude.
type intLiteral struct {
	Value   *big.Int
	NegOnly bool
}

var surfaceLanguage = map[string]string{
	"ts": "TypeScript", "sol": "Solidity", "move": "Move", "go": "Go", "rs": "Rust",
	"py": "Python", "zig": "Zig", "rb": "Ruby", "java": "Java",
}

// invalidIntegerLiteralMsg is the TS reference's invalidIntegerLiteral().
func invalidIntegerLiteralMsg(surface, text string) string {
	return fmt.Sprintf("invalid %s integer literal '%s'", surfaceLanguage[surface], text)
}

// isNumberContinue reports whether ch continues a number token.
func isNumberContinue(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

// scanNumberEnd returns the end (exclusive) of the number token whose first
// digit is at pos.
func scanNumberEnd(src string, pos int) int {
	i := pos + 1
	for i < len(src) && isNumberContinue(src[i]) {
		i++
	}
	return i
}

func digitsValue(digits string, radix int) *big.Int {
	v, ok := new(big.Int).SetString(strings.ReplaceAll(digits, "_", ""), radix)
	if !ok {
		return nil
	}
	return v
}

func litOk(v *big.Int) *intLiteral { return &intLiteral{Value: v} }

func radixOf(prefix byte) int {
	switch prefix {
	case 'x', 'X':
		return 16
	case 'o', 'O':
		return 8
	case 'b', 'B':
		return 2
	}
	return 10
}

// prefixed matches `0<p>digits` with the digits in group 1.
func prefixed(text string, re *regexp.Regexp) *intLiteral {
	m := re.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	return litOk(digitsValue(m[1], radixOf(text[1])))
}

func firstLit(ls ...func() *intLiteral) *intLiteral {
	for _, f := range ls {
		if l := f(); l != nil {
			return l
		}
	}
	return nil
}

func pow2(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }

var (
	reTsDec  = regexp.MustCompile(`^(?:0|[1-9](?:_?[0-9])*)$`)
	reTsHex  = regexp.MustCompile(`^0[xX]([0-9a-fA-F](?:_?[0-9a-fA-F])*)$`)
	reTsOct  = regexp.MustCompile(`^0[oO]([0-7](?:_?[0-7])*)$`)
	reTsBin  = regexp.MustCompile(`^0[bB]([01](?:_?[01])*)$`)
	reMove   = regexp.MustCompile(`^([0-9][0-9_]*)(u8|u16|u32|u64|u128|u256)?$`)
	reGoOct  = regexp.MustCompile(`^0((?:_?[0-7])+)$`)
	reGoHex  = regexp.MustCompile(`^0[xX]((?:_?[0-9a-fA-F])+)$`)
	reGoOctP = regexp.MustCompile(`^0[oO]((?:_?[0-7])+)$`)
	reGoBin  = regexp.MustCompile(`^0[bB]((?:_?[01])+)$`)
	reRust   = regexp.MustCompile(`^(?:0x([0-9a-fA-F_]*)|0o([0-7_]*)|0b([01_]*)|([0-9][0-9_]*))(i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)?$`)
	rePyDec  = regexp.MustCompile(`^(?:[1-9](?:_?[0-9])*|0(?:_?0)*)$`)
	reZigHex = regexp.MustCompile(`^0x([0-9a-fA-F](?:_?[0-9a-fA-F])*)$`)
	reZigOct = regexp.MustCompile(`^0o([0-7](?:_?[0-7])*)$`)
	reZigBin = regexp.MustCompile(`^0b([01](?:_?[01])*)$`)
	reRbOct  = regexp.MustCompile(`^0(_?[0-7](?:_?[0-7])*)$`)
	reRbDec  = regexp.MustCompile(`^0[dD]([0-9](?:_?[0-9])*)$`)
	reJDec   = regexp.MustCompile(`^(?:0|[1-9](?:[0-9_]*[0-9])?)$`)
	reJOct   = regexp.MustCompile(`^0([0-7_]*[0-7])$`)
	reJHex   = regexp.MustCompile(`^0[xX]([0-9a-fA-F](?:[0-9a-fA-F_]*[0-9a-fA-F])?)$`)
	reJBin   = regexp.MustCompile(`^0[bB]([01](?:[01_]*[01])?)$`)
	reHexDig = regexp.MustCompile(`[0-9a-fA-F]`)
)

var moveBits = map[string]uint{"u8": 8, "u16": 16, "u32": 32, "u64": 64, "u128": 128, "u256": 256}

type rustSuffix struct {
	bits   uint
	signed bool
}

var rustBits = map[string]rustSuffix{
	"i8": {8, true}, "i16": {16, true}, "i32": {32, true}, "i64": {64, true}, "i128": {128, true}, "isize": {64, true},
	"u8": {8, false}, "u16": {16, false}, "u32": {32, false}, "u64": {64, false}, "u128": {128, false}, "usize": {64, false},
}

func parseIntLiteralTs(text string) *intLiteral {
	body := strings.TrimSuffix(text, "n")
	if reTsDec.MatchString(body) {
		return litOk(digitsValue(body, 10))
	}
	return firstLit(
		func() *intLiteral { return prefixed(body, reTsHex) },
		func() *intLiteral { return prefixed(body, reTsOct) },
		func() *intLiteral { return prefixed(body, reTsBin) },
	)
}

func parseIntLiteralMove(text string) *intLiteral {
	m := reMove.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	v := digitsValue(m[1], 10)
	bits := moveBits["u256"]
	if m[2] != "" {
		bits = moveBits[m[2]]
	}
	if v.Cmp(pow2(bits)) < 0 {
		return litOk(v)
	}
	return nil
}

func parseIntLiteralGo(text string) *intLiteral {
	if reTsDec.MatchString(text) {
		return litOk(digitsValue(text, 10))
	}
	if m := reGoOct.FindStringSubmatch(text); m != nil {
		return litOk(digitsValue(m[1], 8))
	}
	return firstLit(
		func() *intLiteral { return prefixed(text, reGoHex) },
		func() *intLiteral { return prefixed(text, reGoOctP) },
		func() *intLiteral { return prefixed(text, reGoBin) },
	)
}

func parseIntLiteralRust(text string) *intLiteral {
	m := reRust.FindStringSubmatchIndex(text)
	if m == nil {
		return nil
	}
	group := func(i int) (string, bool) {
		if m[2*i] < 0 {
			return "", false
		}
		return text[m[2*i]:m[2*i+1]], true
	}
	var digits string
	radix := 10
	if d, ok := group(1); ok {
		digits, radix = d, 16
	} else if d, ok := group(2); ok {
		digits, radix = d, 8
	} else if d, ok := group(3); ok {
		digits, radix = d, 2
	} else {
		digits, _ = group(4)
	}
	if !reHexDig.MatchString(digits) {
		return nil
	}
	v := digitsValue(digits, radix)
	suffix, has := group(5)
	if !has {
		// Unbounded: rustc stops at u128::MAX, Rúnar's bigint corpus does not.
		return litOk(v)
	}
	s := rustBits[suffix]
	if !s.signed {
		if v.Cmp(pow2(s.bits)) < 0 {
			return litOk(v)
		}
		return nil
	}
	min := pow2(s.bits - 1)
	switch v.Cmp(min) {
	case -1:
		return litOk(v)
	case 0:
		return &intLiteral{Value: v, NegOnly: true}
	}
	return nil
}

func parseIntLiteralPy(text string) *intLiteral {
	if rePyDec.MatchString(text) {
		return litOk(digitsValue(text, 10))
	}
	return firstLit(
		func() *intLiteral { return prefixed(text, reGoHex) },
		func() *intLiteral { return prefixed(text, reGoOctP) },
		func() *intLiteral { return prefixed(text, reGoBin) },
	)
}

func parseIntLiteralZig(text string) *intLiteral {
	if reTsDec.MatchString(text) {
		return litOk(digitsValue(text, 10))
	}
	return firstLit(
		func() *intLiteral { return prefixed(text, reZigHex) },
		func() *intLiteral { return prefixed(text, reZigOct) },
		func() *intLiteral { return prefixed(text, reZigBin) },
	)
}

func parseIntLiteralRb(text string) *intLiteral {
	if reTsDec.MatchString(text) {
		return litOk(digitsValue(text, 10))
	}
	if m := reRbOct.FindStringSubmatch(text); m != nil {
		return litOk(digitsValue(m[1], 8))
	}
	return firstLit(
		func() *intLiteral { return prefixed(text, reRbDec) },
		func() *intLiteral { return prefixed(text, reTsHex) },
		func() *intLiteral { return prefixed(text, reTsOct) },
		func() *intLiteral { return prefixed(text, reTsBin) },
	)
}

func parseIntLiteralJava(text string) *intLiteral {
	isLong := strings.HasSuffix(text, "L") || strings.HasSuffix(text, "l")
	body := text
	var bits uint = 32
	if isLong {
		body = text[:len(text)-1]
		bits = 64
	}
	if reJDec.MatchString(body) {
		v := digitsValue(body, 10)
		min := pow2(bits - 1)
		switch v.Cmp(min) {
		case -1:
			return litOk(v)
		case 0:
			return &intLiteral{Value: v, NegOnly: true}
		}
		return nil
	}
	var v *big.Int
	if m := reJOct.FindStringSubmatch(body); m != nil {
		v = digitsValue(m[1], 8)
	}
	if m := reJHex.FindStringSubmatch(body); m != nil {
		v = digitsValue(m[1], 16)
	}
	if m := reJBin.FindStringSubmatch(body); m != nil {
		v = digitsValue(m[1], 2)
	}
	if v == nil || v.Cmp(pow2(bits)) >= 0 {
		return nil
	}
	if v.Cmp(pow2(bits-1)) >= 0 {
		v = new(big.Int).Sub(v, pow2(bits))
	}
	return litOk(v)
}

// parseIntLiteral returns the value of the integer literal text (the whole
// number token) on surface, or nil when the host language rejects it.
func parseIntLiteral(surface, text string) *intLiteral {
	switch surface {
	case "ts":
		return parseIntLiteralTs(text)
	case "sol":
		if reTsDec.MatchString(text) {
			return litOk(digitsValue(text, 10))
		}
		return nil
	case "move":
		return parseIntLiteralMove(text)
	case "go":
		return parseIntLiteralGo(text)
	case "rs":
		return parseIntLiteralRust(text)
	case "py":
		return parseIntLiteralPy(text)
	case "zig":
		return parseIntLiteralZig(text)
	case "rb":
		return parseIntLiteralRb(text)
	case "java":
		return parseIntLiteralJava(text)
	}
	return nil
}

// scanNumberEndRunes is scanNumberEnd over a rune slice.
func scanNumberEndRunes(chars []rune, pos int) int {
	i := pos + 1
	for i < len(chars) && chars[i] < 0x80 && isNumberContinue(byte(chars[i])) {
		i++
	}
	return i
}
