package frontend

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParsePython parses a Python-syntax Rúnar contract (.runar.py) and produces
// the standard AST.
func ParsePython(source []byte, fileName string) *ParseResult {
	p := &pyParser{
		fileName: fileName,
	}

	tokens := p.tokenize(string(source))
	p.tokens = tokens
	p.pos = 0

	contract, err := p.parseContract()
	if err != nil {
		return &ParseResult{Errors: []Diagnostic{{Message: err.Error(), Severity: SeverityError}}}
	}
	if len(p.errors) > 0 {
		return &ParseResult{Contract: contract, Errors: p.errors}
	}
	return &ParseResult{Contract: contract}
}

// ---------------------------------------------------------------------------
// Token types
// ---------------------------------------------------------------------------

type pyTokenKind int

const (
	pyTokEOF pyTokenKind = iota
	pyTokIdent
	pyTokNumber
	pyTokString
	pyTokLBrace    // { (not used in Python syntax, but kept for consistency)
	pyTokRBrace    // }
	pyTokLParen    // (
	pyTokRParen    // )
	pyTokLBracket  // [
	pyTokRBracket  // ]
	pyTokSemicolon // ; (rare in Python)
	pyTokComma     // ,
	pyTokDot       // .
	pyTokColon     // :
	pyTokAssign    // =
	pyTokEqEq      // ==
	pyTokNotEq     // !=
	pyTokLt        // <
	pyTokLtEq      // <=
	pyTokGt        // >
	pyTokGtEq      // >=
	pyTokPlus      // +
	pyTokMinus     // -
	pyTokStar      // *
	pyTokSlash     // /
	pyTokPercent   // %
	pyTokBang      // !
	pyTokTilde     // ~
	pyTokAmp       // &
	pyTokPipe      // |
	pyTokCaret     // ^
	pyTokAmpAmp    // && (synthetic — produced from 'and')
	pyTokPipePipe  // || (synthetic — produced from 'or')
	pyTokPlusEq    // +=
	pyTokMinusEq   // -=
	pyTokStarEq    // *=
	pyTokSlashEq   // /= (maps to integer div assign, since // is int-div)
	pyTokPercentEq // %=
	pyTokAt        // @
	pyTokSlashSlash // // (integer division)
	pyTokStarStar   // **
	pyTokArrow      // ->
	pyTokLShift     // <<
	pyTokRShift     // >>
	pyTokIndent     // synthetic INDENT
	pyTokDedent     // synthetic DEDENT
	pyTokNewline    // synthetic NEWLINE (logical line end)
)

type pyToken struct {
	kind  pyTokenKind
	value string
	line  int
	col   int
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

type pyParser struct {
	fileName string
	tokens   []pyToken
	pos      int
	errors   []Diagnostic
}

func (p *pyParser) addError(msg string) {
	p.errors = append(p.errors, Diagnostic{Message: msg, Severity: SeverityError})
}

func (p *pyParser) tokenize(source string) []pyToken {
	// Phase 1: produce raw tokens with line/col info, tracking newlines
	// Phase 2: insert INDENT/DEDENT tokens based on indentation

	raw := p.tokenizeRaw(source)
	return p.insertIndentation(raw)
}

// tokenizeRaw produces tokens including NEWLINE tokens but without INDENT/DEDENT.
func (p *pyParser) tokenizeRaw(source string) []pyToken {
	var tokens []pyToken
	line := 1
	col := 0
	i := 0
	parenDepth := 0 // tracks nesting inside (), [], {}

	for i < len(source) {
		ch := source[i]

		// Newlines — emit NEWLINE token only if not inside parens
		if ch == '\n' || ch == '\r' {
			if ch == '\r' {
				i++
				if i < len(source) && source[i] == '\n' {
					i++
				}
			} else {
				i++
			}
			if parenDepth == 0 {
				tokens = append(tokens, pyToken{kind: pyTokNewline, value: "\n", line: line, col: col})
			}
			line++
			col = 0
			continue
		}

		// Whitespace (non-newline) — skip
		if ch == ' ' || ch == '\t' {
			i++
			col++
			continue
		}

		// Single-line comment: # ...
		if ch == '#' {
			for i < len(source) && source[i] != '\n' && source[i] != '\r' {
				i++
			}
			continue
		}

		startCol := col

		// Byte string literals: b'...' or b"..."
		if ch == 'b' && i+1 < len(source) && (source[i+1] == '\'' || source[i+1] == '"') {
			quote := source[i+1]
			i += 2
			col += 2
			start := i
			for i < len(source) && source[i] != quote {
				if source[i] == '\\' {
					i++
					col++
				}
				i++
				col++
			}
			val := source[start:i]
			if i < len(source) {
				i++ // skip closing quote
				col++
			}
			// Convert Python byte string escapes to hex
			hexVal := pyByteStringToHex(val)
			tokens = append(tokens, pyToken{kind: pyTokString, value: hexVal, line: line, col: startCol})
			continue
		}

		// String literals (single or double quoted, including triple-quoted)
		if ch == '"' || ch == '\'' {
			quote := ch
			// Check for triple-quote
			if i+2 < len(source) && source[i+1] == quote && source[i+2] == quote {
				// Triple-quoted string — always a docstring in Rúnar.
				// Skip it without emitting a token.
				i += 3
				col += 3
				for i+2 < len(source) {
					if source[i] == quote && source[i+1] == quote && source[i+2] == quote {
						break
					}
					if source[i] == '\n' {
						line++
						col = 0
					} else {
						col++
					}
					i++
				}
				if i+2 < len(source) {
					i += 3
					col += 3
				}
				continue
			}
			i++
			col++
			start := i
			for i < len(source) && source[i] != quote {
				if source[i] == '\\' {
					i++
					col++
				}
				i++
				col++
			}
			val := source[start:i]
			if i < len(source) {
				i++ // skip closing quote
				col++
			}
			tokens = append(tokens, pyToken{kind: pyTokString, value: val, line: line, col: startCol})
			continue
		}

		// Numbers
		if ch >= '0' && ch <= '9' {
			start := i
			if ch == '0' && i+1 < len(source) && (source[i+1] == 'x' || source[i+1] == 'X') {
				i += 2
				col += 2
				for i < len(source) && isHexDigit(source[i]) {
					i++
					col++
				}
			} else {
				for i < len(source) && (source[i] >= '0' && source[i] <= '9' || source[i] == '_') {
					i++
					col++
				}
			}
			numStr := strings.ReplaceAll(source[start:i], "_", "")
			tokens = append(tokens, pyToken{kind: pyTokNumber, value: numStr, line: line, col: startCol})
			continue
		}

		// Identifiers and keywords
		if pyIsIdentStart(ch) {
			start := i
			for i < len(source) && pyIsIdentPart(source[i]) {
				i++
				col++
			}
			word := source[start:i]

			// Map Python boolean keywords
			switch word {
			case "and":
				tokens = append(tokens, pyToken{kind: pyTokAmpAmp, value: "and", line: line, col: startCol})
			case "or":
				tokens = append(tokens, pyToken{kind: pyTokPipePipe, value: "or", line: line, col: startCol})
			case "not":
				tokens = append(tokens, pyToken{kind: pyTokBang, value: "not", line: line, col: startCol})
			default:
				tokens = append(tokens, pyToken{kind: pyTokIdent, value: word, line: line, col: startCol})
			}
			continue
		}

		// Three-character operators
		if i+2 < len(source) {
			three := source[i : i+3]
			switch three {
			case "<<=", ">>=":
				// Compound shift-assign — we don't support these, skip
			case "//=":
				tokens = append(tokens, pyToken{kind: pyTokSlashEq, value: "//=", line: line, col: startCol})
				i += 3
				col += 3
				continue
			case "**=":
				// Power-assign — not supported in Rúnar
			}
		}

		// Two-character operators
		if i+1 < len(source) {
			two := source[i : i+2]
			var twoKind pyTokenKind
			found := true
			switch two {
			case "==":
				twoKind = pyTokEqEq
			case "!=":
				twoKind = pyTokNotEq
			case "<=":
				twoKind = pyTokLtEq
			case ">=":
				twoKind = pyTokGtEq
			case "+=":
				twoKind = pyTokPlusEq
			case "-=":
				twoKind = pyTokMinusEq
			case "*=":
				twoKind = pyTokStarEq
			case "%=":
				twoKind = pyTokPercentEq
			case "//":
				twoKind = pyTokSlashSlash
			case "**":
				twoKind = pyTokStarStar
			case "->":
				twoKind = pyTokArrow
			case "<<":
				twoKind = pyTokLShift
			case ">>":
				twoKind = pyTokRShift
			default:
				found = false
			}
			if found {
				tokens = append(tokens, pyToken{kind: twoKind, value: two, line: line, col: startCol})
				i += 2
				col += 2
				continue
			}
		}

		// Single-character operators and punctuation
		var oneKind pyTokenKind
		oneFound := true
		switch ch {
		case '(':
			oneKind = pyTokLParen
			parenDepth++
		case ')':
			oneKind = pyTokRParen
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			oneKind = pyTokLBracket
			parenDepth++
		case ']':
			oneKind = pyTokRBracket
			if parenDepth > 0 {
				parenDepth--
			}
		case '{':
			oneKind = pyTokLBrace
			parenDepth++
		case '}':
			oneKind = pyTokRBrace
			if parenDepth > 0 {
				parenDepth--
			}
		case ',':
			oneKind = pyTokComma
		case '.':
			oneKind = pyTokDot
		case ':':
			oneKind = pyTokColon
		case ';':
			oneKind = pyTokSemicolon
		case '=':
			oneKind = pyTokAssign
		case '<':
			oneKind = pyTokLt
		case '>':
			oneKind = pyTokGt
		case '+':
			oneKind = pyTokPlus
		case '-':
			oneKind = pyTokMinus
		case '*':
			oneKind = pyTokStar
		case '/':
			oneKind = pyTokSlash
		case '%':
			oneKind = pyTokPercent
		case '!':
			oneKind = pyTokBang
		case '~':
			oneKind = pyTokTilde
		case '&':
			oneKind = pyTokAmp
		case '|':
			oneKind = pyTokPipe
		case '^':
			oneKind = pyTokCaret
		case '@':
			oneKind = pyTokAt
		default:
			oneFound = false
		}

		if oneFound {
			tokens = append(tokens, pyToken{kind: oneKind, value: string(ch), line: line, col: startCol})
			i++
			col++
			continue
		}

		// Skip unknown characters
		i++
		col++
	}

	// Ensure final NEWLINE
	if len(tokens) == 0 || tokens[len(tokens)-1].kind != pyTokNewline {
		tokens = append(tokens, pyToken{kind: pyTokNewline, value: "\n", line: line, col: col})
	}

	tokens = append(tokens, pyToken{kind: pyTokEOF, value: "", line: line, col: col})
	return tokens
}

// insertIndentation processes raw tokens and inserts INDENT/DEDENT tokens
// based on leading whitespace at the start of each logical line.
func (p *pyParser) insertIndentation(raw []pyToken) []pyToken {
	var result []pyToken
	indentStack := []int{0}
	atLineStart := true
	i := 0

	for i < len(raw) {
		tok := raw[i]

		if tok.kind == pyTokNewline {
			result = append(result, tok)
			atLineStart = true
			i++
			continue
		}

		if tok.kind == pyTokEOF {
			// Emit DEDENT for each remaining indent level
			for len(indentStack) > 1 {
				result = append(result, pyToken{kind: pyTokDedent, value: "", line: tok.line, col: tok.col})
				indentStack = indentStack[:len(indentStack)-1]
			}
			result = append(result, tok)
			break
		}

		if atLineStart {
			atLineStart = false
			indent := tok.col // col is already the column offset
			currentIndent := indentStack[len(indentStack)-1]

			if indent > currentIndent {
				indentStack = append(indentStack, indent)
				result = append(result, pyToken{kind: pyTokIndent, value: "", line: tok.line, col: tok.col})
			} else if indent < currentIndent {
				for len(indentStack) > 1 && indentStack[len(indentStack)-1] > indent {
					indentStack = indentStack[:len(indentStack)-1]
					result = append(result, pyToken{kind: pyTokDedent, value: "", line: tok.line, col: tok.col})
				}
			}
		}

		result = append(result, tok)
		i++
	}

	return result
}

// pyByteStringToHex converts Python byte string content like \xde\xad to hex "dead".
func pyByteStringToHex(s string) string {
	var hex strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == 'x' && i+3 < len(s) {
				hex.WriteString(s[i+2 : i+4])
				i += 4
				continue
			}
		}
		// Non-escape byte: encode as hex
		hex.WriteString(fmt.Sprintf("%02x", s[i]))
		i++
	}
	return hex.String()
}

func pyIsIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func pyIsIdentPart(ch byte) bool {
	return pyIsIdentStart(ch) || (ch >= '0' && ch <= '9')
}

// ---------------------------------------------------------------------------
// Snake-case to camelCase name conversion
// ---------------------------------------------------------------------------

// pySpecialNames maps Python snake_case names to their Rúnar camelCase equivalents.
var pySpecialNames = map[string]string{
	// Strip trailing underscore
	"assert_": "assert",

	// Constructor
	"__init__": "constructor",

	// Crypto builtins
	"check_sig":       "checkSig",
	"check_multi_sig": "checkMultiSig",
	"check_preimage":  "checkPreimage",

	// Post-quantum
	"verify_wots":                "verifyWOTS",
	"verify_slh_dsa_sha2_128s":  "verifySLHDSA_SHA2_128s",
	"verify_slh_dsa_sha2_128f":  "verifySLHDSA_SHA2_128f",
	"verify_slh_dsa_sha2_192s":  "verifySLHDSA_SHA2_192s",
	"verify_slh_dsa_sha2_192f":  "verifySLHDSA_SHA2_192f",
	"verify_slh_dsa_sha2_256s":  "verifySLHDSA_SHA2_256s",
	"verify_slh_dsa_sha2_256f":  "verifySLHDSA_SHA2_256f",
	"verify_rabin_sig":          "verifyRabinSig",

	// EC builtins
	"ec_add":               "ecAdd",
	"ec_mul":               "ecMul",
	"ec_mul_gen":           "ecMulGen",
	"ec_negate":            "ecNegate",
	"ec_on_curve":          "ecOnCurve",
	"ec_mod_reduce":        "ecModReduce",
	"ec_encode_compressed": "ecEncodeCompressed",
	"ec_make_point":        "ecMakePoint",
	"ec_point_x":           "ecPointX",
	"ec_point_y":           "ecPointY",

	// Intrinsics
	"add_output":       "addOutput",
	"get_state_script": "getStateScript",

	// Transaction intrinsics
	"extract_locktime":     "extractLocktime",
	"extract_output_hash":  "extractOutputHash",
	"extract_sequence":     "extractSequence",
	"extract_version":      "extractVersion",

	// Math builtins
	"mul_div":       "mulDiv",
	"percent_of":    "percentOf",
	"reverse_bytes": "reverseBytes",
	"safe_div":      "safediv",
	"safe_mod":      "safemod",

	// Hash builtins
	"sha256":    "sha256",
	"ripemd160": "ripemd160",
	"hash160":   "hash160",
	"hash256":   "hash256",

	// Misc
	"num2bin":  "num2bin",
	"bin2num":  "bin2num",
	"log2":    "log2",
	"div_mod": "divmod",

	// EC constants
	"EC_P": "EC_P",
	"EC_N": "EC_N",
	"EC_G": "EC_G",
}

// pyConvertName converts a Python snake_case name to the Rúnar camelCase equivalent.
func pyConvertName(name string) string {
	// Check special names first
	if mapped, ok := pySpecialNames[name]; ok {
		return mapped
	}

	// If the name doesn't contain underscores, return as-is
	if !strings.Contains(name, "_") {
		return name
	}

	// Check for dunder names
	if strings.HasPrefix(name, "__") && strings.HasSuffix(name, "__") {
		return name
	}

	// Strip trailing underscore (e.g., assert_ -> assert)
	cleaned := strings.TrimRight(name, "_")
	if cleaned != name {
		if mapped, ok := pySpecialNames[cleaned+"_"]; ok {
			return mapped
		}
	}

	// Strip leading single underscore for private methods (Python convention)
	// _helper -> helper, __dunder__ already handled above
	stripped := name
	if strings.HasPrefix(stripped, "_") && !strings.HasPrefix(stripped, "__") {
		stripped = stripped[1:]
	}

	// General snake_case to camelCase conversion
	parts := strings.Split(stripped, "_")
	if len(parts) <= 1 {
		return stripped
	}

	var b strings.Builder
	b.WriteString(parts[0])
	for _, part := range parts[1:] {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Parser helpers
// ---------------------------------------------------------------------------

func (p *pyParser) peek() pyToken {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return pyToken{kind: pyTokEOF}
}

func (p *pyParser) advance() pyToken {
	tok := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

func (p *pyParser) expect(kind pyTokenKind) pyToken {
	tok := p.advance()
	if tok.kind != kind {
		p.addError(fmt.Sprintf("line %d: expected token kind %d, got %d (%q)", tok.line, kind, tok.kind, tok.value))
	}
	return tok
}

func (p *pyParser) expectIdent(value string) pyToken {
	tok := p.advance()
	if tok.kind != pyTokIdent || tok.value != value {
		p.addError(fmt.Sprintf("line %d: expected '%s', got %q", tok.line, value, tok.value))
	}
	return tok
}

func (p *pyParser) check(kind pyTokenKind) bool {
	return p.peek().kind == kind
}

func (p *pyParser) checkIdent(value string) bool {
	tok := p.peek()
	return tok.kind == pyTokIdent && tok.value == value
}

func (p *pyParser) match(kind pyTokenKind) bool {
	if p.check(kind) {
		p.advance()
		return true
	}
	return false
}

func (p *pyParser) matchIdent(value string) bool {
	if p.checkIdent(value) {
		p.advance()
		return true
	}
	return false
}

func (p *pyParser) loc() SourceLocation {
	tok := p.peek()
	return SourceLocation{File: p.fileName, Line: tok.line, Column: tok.col}
}

// skipNewlines consumes consecutive NEWLINE tokens.
func (p *pyParser) skipNewlines() {
	for p.check(pyTokNewline) {
		p.advance()
	}
}

// ---------------------------------------------------------------------------
// Type parsing
// ---------------------------------------------------------------------------

func parsePyType(name string) TypeNode {
	switch name {
	case "int":
		return PrimitiveType{Name: "bigint"}
	case "Int":
		return PrimitiveType{Name: "bigint"}
	case "Bigint":
		return PrimitiveType{Name: "bigint"}
	case "bool":
		return PrimitiveType{Name: "boolean"}
	case "Bool":
		return PrimitiveType{Name: "boolean"}
	case "bytes":
		return PrimitiveType{Name: "ByteString"}
	case "ByteString":
		return PrimitiveType{Name: "ByteString"}
	case "PubKey":
		return PrimitiveType{Name: "PubKey"}
	case "Sig":
		return PrimitiveType{Name: "Sig"}
	case "Sha256":
		return PrimitiveType{Name: "Sha256"}
	case "Ripemd160":
		return PrimitiveType{Name: "Ripemd160"}
	case "Addr":
		return PrimitiveType{Name: "Addr"}
	case "SigHashPreimage":
		return PrimitiveType{Name: "SigHashPreimage"}
	case "RabinSig":
		return PrimitiveType{Name: "RabinSig"}
	case "RabinPubKey":
		return PrimitiveType{Name: "RabinPubKey"}
	case "Point":
		return PrimitiveType{Name: "Point"}
	case "bigint":
		return PrimitiveType{Name: "bigint"}
	case "boolean":
		return PrimitiveType{Name: "boolean"}
	default:
		if IsPrimitiveType(name) {
			return PrimitiveType{Name: name}
		}
		return CustomType{Name: name}
	}
}

// parsePyTypeAnnotation parses a type annotation after ":".
// Handles: int, bool, bytes, Readonly[T], FixedArray[T, N], etc.
func (p *pyParser) parsePyTypeAnnotation() TypeNode {
	tok := p.peek()
	if tok.kind != pyTokIdent {
		p.addError(fmt.Sprintf("line %d: expected type name, got %q", tok.line, tok.value))
		p.advance()
		return CustomType{Name: "unknown"}
	}

	name := tok.value
	p.advance()

	// Check for Readonly[T]
	if name == "Readonly" {
		if p.match(pyTokLBracket) {
			inner := p.parsePyTypeAnnotation()
			p.expect(pyTokRBracket)
			// Return the inner type — Readonly-ness is handled at the property level
			return inner
		}
		return CustomType{Name: name}
	}

	// Check for FixedArray[T, N]
	if name == "FixedArray" {
		if p.match(pyTokLBracket) {
			elemType := p.parsePyTypeAnnotation()
			p.expect(pyTokComma)
			sizeTok := p.expect(pyTokNumber)
			size, err := strconv.Atoi(sizeTok.value)
			if err != nil || size < 0 {
				p.addError(fmt.Sprintf("line %d: FixedArray size must be a non-negative integer, got %q", sizeTok.line, sizeTok.value))
			}
			p.expect(pyTokRBracket)
			return FixedArrayType{Element: elemType, Length: size}
		}
		return CustomType{Name: name}
	}

	// Generic subscript: SomeType[...]
	if p.check(pyTokLBracket) {
		// Skip subscript for unknown generic types
		p.advance()
		depth := 1
		for depth > 0 && !p.check(pyTokEOF) {
			if p.check(pyTokLBracket) {
				depth++
			}
			if p.check(pyTokRBracket) {
				depth--
				if depth == 0 {
					p.advance()
					break
				}
			}
			p.advance()
		}
		return parsePyType(name)
	}

	return parsePyType(name)
}

// ---------------------------------------------------------------------------
// Contract parsing
// ---------------------------------------------------------------------------

func (p *pyParser) parseContract() (*ContractNode, error) {
	p.skipNewlines()

	// Skip "from ... import ..." or "import ..." statements
	for p.checkIdent("from") || p.checkIdent("import") {
		for !p.check(pyTokNewline) && !p.check(pyTokEOF) {
			p.advance()
		}
		p.skipNewlines()
	}

	// class Name(ParentClass):
	if !p.matchIdent("class") {
		return nil, fmt.Errorf("expected 'class' keyword")
	}

	nameTok := p.expect(pyTokIdent)
	contractName := nameTok.value

	// Parse parent class: (SmartContract) or (StatefulSmartContract)
	parentClass := "SmartContract"
	if p.match(pyTokLParen) {
		parentTok := p.expect(pyTokIdent)
		parentClass = parentTok.value
		p.expect(pyTokRParen)
	}

	if parentClass != "SmartContract" && parentClass != "StatefulSmartContract" {
		return nil, fmt.Errorf("unknown parent class: %s", parentClass)
	}

	p.expect(pyTokColon)
	p.skipNewlines()
	p.expect(pyTokIndent)

	var properties []PropertyNode
	var constructor *MethodNode
	var methods []MethodNode

	for !p.check(pyTokDedent) && !p.check(pyTokEOF) {
		p.skipNewlines()
		if p.check(pyTokDedent) || p.check(pyTokEOF) {
			break
		}

		// Decorator: @public or @private
		if p.check(pyTokAt) {
			p.advance()
			decoratorTok := p.expect(pyTokIdent)
			decorator := decoratorTok.value
			p.skipNewlines()

			// The next thing should be a def
			if p.checkIdent("def") {
				method := p.parsePyMethod(decorator)
				methods = append(methods, method)
			} else {
				p.addError(fmt.Sprintf("line %d: expected 'def' after @%s decorator", p.peek().line, decorator))
			}
			continue
		}

		// def __init__(self, ...): or def method(self, ...):
		if p.checkIdent("def") {
			// Check if it's __init__
			if p.pos+1 < len(p.tokens) && p.tokens[p.pos+1].value == "__init__" {
				ctor := p.parsePyConstructor(properties)
				constructor = &ctor
			} else {
				method := p.parsePyMethod("private")
				methods = append(methods, method)
			}
			continue
		}

		// Check for pass
		if p.matchIdent("pass") {
			p.skipNewlines()
			continue
		}

		// Property: name: Type  or  name: Readonly[Type]
		if p.peek().kind == pyTokIdent && p.isPyPropertyDecl() {
			prop := p.parsePyProperty(parentClass)
			if prop != nil {
				properties = append(properties, *prop)
			}
			continue
		}

		// Skip unknown tokens to avoid infinite loops
		p.advance()
	}

	p.match(pyTokDedent)

	if constructor == nil {
		// Only non-initialized properties become constructor params
		var uninitProps []PropertyNode
		for _, prop := range properties {
			if prop.Initializer == nil {
				uninitProps = append(uninitProps, prop)
			}
		}
		params := make([]ParamNode, len(uninitProps))
		for i, prop := range uninitProps {
			params[i] = ParamNode{Name: prop.Name, Type: prop.Type}
		}
		superArgs := make([]Expression, len(uninitProps))
		for i, prop := range uninitProps {
			superArgs[i] = Identifier{Name: prop.Name}
		}
		body := []Statement{
			ExpressionStmt{
				Expr: CallExpr{
					Callee: Identifier{Name: "super"},
					Args:   superArgs,
				},
				SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
			},
		}
		for _, prop := range uninitProps {
			body = append(body, AssignmentStmt{
				Target:         PropertyAccessExpr{Property: prop.Name},
				Value:          Identifier{Name: prop.Name},
				SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
			})
		}
		constructor = &MethodNode{
			Name:       "constructor",
			Params:     params,
			Body:       body,
			Visibility: "public",
			SourceLocation: SourceLocation{
				File: p.fileName, Line: 1, Column: 0,
			},
		}
	}

	return &ContractNode{
		Name:        contractName,
		ParentClass: parentClass,
		Properties:  properties,
		Constructor: *constructor,
		Methods:     methods,
		SourceFile:  p.fileName,
	}, nil
}

// isPyPropertyDecl checks if current position is a property declaration: name: Type
func (p *pyParser) isPyPropertyDecl() bool {
	if p.pos+1 >= len(p.tokens) {
		return false
	}
	// name: Type — second token is ':'
	return p.tokens[p.pos+1].kind == pyTokColon
}

// ---------------------------------------------------------------------------
// Property parsing: name: Type or name: Readonly[Type]
// ---------------------------------------------------------------------------

func (p *pyParser) parsePyProperty(parentClass string) *PropertyNode {
	loc := p.loc()

	nameTok := p.expect(pyTokIdent)
	propName := pyConvertName(nameTok.value)

	p.expect(pyTokColon)

	// Check for Readonly[T]
	isReadonly := false
	if p.checkIdent("Readonly") {
		isReadonly = true
	}
	// In SmartContract, all properties are automatically readonly
	if parentClass == "SmartContract" {
		isReadonly = true
	}

	typNode := p.parsePyTypeAnnotation()

	// Optional initializer: = value
	var initializer Expression
	if p.match(pyTokAssign) {
		initializer = p.parsePyExpression()
	}

	p.skipNewlines()

	return &PropertyNode{
		Name:           propName,
		Type:           typNode,
		Readonly:       isReadonly,
		Initializer:    initializer,
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// Constructor parsing: def __init__(self, param: Type, ...):
// ---------------------------------------------------------------------------

func (p *pyParser) parsePyConstructor(properties []PropertyNode) MethodNode {
	loc := p.loc()
	p.expectIdent("def")
	p.expectIdent("__init__")

	params := p.parsePyParams()

	// Parse optional return type annotation
	if p.match(pyTokArrow) {
		// Skip return type (should be None for __init__)
		p.advance()
	}

	p.expect(pyTokColon)
	body := p.parsePyBlock()

	// Transform: find super().__init__(...) calls and convert to super(...) form.
	// Note: __init__ is converted to "constructor" by pyConvertName during parsing,
	// so we check for both "constructor" and "__init__".
	var constructorBody []Statement
	foundSuper := false

	for _, stmt := range body {
		if es, ok := stmt.(ExpressionStmt); ok {
			if call, ok := es.Expr.(CallExpr); ok {
				// Check for super().__init__(args) pattern
				if me, ok := call.Callee.(MemberExpr); ok && (me.Property == "__init__" || me.Property == "constructor") {
					if superCall, ok := me.Object.(CallExpr); ok {
						if ident, ok := superCall.Callee.(Identifier); ok && ident.Name == "super" {
							// Convert to super(...) call
							constructorBody = append(constructorBody, ExpressionStmt{
								Expr: CallExpr{
									Callee: Identifier{Name: "super"},
									Args:   call.Args,
								},
								SourceLocation: es.SourceLocation,
							})
							foundSuper = true
							continue
						}
					}
				}
			}
		}
		constructorBody = append(constructorBody, stmt)
	}

	// If no super() call was found, generate one with all param names
	if !foundSuper {
		superArgs := make([]Expression, len(params))
		for i, param := range params {
			superArgs[i] = Identifier{Name: param.Name}
		}
		constructorBody = append([]Statement{
			ExpressionStmt{
				Expr: CallExpr{
					Callee: Identifier{Name: "super"},
					Args:   superArgs,
				},
				SourceLocation: loc,
			},
		}, constructorBody...)
	}

	return MethodNode{
		Name:           "constructor",
		Params:         params,
		Body:           constructorBody,
		Visibility:     "public",
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// Method parsing: def method_name(self, param: Type, ...) -> ReturnType:
// ---------------------------------------------------------------------------

func (p *pyParser) parsePyMethod(visibility string) MethodNode {
	loc := p.loc()
	p.expectIdent("def")

	nameTok := p.expect(pyTokIdent)
	name := pyConvertName(nameTok.value)

	params := p.parsePyParams()

	// Parse optional return type annotation: -> Type
	if p.match(pyTokArrow) {
		// Skip return type
		p.parsePyTypeAnnotation()
	}

	p.expect(pyTokColon)
	body := p.parsePyBlock()

	return MethodNode{
		Name:           name,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// Parameter parsing: (self, param: Type, ...)
// ---------------------------------------------------------------------------

func (p *pyParser) parsePyParams() []ParamNode {
	p.expect(pyTokLParen)
	var params []ParamNode

	for !p.check(pyTokRParen) && !p.check(pyTokEOF) {
		nameTok := p.expect(pyTokIdent)
		paramName := nameTok.value

		// Skip 'self' parameter
		if paramName == "self" {
			if !p.match(pyTokComma) {
				break
			}
			continue
		}

		var typ TypeNode
		if p.match(pyTokColon) {
			typ = p.parsePyTypeAnnotation()
		}

		params = append(params, ParamNode{
			Name: pyConvertName(paramName),
			Type: typ,
		})

		if !p.match(pyTokComma) {
			break
		}
	}

	p.expect(pyTokRParen)
	return params
}

// ---------------------------------------------------------------------------
// Block parsing (indentation-based)
// ---------------------------------------------------------------------------

func (p *pyParser) parsePyBlock() []Statement {
	p.skipNewlines()
	p.expect(pyTokIndent)

	var stmts []Statement
	for !p.check(pyTokDedent) && !p.check(pyTokEOF) {
		p.skipNewlines()
		if p.check(pyTokDedent) || p.check(pyTokEOF) {
			break
		}
		stmt := p.parsePyStatement()
		if stmt != nil {
			stmts = append(stmts, stmt)
		}
	}

	p.match(pyTokDedent)
	return stmts
}

// ---------------------------------------------------------------------------
// Statement parsing
// ---------------------------------------------------------------------------

func (p *pyParser) parsePyStatement() Statement {
	loc := p.loc()

	// assert expr or assert_(expr)
	if p.checkIdent("assert") || p.checkIdent("assert_") {
		return p.parsePyAssert(loc)
	}

	// if ... :
	if p.checkIdent("if") {
		return p.parsePyIf(loc)
	}

	// for ... in range(...):
	if p.checkIdent("for") {
		return p.parsePyFor(loc)
	}

	// return ...
	if p.checkIdent("return") {
		return p.parsePyReturn(loc)
	}

	// pass
	if p.matchIdent("pass") {
		p.skipNewlines()
		return nil
	}

	// Variable declarations or expression statements
	return p.parsePyExprOrAssignStatement(loc)
}

func (p *pyParser) parsePyAssert(loc SourceLocation) Statement {
	tok := p.advance() // consume 'assert' or 'assert_'

	if tok.value == "assert_" {
		// assert_(expr) — function-call style
		p.expect(pyTokLParen)
		expr := p.parsePyExpression()
		p.expect(pyTokRParen)
		p.skipNewlines()
		return ExpressionStmt{
			Expr:           CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{expr}},
			SourceLocation: loc,
		}
	}

	// assert expr — keyword style
	if p.check(pyTokLParen) {
		// assert(expr) — also supported
		p.advance()
		expr := p.parsePyExpression()
		p.expect(pyTokRParen)
		p.skipNewlines()
		return ExpressionStmt{
			Expr:           CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{expr}},
			SourceLocation: loc,
		}
	}

	expr := p.parsePyExpression()
	p.skipNewlines()
	return ExpressionStmt{
		Expr:           CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{expr}},
		SourceLocation: loc,
	}
}

func (p *pyParser) parsePyIf(loc SourceLocation) Statement {
	p.expectIdent("if")
	return p.parsePyIfBody(loc)
}

// parsePyIfBody parses the condition, then-block, and optional elif/else chain.
// Factored out so that elif can call it after consuming the "elif" keyword.
func (p *pyParser) parsePyIfBody(loc SourceLocation) Statement {
	condition := p.parsePyExpression()
	p.expect(pyTokColon)

	thenBlock := p.parsePyBlock()

	var elseBlock []Statement
	p.skipNewlines()
	if p.checkIdent("elif") {
		elifLoc := p.loc()
		p.advance() // consume 'elif'
		// Recurse using parsePyIfBody which handles the rest identically
		elifStmt := p.parsePyIfBody(elifLoc)
		elseBlock = []Statement{elifStmt}
	} else if p.matchIdent("else") {
		p.expect(pyTokColon)
		elseBlock = p.parsePyBlock()
	}

	return IfStmt{
		Condition:      condition,
		Then:           thenBlock,
		Else:           elseBlock,
		SourceLocation: loc,
	}
}

func (p *pyParser) parsePyFor(loc SourceLocation) Statement {
	p.expectIdent("for")

	varTok := p.expect(pyTokIdent)
	varName := pyConvertName(varTok.value)

	p.expectIdent("in")
	p.expectIdent("range")
	p.expect(pyTokLParen)

	// range(n) or range(a, b)
	first := p.parsePyExpression()
	var initExpr Expression
	var limitExpr Expression

	if p.match(pyTokComma) {
		// range(a, b)
		initExpr = first
		limitExpr = p.parsePyExpression()
	} else {
		// range(n) — init = 0, limit = n
		initExpr = BigIntLiteral{Value: big.NewInt(0)}
		limitExpr = first
	}

	p.expect(pyTokRParen)
	p.expect(pyTokColon)

	body := p.parsePyBlock()

	// Build: for (let varName = initExpr; varName < limitExpr; varName++)
	initStmt := VariableDeclStmt{
		Name:           varName,
		Type:           PrimitiveType{Name: "bigint"},
		Mutable:        true,
		Init:           initExpr,
		SourceLocation: loc,
	}

	condition := BinaryExpr{
		Op:    "<",
		Left:  Identifier{Name: varName},
		Right: limitExpr,
	}

	update := ExpressionStmt{
		Expr:           IncrementExpr{Operand: Identifier{Name: varName}, Prefix: false},
		SourceLocation: loc,
	}

	return ForStmt{
		Init:           initStmt,
		Condition:      condition,
		Update:         update,
		Body:           body,
		SourceLocation: loc,
	}
}

func (p *pyParser) parsePyReturn(loc SourceLocation) Statement {
	p.expectIdent("return")
	var value Expression
	if !p.check(pyTokNewline) && !p.check(pyTokDedent) && !p.check(pyTokEOF) {
		value = p.parsePyExpression()
	}
	p.skipNewlines()
	return ReturnStmt{Value: value, SourceLocation: loc}
}

// parsePyExprOrAssignStatement handles:
// - name: Type = expr  (variable declaration with type)
// - name = expr        (variable declaration or assignment)
// - expr               (expression statement)
// - compound assignments: +=, -=, *=, //=, %=
func (p *pyParser) parsePyExprOrAssignStatement(loc SourceLocation) Statement {
	// Check for variable declaration: name: Type = expr
	if p.peek().kind == pyTokIdent && p.pos+1 < len(p.tokens) && p.tokens[p.pos+1].kind == pyTokColon {
		// Could be a property-like declaration or a variable declaration
		// In a method body, "name: Type = expr" is a typed variable declaration
		nameTok := p.advance()
		varName := pyConvertName(nameTok.value)
		p.expect(pyTokColon) // consume ':'

		typNode := p.parsePyTypeAnnotation()

		var init Expression
		if p.match(pyTokAssign) {
			init = p.parsePyExpression()
		} else {
			init = BigIntLiteral{Value: big.NewInt(0)}
		}
		p.skipNewlines()
		return VariableDeclStmt{
			Name:           varName,
			Type:           typNode,
			Mutable:        true,
			Init:           init,
			SourceLocation: loc,
		}
	}

	expr := p.parsePyExpression()
	if expr == nil {
		p.advance()
		p.skipNewlines()
		return nil
	}

	// Check for assignment: name = expr
	if p.match(pyTokAssign) {
		value := p.parsePyExpression()
		p.skipNewlines()
		// If the target is a plain identifier, it's a variable declaration (first assignment)
		// But we can't always tell — emit assignment for now (the validator/ANF handles it)
		if ident, ok := expr.(Identifier); ok {
			// Treat bare "name = expr" as a variable declaration for simple identifiers
			return VariableDeclStmt{
				Name:           ident.Name,
				Mutable:        true,
				Init:           value,
				SourceLocation: loc,
			}
		}
		return AssignmentStmt{Target: expr, Value: value, SourceLocation: loc}
	}

	// Compound assignments
	compoundOps := map[pyTokenKind]string{
		pyTokPlusEq:    "+",
		pyTokMinusEq:   "-",
		pyTokStarEq:    "*",
		pyTokSlashEq:   "/",
		pyTokPercentEq: "%",
	}
	for kind, binOp := range compoundOps {
		if p.match(kind) {
			right := p.parsePyExpression()
			p.skipNewlines()
			value := BinaryExpr{Op: binOp, Left: expr, Right: right}
			return AssignmentStmt{Target: expr, Value: value, SourceLocation: loc}
		}
	}

	p.skipNewlines()
	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// Expression parsing (recursive descent with precedence)
// ---------------------------------------------------------------------------

func (p *pyParser) parsePyExpression() Expression {
	return p.parsePyTernary()
}

// Python ternary: value_if_true if condition else value_if_false
// Parsed as: parse lower precedence, then check for postfix "if"
func (p *pyParser) parsePyTernary() Expression {
	expr := p.parsePyOr()

	// Check for "if" keyword (ternary postfix)
	if p.checkIdent("if") {
		p.advance() // consume 'if'
		condition := p.parsePyOr()
		p.expectIdent("else")
		alternate := p.parsePyTernary()
		return TernaryExpr{
			Condition:  condition,
			Consequent: expr,
			Alternate:  alternate,
		}
	}

	return expr
}

func (p *pyParser) parsePyOr() Expression {
	left := p.parsePyAnd()
	for p.match(pyTokPipePipe) {
		right := p.parsePyAnd()
		left = BinaryExpr{Op: "||", Left: left, Right: right}
	}
	return left
}

func (p *pyParser) parsePyAnd() Expression {
	left := p.parsePyNot()
	for p.match(pyTokAmpAmp) {
		right := p.parsePyNot()
		left = BinaryExpr{Op: "&&", Left: left, Right: right}
	}
	return left
}

func (p *pyParser) parsePyNot() Expression {
	if p.match(pyTokBang) {
		operand := p.parsePyNot()
		return UnaryExpr{Op: "!", Operand: operand}
	}
	return p.parsePyBitwiseOr()
}

func (p *pyParser) parsePyBitwiseOr() Expression {
	left := p.parsePyBitwiseXor()
	for p.match(pyTokPipe) {
		right := p.parsePyBitwiseXor()
		left = BinaryExpr{Op: "|", Left: left, Right: right}
	}
	return left
}

func (p *pyParser) parsePyBitwiseXor() Expression {
	left := p.parsePyBitwiseAnd()
	for p.match(pyTokCaret) {
		right := p.parsePyBitwiseAnd()
		left = BinaryExpr{Op: "^", Left: left, Right: right}
	}
	return left
}

func (p *pyParser) parsePyBitwiseAnd() Expression {
	left := p.parsePyEquality()
	for p.match(pyTokAmp) {
		right := p.parsePyEquality()
		left = BinaryExpr{Op: "&", Left: left, Right: right}
	}
	return left
}

func (p *pyParser) parsePyEquality() Expression {
	left := p.parsePyComparison()
	for {
		if p.match(pyTokEqEq) {
			right := p.parsePyComparison()
			left = BinaryExpr{Op: "===", Left: left, Right: right} // Map == to ===
		} else if p.match(pyTokNotEq) {
			right := p.parsePyComparison()
			left = BinaryExpr{Op: "!==", Left: left, Right: right} // Map != to !==
		} else {
			break
		}
	}
	return left
}

func (p *pyParser) parsePyComparison() Expression {
	left := p.parsePyShift()
	for {
		if p.match(pyTokLt) {
			right := p.parsePyShift()
			left = BinaryExpr{Op: "<", Left: left, Right: right}
		} else if p.match(pyTokLtEq) {
			right := p.parsePyShift()
			left = BinaryExpr{Op: "<=", Left: left, Right: right}
		} else if p.match(pyTokGt) {
			right := p.parsePyShift()
			left = BinaryExpr{Op: ">", Left: left, Right: right}
		} else if p.match(pyTokGtEq) {
			right := p.parsePyShift()
			left = BinaryExpr{Op: ">=", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *pyParser) parsePyShift() Expression {
	left := p.parsePyAdditive()
	for {
		if p.match(pyTokLShift) {
			right := p.parsePyAdditive()
			left = BinaryExpr{Op: "<<", Left: left, Right: right}
		} else if p.match(pyTokRShift) {
			right := p.parsePyAdditive()
			left = BinaryExpr{Op: ">>", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *pyParser) parsePyAdditive() Expression {
	left := p.parsePyMultiplicative()
	for {
		if p.match(pyTokPlus) {
			right := p.parsePyMultiplicative()
			left = BinaryExpr{Op: "+", Left: left, Right: right}
		} else if p.match(pyTokMinus) {
			right := p.parsePyMultiplicative()
			left = BinaryExpr{Op: "-", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *pyParser) parsePyMultiplicative() Expression {
	left := p.parsePyUnary()
	for {
		if p.match(pyTokStar) {
			right := p.parsePyUnary()
			left = BinaryExpr{Op: "*", Left: left, Right: right}
		} else if p.match(pyTokSlashSlash) {
			// Python // (integer division) maps to / in Rúnar
			right := p.parsePyUnary()
			left = BinaryExpr{Op: "/", Left: left, Right: right}
		} else if p.match(pyTokSlash) {
			right := p.parsePyUnary()
			left = BinaryExpr{Op: "/", Left: left, Right: right}
		} else if p.match(pyTokPercent) {
			right := p.parsePyUnary()
			left = BinaryExpr{Op: "%", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *pyParser) parsePyUnary() Expression {
	if p.match(pyTokMinus) {
		operand := p.parsePyUnary()
		return UnaryExpr{Op: "-", Operand: operand}
	}
	if p.match(pyTokTilde) {
		operand := p.parsePyUnary()
		return UnaryExpr{Op: "~", Operand: operand}
	}
	if p.match(pyTokBang) {
		operand := p.parsePyUnary()
		return UnaryExpr{Op: "!", Operand: operand}
	}
	return p.parsePyPower()
}

// parsePyPower handles ** (right-associative)
func (p *pyParser) parsePyPower() Expression {
	base := p.parsePyPostfix()
	if p.match(pyTokStarStar) {
		exp := p.parsePyUnary() // right-associative
		return CallExpr{Callee: Identifier{Name: "pow"}, Args: []Expression{base, exp}}
	}
	return base
}

func (p *pyParser) parsePyPostfix() Expression {
	expr := p.parsePyPrimary()
	for {
		if p.match(pyTokDot) {
			propTok := p.expect(pyTokIdent)
			propName := pyConvertName(propTok.value)

			// Check if this is a method call: obj.method(...)
			if p.check(pyTokLParen) {
				args := p.parsePyCallArgs()

				// Handle self.add_output(...) etc.
				if ident, ok := expr.(Identifier); ok && ident.Name == "self" {
					expr = CallExpr{
						Callee: MemberExpr{Object: Identifier{Name: "this"}, Property: propName},
						Args:   args,
					}
				} else {
					expr = CallExpr{
						Callee: MemberExpr{Object: expr, Property: propName},
						Args:   args,
					}
				}
			} else {
				// Property access
				if ident, ok := expr.(Identifier); ok && ident.Name == "self" {
					expr = PropertyAccessExpr{Property: propName}
				} else {
					expr = MemberExpr{Object: expr, Property: propName}
				}
			}
		} else if p.match(pyTokLBracket) {
			index := p.parsePyExpression()
			p.expect(pyTokRBracket)
			expr = IndexAccessExpr{Object: expr, Index: index}
		} else if p.match(pyTokLParen) {
			// Direct call on expression: expr(...)
			var args []Expression
			for !p.check(pyTokRParen) && !p.check(pyTokEOF) {
				arg := p.parsePyExpression()
				args = append(args, arg)
				if !p.match(pyTokComma) {
					break
				}
			}
			p.expect(pyTokRParen)
			expr = CallExpr{Callee: expr, Args: args}
		} else {
			break
		}
	}
	return expr
}

func (p *pyParser) parsePyPrimary() Expression {
	tok := p.peek()

	switch tok.kind {
	case pyTokNumber:
		p.advance()
		return parsePyNumber(tok.value)
	case pyTokString:
		p.advance()
		return ByteStringLiteral{Value: tok.value}
	case pyTokIdent:
		p.advance()
		name := tok.value

		// Boolean literals
		if name == "True" {
			return BoolLiteral{Value: true}
		}
		if name == "False" {
			return BoolLiteral{Value: false}
		}
		if name == "None" {
			return BigIntLiteral{Value: big.NewInt(0)}
		}
		if name == "true" {
			return BoolLiteral{Value: true}
		}
		if name == "false" {
			return BoolLiteral{Value: false}
		}
		if name == "self" {
			return Identifier{Name: "self"}
		}
		if name == "super" {
			return Identifier{Name: "super"}
		}

		// bytes.fromhex("dead") pattern
		if name == "bytes" && p.check(pyTokDot) {
			return p.parsePyBytesMethod()
		}

		// Convert name
		converted := pyConvertName(name)

		// Function call
		if p.check(pyTokLParen) {
			args := p.parsePyCallArgs()
			return CallExpr{Callee: Identifier{Name: converted}, Args: args}
		}

		return Identifier{Name: converted}

	case pyTokLParen:
		p.advance()
		expr := p.parsePyExpression()
		p.expect(pyTokRParen)
		return expr

	case pyTokLBracket:
		// Array literal: [a, b, c]
		return p.parsePyArrayLiteral()

	default:
		p.addError(fmt.Sprintf("line %d: unexpected token %q", tok.line, tok.value))
		p.advance()
		return BigIntLiteral{Value: big.NewInt(0)}
	}
}

// parsePyBytesMethod handles bytes.fromhex("dead") → ByteStringLiteral
func (p *pyParser) parsePyBytesMethod() Expression {
	// We already consumed "bytes" — now expect .fromhex("hexstring")
	p.expect(pyTokDot)
	methodTok := p.expect(pyTokIdent)
	if methodTok.value == "fromhex" {
		p.expect(pyTokLParen)
		strTok := p.expect(pyTokString)
		p.expect(pyTokRParen)
		return ByteStringLiteral{Value: strTok.value}
	}
	// Unknown bytes method — return as a member call
	if p.check(pyTokLParen) {
		args := p.parsePyCallArgs()
		return CallExpr{
			Callee: MemberExpr{Object: Identifier{Name: "bytes"}, Property: methodTok.value},
			Args:   args,
		}
	}
	return MemberExpr{Object: Identifier{Name: "bytes"}, Property: methodTok.value}
}

// parsePyArrayLiteral handles [a, b, c]
func (p *pyParser) parsePyArrayLiteral() Expression {
	p.expect(pyTokLBracket)
	var elements []Expression
	for !p.check(pyTokRBracket) && !p.check(pyTokEOF) {
		elem := p.parsePyExpression()
		elements = append(elements, elem)
		if !p.match(pyTokComma) {
			break
		}
	}
	p.expect(pyTokRBracket)
	// Represent as a call to FixedArray constructor (same pattern as other parsers)
	return CallExpr{
		Callee: Identifier{Name: "FixedArray"},
		Args:   elements,
	}
}

func (p *pyParser) parsePyCallArgs() []Expression {
	p.expect(pyTokLParen)
	var args []Expression
	for !p.check(pyTokRParen) && !p.check(pyTokEOF) {
		arg := p.parsePyExpression()
		args = append(args, arg)
		if !p.match(pyTokComma) {
			break
		}
	}
	p.expect(pyTokRParen)
	return args
}

func parsePyNumber(s string) Expression {
	bi := new(big.Int)
	if _, ok := bi.SetString(s, 0); !ok {
		return BigIntLiteral{Value: big.NewInt(0)}
	}
	return BigIntLiteral{Value: bi}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// pyIsPyKeyword returns true if the identifier is a Python keyword that
// cannot be a variable name.
func pyIsPyKeyword(name string) bool {
	switch name {
	case "class", "def", "if", "elif", "else", "for", "in", "range",
		"return", "pass", "True", "False", "None", "and", "or", "not",
		"self", "super", "from", "import", "assert", "while", "break",
		"continue", "lambda", "yield", "with", "as", "try", "except",
		"finally", "raise", "del", "global", "nonlocal":
		return true
	}
	return false
}

// pyIsPyTypeStart checks if the current position looks like a type annotation
// pattern: identifier followed by identifier (Type name).
func (p *pyParser) pyIsPyTypeStart() bool {
	if p.pos+1 >= len(p.tokens) {
		return false
	}
	next := p.tokens[p.pos+1]
	if next.kind == pyTokIdent {
		name := p.peek().value
		// Known types
		if IsPrimitiveType(name) || parsePyType(name) != (CustomType{Name: name}) {
			return true
		}
		if len(name) > 0 && unicode.IsUpper(rune(name[0])) {
			return true
		}
		switch name {
		case "int", "bool", "bytes", "Int":
			return true
		}
	}
	return false
}

// Ensure the _ import is used
var _ = unicode.IsUpper
