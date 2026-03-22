package frontend

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParseRuby parses a Ruby-syntax Rúnar contract (.runar.rb) and produces
// the standard AST.
func ParseRuby(source []byte, fileName string) *ParseResult {
	p := &rbParser{
		fileName: fileName,
	}

	tokens := p.tokenize(string(source))
	p.tokens = tokens
	p.pos = 0

	contract, err := p.parseContract()
	if err != nil {
		return &ParseResult{Errors: []string{err.Error()}}
	}
	if len(p.errors) > 0 {
		return &ParseResult{Contract: contract, Errors: p.errors}
	}
	return &ParseResult{Contract: contract}
}

// ---------------------------------------------------------------------------
// Token types
// ---------------------------------------------------------------------------

type rbTokenKind int

const (
	rbTokEOF rbTokenKind = iota
	rbTokIdent
	rbTokNumber
	rbTokHexString  // single-quoted string -> hex ByteString
	rbTokString     // double-quoted string
	rbTokSymbol     // :name
	rbTokIvar       // @name
	rbTokLParen     // (
	rbTokRParen     // )
	rbTokLBracket   // [
	rbTokRBracket   // ]
	rbTokComma      // ,
	rbTokDot        // .
	rbTokColon      // :
	rbTokColonColon // ::
	rbTokAssign     // =
	rbTokEqEq       // ==
	rbTokNotEq      // !=
	rbTokLt         // <
	rbTokLtEq       // <=
	rbTokGt         // >
	rbTokGtEq       // >=
	rbTokPlus       // +
	rbTokMinus      // -
	rbTokStar       // *
	rbTokSlash      // /
	rbTokPercent    // %
	rbTokBang       // !
	rbTokTilde      // ~
	rbTokAmp        // &
	rbTokPipe       // |
	rbTokCaret      // ^
	rbTokAmpAmp     // &&
	rbTokPipePipe   // ||
	rbTokPlusEq     // +=
	rbTokMinusEq    // -=
	rbTokStarEq     // *=
	rbTokSlashEq    // /=
	rbTokPercentEq  // %=
	rbTokStarStar   // **
	rbTokLShift     // <<
	rbTokRShift     // >>
	rbTokDotDot     // ..
	rbTokDotDotDot  // ...
	rbTokQuestion   // ?
	rbTokNewline    // logical line end
	// Keywords (stored as distinct token kinds for fast matching)
	rbTokClass
	rbTokDef
	rbTokIf
	rbTokElsif
	rbTokElse
	rbTokUnless
	rbTokFor
	rbTokIn
	rbTokEnd
	rbTokReturn
	rbTokTrue
	rbTokFalse
	rbTokNil
	rbTokAnd    // keyword 'and'
	rbTokOr     // keyword 'or'
	rbTokNot    // keyword 'not'
	rbTokSuper
	rbTokRequire
	rbTokAssert
	rbTokDo
)

type rbToken struct {
	kind  rbTokenKind
	value string
	line  int
	col   int
}

// ---------------------------------------------------------------------------
// Parser struct
// ---------------------------------------------------------------------------

type rbParser struct {
	fileName      string
	tokens        []rbToken
	pos           int
	errors        []string
	declaredLocals map[string]bool // track locally declared variables per method scope
}

func (p *rbParser) addError(msg string) {
	p.errors = append(p.errors, msg)
}

// ---------------------------------------------------------------------------
// Tokeniser
// ---------------------------------------------------------------------------

// rbKeywords maps Ruby keyword strings to token kinds.
var rbKeywords = map[string]rbTokenKind{
	"class":   rbTokClass,
	"def":     rbTokDef,
	"if":      rbTokIf,
	"elsif":   rbTokElsif,
	"else":    rbTokElse,
	"unless":  rbTokUnless,
	"for":     rbTokFor,
	"in":      rbTokIn,
	"end":     rbTokEnd,
	"return":  rbTokReturn,
	"true":    rbTokTrue,
	"false":   rbTokFalse,
	"nil":     rbTokNil,
	"and":     rbTokAnd,
	"or":      rbTokOr,
	"not":     rbTokNot,
	"super":   rbTokSuper,
	"require": rbTokRequire,
	"assert":  rbTokAssert,
	"do":      rbTokDo,
}

func (p *rbParser) tokenize(source string) []rbToken {
	var tokens []rbToken
	lines := strings.Split(source, "\n")
	parenDepth := 0

	for lineIdx, rawLine := range lines {
		lineNum := lineIdx + 1

		// Strip trailing \r
		line := strings.TrimRight(rawLine, "\r")

		// Skip blank lines and comment-only lines
		stripped := strings.TrimLeft(line, " \t")
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}

		pos := len(line) - len(stripped)

		for pos < len(line) {
			ch := line[pos]
			col := pos + 1

			// Whitespace within line
			if ch == ' ' || ch == '\t' {
				pos++
				continue
			}

			// Comment
			if ch == '#' {
				break // rest of line is comment
			}

			// Instance variable: @name
			if ch == '@' {
				pos++
				name := ""
				for pos < len(line) && rbIsIdentPart(line[pos]) {
					name += string(line[pos])
					pos++
				}
				if len(name) > 0 {
					tokens = append(tokens, rbToken{kind: rbTokIvar, value: name, line: lineNum, col: col})
				}
				continue
			}

			// Three-dot range operator
			if ch == '.' && pos+2 < len(line) && line[pos+1] == '.' && line[pos+2] == '.' {
				tokens = append(tokens, rbToken{kind: rbTokDotDotDot, value: "...", line: lineNum, col: col})
				pos += 3
				continue
			}

			// Two-dot range operator
			if ch == '.' && pos+1 < len(line) && line[pos+1] == '.' {
				tokens = append(tokens, rbToken{kind: rbTokDotDot, value: "..", line: lineNum, col: col})
				pos += 2
				continue
			}

			// Two-char operators
			if pos+1 < len(line) {
				two := line[pos : pos+2]
				var twoKind rbTokenKind
				found := true
				switch two {
				case "**":
					twoKind = rbTokStarStar
				case "::":
					twoKind = rbTokColonColon
				case "==":
					twoKind = rbTokEqEq
				case "!=":
					twoKind = rbTokNotEq
				case "<=":
					twoKind = rbTokLtEq
				case ">=":
					twoKind = rbTokGtEq
				case "<<":
					twoKind = rbTokLShift
				case ">>":
					twoKind = rbTokRShift
				case "&&":
					twoKind = rbTokAmpAmp
				case "||":
					twoKind = rbTokPipePipe
				case "+=":
					twoKind = rbTokPlusEq
				case "-=":
					twoKind = rbTokMinusEq
				case "*=":
					twoKind = rbTokStarEq
				case "/=":
					twoKind = rbTokSlashEq
				case "%=":
					twoKind = rbTokPercentEq
				default:
					found = false
				}
				if found {
					tokens = append(tokens, rbToken{kind: twoKind, value: two, line: lineNum, col: col})
					pos += 2
					continue
				}
			}

			// Parentheses (track depth for multi-line expressions)
			if ch == '(' {
				parenDepth++
				tokens = append(tokens, rbToken{kind: rbTokLParen, value: "(", line: lineNum, col: col})
				pos++
				continue
			}
			if ch == ')' {
				if parenDepth > 0 {
					parenDepth--
				}
				tokens = append(tokens, rbToken{kind: rbTokRParen, value: ")", line: lineNum, col: col})
				pos++
				continue
			}
			if ch == '[' {
				parenDepth++
				tokens = append(tokens, rbToken{kind: rbTokLBracket, value: "[", line: lineNum, col: col})
				pos++
				continue
			}
			if ch == ']' {
				if parenDepth > 0 {
					parenDepth--
				}
				tokens = append(tokens, rbToken{kind: rbTokRBracket, value: "]", line: lineNum, col: col})
				pos++
				continue
			}

			// Symbol: :name (but not ::)
			if ch == ':' && pos+1 < len(line) && rbIsIdentStart(line[pos+1]) {
				pos++ // skip ':'
				name := ""
				for pos < len(line) && rbIsIdentPart(line[pos]) {
					name += string(line[pos])
					pos++
				}
				tokens = append(tokens, rbToken{kind: rbTokSymbol, value: name, line: lineNum, col: col})
				continue
			}

			// Single-quoted string literals: hex ByteStrings
			if ch == '\'' {
				pos++
				val := ""
				for pos < len(line) && line[pos] != '\'' {
					if line[pos] == '\\' && pos+1 < len(line) {
						pos++ // skip backslash
						val += string(line[pos])
						pos++
					} else {
						val += string(line[pos])
						pos++
					}
				}
				if pos < len(line) {
					pos++ // skip closing quote
				}
				tokens = append(tokens, rbToken{kind: rbTokHexString, value: val, line: lineNum, col: col})
				continue
			}

			// Double-quoted string literals
			if ch == '"' {
				pos++
				val := ""
				for pos < len(line) && line[pos] != '"' {
					if line[pos] == '\\' && pos+1 < len(line) {
						pos++ // skip backslash
						val += string(line[pos])
						pos++
					} else {
						val += string(line[pos])
						pos++
					}
				}
				if pos < len(line) {
					pos++ // skip closing quote
				}
				tokens = append(tokens, rbToken{kind: rbTokString, value: val, line: lineNum, col: col})
				continue
			}

			// Numbers (decimal and hex)
			if ch >= '0' && ch <= '9' {
				num := ""
				if ch == '0' && pos+1 < len(line) && (line[pos+1] == 'x' || line[pos+1] == 'X') {
					num = "0x"
					pos += 2
					for pos < len(line) && (isHexDigit(line[pos]) || line[pos] == '_') {
						if line[pos] != '_' {
							num += string(line[pos])
						}
						pos++
					}
				} else {
					for pos < len(line) && ((line[pos] >= '0' && line[pos] <= '9') || line[pos] == '_') {
						if line[pos] != '_' {
							num += string(line[pos])
						}
						pos++
					}
				}
				tokens = append(tokens, rbToken{kind: rbTokNumber, value: num, line: lineNum, col: col})
				continue
			}

			// Identifiers and keywords
			if rbIsIdentStart(ch) {
				val := ""
				for pos < len(line) && rbIsIdentPart(line[pos]) {
					val += string(line[pos])
					pos++
				}
				// Check for trailing ? or ! (Ruby convention)
				if pos < len(line) && (line[pos] == '?' || line[pos] == '!') {
					val += string(line[pos])
					pos++
				}
				if kw, ok := rbKeywords[val]; ok {
					tokens = append(tokens, rbToken{kind: kw, value: val, line: lineNum, col: col})
				} else {
					tokens = append(tokens, rbToken{kind: rbTokIdent, value: val, line: lineNum, col: col})
				}
				continue
			}

			// Single-character operators and punctuation
			var oneKind rbTokenKind
			oneFound := true
			switch ch {
			case ',':
				oneKind = rbTokComma
			case '.':
				oneKind = rbTokDot
			case ':':
				oneKind = rbTokColon
			case '=':
				oneKind = rbTokAssign
			case '<':
				oneKind = rbTokLt
			case '>':
				oneKind = rbTokGt
			case '+':
				oneKind = rbTokPlus
			case '-':
				oneKind = rbTokMinus
			case '*':
				oneKind = rbTokStar
			case '/':
				oneKind = rbTokSlash
			case '%':
				oneKind = rbTokPercent
			case '!':
				oneKind = rbTokBang
			case '~':
				oneKind = rbTokTilde
			case '&':
				oneKind = rbTokAmp
			case '|':
				oneKind = rbTokPipe
			case '^':
				oneKind = rbTokCaret
			case '?':
				oneKind = rbTokQuestion
			default:
				oneFound = false
			}
			if oneFound {
				tokens = append(tokens, rbToken{kind: oneKind, value: string(ch), line: lineNum, col: col})
				pos++
				continue
			}

			// Skip unknown characters
			pos++
		}

		// Emit NEWLINE at end of significant line (only if not inside parens)
		if parenDepth == 0 {
			tokens = append(tokens, rbToken{kind: rbTokNewline, value: "", line: lineNum, col: len(line) + 1})
		}
	}

	tokens = append(tokens, rbToken{kind: rbTokEOF, value: "", line: len(lines) + 1, col: 1})
	return tokens
}

func rbIsIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func rbIsIdentPart(ch byte) bool {
	return rbIsIdentStart(ch) || (ch >= '0' && ch <= '9')
}

// ---------------------------------------------------------------------------
// Snake-case to camelCase name conversion
// ---------------------------------------------------------------------------

// rbSpecialNames maps Ruby snake_case names to their Rúnar camelCase equivalents.
var rbSpecialNames = map[string]string{
	// Crypto builtins
	"check_sig":       "checkSig",
	"check_multi_sig": "checkMultiSig",
	"check_preimage":  "checkPreimage",

	// Post-quantum
	"verify_wots":               "verifyWOTS",
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
	"add_output":     "addOutput",
	"add_raw_output": "addRawOutput",
	"get_state_script": "getStateScript",

	// SHA-256 partial verification
	"sha256_compress": "sha256Compress",
	"sha256_finalize": "sha256Finalize",

	// Transaction intrinsics
	"extract_locktime":    "extractLocktime",
	"extract_output_hash": "extractOutputHash",
	"extract_sequence":    "extractSequence",
	"extract_version":     "extractVersion",
	"extract_amount":      "extractAmount",
	"extract_nsequence":   "extractNSequence",
	"extract_hash_prevouts": "extractHashPrevouts",
	"extract_hash_sequence": "extractHashSequence",
	"extract_outpoint":    "extractOutpoint",
	"extract_script_code": "extractScriptCode",
	"extract_input_index": "extractInputIndex",
	"extract_sig_hash_type": "extractSigHashType",
	"extract_outputs":     "extractOutputs",

	// Math builtins
	"mul_div":       "mulDiv",
	"percent_of":    "percentOf",
	"safe_div":      "safediv",
	"safe_mod":      "safemod",
	"div_mod":       "divmod",
	"reverse_bytes": "reverseBytes",

	// Hash builtins (pass through unchanged)
	"sha256":    "sha256",
	"ripemd160": "ripemd160",
	"hash160":   "hash160",
	"hash256":   "hash256",

	// Misc
	"num2bin": "num2bin",
	"bin2num": "bin2num",
	"log2":   "log2",
	"divmod": "divmod",

	// Trailing-underscore variants (avoid Ruby Kernel method clashes)
	"sign_": "sign",
	"pow_":  "pow",
	"sqrt_": "sqrt",
	"gcd_":  "gcd",
	"log2_": "log2",

	// EC constants
	"EC_P": "EC_P",
	"EC_N": "EC_N",
	"EC_G": "EC_G",
}

// rbConvertName converts a Ruby snake_case name to the Rúnar camelCase equivalent.
func rbConvertName(name string) string {
	// Check special names first
	if mapped, ok := rbSpecialNames[name]; ok {
		return mapped
	}

	// Names that pass through unchanged (no underscores)
	if !strings.Contains(name, "_") {
		return name
	}

	// Strip leading underscores so `_require_owner` becomes `requireOwner` not `RequireOwner`.
	stripped := strings.TrimLeft(name, "_")
	if stripped == "" {
		return name
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
		runes := []rune(part)
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes))
	}
	return b.String()
}

// rbMapType maps Ruby type names to Rúnar AST type names.
func rbMapType(name string) string {
	switch name {
	case "Bigint", "Integer", "Int":
		return "bigint"
	case "Boolean":
		return "boolean"
	case "ByteString":
		return "ByteString"
	case "PubKey":
		return "PubKey"
	case "Sig":
		return "Sig"
	case "Addr":
		return "Addr"
	case "Sha256":
		return "Sha256"
	case "Ripemd160":
		return "Ripemd160"
	case "SigHashPreimage":
		return "SigHashPreimage"
	case "RabinSig":
		return "RabinSig"
	case "RabinPubKey":
		return "RabinPubKey"
	case "Point":
		return "Point"
	default:
		return name
	}
}

func rbMakePrimitiveOrCustom(name string) TypeNode {
	if IsPrimitiveType(name) {
		return PrimitiveType{Name: name}
	}
	return CustomType{Name: name}
}

// ---------------------------------------------------------------------------
// Parser helpers
// ---------------------------------------------------------------------------

func (p *rbParser) peek() rbToken {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return rbToken{kind: rbTokEOF}
}

func (p *rbParser) advance() rbToken {
	tok := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

func (p *rbParser) expect(kind rbTokenKind) rbToken {
	tok := p.advance()
	if tok.kind != kind {
		p.addError(fmt.Sprintf("line %d: expected token kind %d, got %d (%q)", tok.line, kind, tok.kind, tok.value))
	}
	return tok
}

func (p *rbParser) check(kind rbTokenKind) bool {
	return p.peek().kind == kind
}

func (p *rbParser) checkIdent(value string) bool {
	tok := p.peek()
	return tok.kind == rbTokIdent && tok.value == value
}

func (p *rbParser) match(kind rbTokenKind) bool {
	if p.check(kind) {
		p.advance()
		return true
	}
	return false
}

func (p *rbParser) loc() SourceLocation {
	tok := p.peek()
	return SourceLocation{File: p.fileName, Line: tok.line, Column: tok.col}
}

// skipNewlines consumes consecutive NEWLINE tokens.
func (p *rbParser) skipNewlines() {
	for p.check(rbTokNewline) {
		p.advance()
	}
}

// ---------------------------------------------------------------------------
// Type parsing
// ---------------------------------------------------------------------------

func (p *rbParser) parseRbType() TypeNode {
	tok := p.advance()
	rawName := tok.value

	// Check for FixedArray[T, N] style generic
	if rawName == "FixedArray" && p.check(rbTokLBracket) {
		p.advance() // '['
		elemType := p.parseRbType()
		p.expect(rbTokComma)
		sizeTok := p.expect(rbTokNumber)
		size, err := strconv.Atoi(sizeTok.value)
		if err != nil || size < 0 {
			p.addError(fmt.Sprintf("line %d: FixedArray size must be a non-negative integer, got %q", sizeTok.line, sizeTok.value))
		}
		p.expect(rbTokRBracket)
		return FixedArrayType{Element: elemType, Length: size}
	}

	mapped := rbMapType(rawName)
	return rbMakePrimitiveOrCustom(mapped)
}

// ---------------------------------------------------------------------------
// Contract parsing
// ---------------------------------------------------------------------------

func (p *rbParser) parseContract() (*ContractNode, error) {
	p.skipNewlines()

	// Skip `require 'runar'` lines
	for p.check(rbTokRequire) {
		// Consume everything until end of line
		for !p.check(rbTokNewline) && !p.check(rbTokEOF) {
			p.advance()
		}
		p.skipNewlines()
	}

	// class Name < Runar::SmartContract
	if !p.check(rbTokClass) {
		return nil, fmt.Errorf("expected 'class' keyword")
	}
	p.advance() // 'class'

	nameTok := p.expect(rbTokIdent)
	contractName := nameTok.value

	// Expect `<`
	p.expect(rbTokLt)

	// Parse parent class: could be `Runar::SmartContract` or just `SmartContract`
	firstPart := p.advance() // ident (either 'Runar' or the class name directly)
	parentClass := firstPart.value
	if p.check(rbTokColonColon) {
		p.advance() // '::'
		classPart := p.advance()
		parentClass = classPart.value
	}

	if parentClass != "SmartContract" && parentClass != "StatefulSmartContract" {
		return nil, fmt.Errorf("unknown parent class: %s", parentClass)
	}

	p.skipNewlines()

	// Parse class body until `end`
	var properties []PropertyNode
	var constructor *MethodNode
	var methods []MethodNode

	// Pending visibility/param types for the next method
	var pendingVisibility string          // "public" or ""
	var pendingParamTypes map[string]TypeNode

	for !p.check(rbTokEnd) && !p.check(rbTokEOF) {
		p.skipNewlines()
		if p.check(rbTokEnd) || p.check(rbTokEOF) {
			break
		}

		// `prop :name, Type [, readonly: true]`
		if p.checkIdent("prop") {
			prop := p.parseProp(parentClass)
			if prop != nil {
				properties = append(properties, *prop)
			}
			p.skipNewlines()
			continue
		}

		// `runar_public [key: Type, ...]`
		if p.checkIdent("runar_public") {
			p.advance() // 'runar_public'
			pendingVisibility = "public"
			pendingParamTypes = p.parseOptionalParamTypes()
			p.skipNewlines()
			continue
		}

		// `params key: Type, ...`
		if p.checkIdent("params") {
			p.advance() // 'params'
			pendingParamTypes = p.parseOptionalParamTypes()
			p.skipNewlines()
			continue
		}

		// Method definition
		if p.check(rbTokDef) {
			method := p.parseMethod(pendingVisibility, pendingParamTypes)
			if method.Name == "constructor" {
				constructor = &method
			} else {
				methods = append(methods, method)
			}
			pendingVisibility = ""
			pendingParamTypes = nil
			p.skipNewlines()
			continue
		}

		// Skip unknown tokens
		p.advance()
	}

	p.match(rbTokEnd) // end of class

	// Auto-generate constructor if not provided
	if constructor == nil {
		ctor := p.autoGenerateConstructor(properties)
		constructor = &ctor
	}

	// Back-fill constructor param types from prop declarations.
	// In Ruby, `def initialize(pub_key_hash)` has no type annotations —
	// we infer them from the matching `prop :pub_key_hash, Addr` declarations.
	propTypeMap := make(map[string]TypeNode)
	for _, prop := range properties {
		propTypeMap[prop.Name] = prop.Type
	}
	for i := range constructor.Params {
		if ct, ok := constructor.Params[i].Type.(CustomType); ok && ct.Name == "unknown" {
			if pt, found := propTypeMap[constructor.Params[i].Name]; found {
				constructor.Params[i].Type = pt
			}
		}
	}

	// Convert bare calls to declared methods into this.method() calls.
	// In Ruby, `compute_threshold(a, b)` is equivalent to `self.compute_threshold(a, b)`.
	methodNames := make(map[string]bool)
	for _, m := range methods {
		methodNames[m.Name] = true
	}
	for i := range methods {
		rewriteBareMethodCallsGo(methods[i].Body, methodNames)
	}

	// Convert implicit returns in private methods: in Ruby, the last
	// expression in a method body is its return value.
	for i := range methods {
		if methods[i].Visibility == "private" && len(methods[i].Body) > 0 {
			last := methods[i].Body[len(methods[i].Body)-1]
			if es, ok := last.(ExpressionStmt); ok {
				methods[i].Body[len(methods[i].Body)-1] = ReturnStmt{
					Value:          es.Expr,
					SourceLocation: es.SourceLocation,
				}
			}
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

// parseOptionalParamTypes parses optional key: Type pairs after `runar_public` or `params`.
// Returns nil if there are no pairs (just a bare keyword).
func (p *rbParser) parseOptionalParamTypes() map[string]TypeNode {
	// If the next token is NEWLINE or eof or def, there are no param types
	if p.check(rbTokNewline) || p.check(rbTokEOF) || p.check(rbTokDef) {
		return nil
	}

	paramTypes := make(map[string]TypeNode)

	// Parse key: Type pairs
	for !p.check(rbTokNewline) && !p.check(rbTokEOF) {
		// Expect ident (param name)
		nameTok := p.advance()
		rawName := nameTok.value

		// Expect ':'
		p.expect(rbTokColon)

		// Parse type
		typeNode := p.parseRbType()

		paramTypes[rawName] = typeNode

		// Optional comma
		if !p.match(rbTokComma) {
			break
		}
	}

	if len(paramTypes) == 0 {
		return nil
	}
	return paramTypes
}

// ---------------------------------------------------------------------------
// Property parsing
// ---------------------------------------------------------------------------

func (p *rbParser) parseProp(parentClass string) *PropertyNode {
	loc := p.loc()
	p.advance() // 'prop'

	// Expect symbol :name
	if !p.check(rbTokSymbol) {
		p.addError(fmt.Sprintf("line %d: expected symbol after 'prop', got %q", p.peek().line, p.peek().value))
		// Skip to end of line
		for !p.check(rbTokNewline) && !p.check(rbTokEOF) {
			p.advance()
		}
		return nil
	}

	rawName := p.advance().value // symbol value (without colon)
	p.expect(rbTokComma)

	// Parse type
	typeNode := p.parseRbType()

	// Check for optional trailing options: readonly: true/false, default: <literal>
	// Multiple options are comma-separated and may appear in any order.
	isReadonly := false
	var initializer Expression
	for p.check(rbTokComma) {
		p.advance() // ','
		if p.checkIdent("readonly") {
			p.advance() // 'readonly'
			p.expect(rbTokColon)
			if p.check(rbTokTrue) {
				p.advance()
				isReadonly = true
			} else if p.check(rbTokFalse) {
				p.advance()
				isReadonly = false
			}
		} else if p.checkIdent("default") {
			p.advance() // 'default'
			p.expect(rbTokColon)
			initializer = p.parseUnary()
		} else {
			// Unknown trailing option -- stop parsing options
			break
		}
	}

	// In stateless contracts, all properties are readonly
	if parentClass == "SmartContract" {
		isReadonly = true
	}

	// Skip rest of line
	for !p.check(rbTokNewline) && !p.check(rbTokEOF) {
		p.advance()
	}

	return &PropertyNode{
		Name:           rbConvertName(rawName),
		Type:           typeNode,
		Readonly:       isReadonly,
		Initializer:    initializer,
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// Method parsing
// ---------------------------------------------------------------------------

func (p *rbParser) parseMethod(pendingVisibility string, pendingParamTypes map[string]TypeNode) MethodNode {
	loc := p.loc()
	p.expect(rbTokDef)

	nameTok := p.advance()
	rawName := nameTok.value

	// Reset local variable tracking for this method scope
	p.declaredLocals = make(map[string]bool)

	// Parse parameters (optional parentheses for no-arg methods)
	var params []ParamNode
	if p.check(rbTokLParen) {
		p.advance() // '('
		params = p.parseParams(pendingParamTypes)
		p.expect(rbTokRParen)
	}

	p.skipNewlines()

	// Parse body until 'end'
	body := p.parseStatements()

	p.expect(rbTokEnd)

	// Determine if this is the constructor
	if rawName == "initialize" {
		return MethodNode{
			Name:           "constructor",
			Params:         params,
			Body:           body,
			Visibility:     "public",
			SourceLocation: loc,
		}
	}

	isPublic := pendingVisibility == "public"
	methodName := rbConvertName(rawName)

	visibility := "private"
	if isPublic {
		visibility = "public"
	}

	return MethodNode{
		Name:           methodName,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SourceLocation: loc,
	}
}

func (p *rbParser) parseParams(paramTypes map[string]TypeNode) []ParamNode {
	var params []ParamNode

	for !p.check(rbTokRParen) && !p.check(rbTokEOF) {
		nameTok := p.advance()
		rawName := nameTok.value
		camelName := rbConvertName(rawName)

		// Look up the type from the preceding runar_public/params declaration
		var typeNode TypeNode
		if paramTypes != nil {
			typeNode = paramTypes[rawName]
		}
		if typeNode == nil {
			typeNode = CustomType{Name: "unknown"}
		}

		params = append(params, ParamNode{
			Name: camelName,
			Type: typeNode,
		})

		if !p.match(rbTokComma) {
			break
		}
	}

	return params
}

func (p *rbParser) autoGenerateConstructor(properties []PropertyNode) MethodNode {
	// Properties with initializers do not need constructor parameters.
	var requiredProps []PropertyNode
	for _, prop := range properties {
		if prop.Initializer == nil {
			requiredProps = append(requiredProps, prop)
		}
	}

	params := make([]ParamNode, len(requiredProps))
	for i, prop := range requiredProps {
		params[i] = ParamNode{
			Name: prop.Name,
			Type: prop.Type,
		}
	}

	superArgs := make([]Expression, len(params))
	for i, param := range params {
		superArgs[i] = Identifier{Name: param.Name}
	}

	superCall := ExpressionStmt{
		Expr: CallExpr{
			Callee: Identifier{Name: "super"},
			Args:   superArgs,
		},
		SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
	}

	var body []Statement
	body = append(body, superCall)

	for _, prop := range requiredProps {
		body = append(body, AssignmentStmt{
			Target: PropertyAccessExpr{Property: prop.Name},
			Value:  Identifier{Name: prop.Name},
			SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
		})
	}

	return MethodNode{
		Name:           "constructor",
		Params:         params,
		Body:           body,
		Visibility:     "public",
		SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
	}
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

func (p *rbParser) parseStatements() []Statement {
	var stmts []Statement

	for !p.check(rbTokEnd) && !p.check(rbTokElsif) &&
		!p.check(rbTokElse) && !p.check(rbTokEOF) {
		p.skipNewlines()
		if p.check(rbTokEnd) || p.check(rbTokElsif) ||
			p.check(rbTokElse) || p.check(rbTokEOF) {
			break
		}

		stmt := p.parseStatement()
		if stmt != nil {
			stmts = append(stmts, stmt)
		}
		p.skipNewlines()
	}

	return stmts
}

func (p *rbParser) parseStatement() Statement {
	loc := p.loc()

	// assert statement: assert expr
	if p.check(rbTokAssert) {
		return p.parseAssertStatement(loc)
	}

	// if statement
	if p.check(rbTokIf) {
		return p.parseIfStatement(loc)
	}

	// unless statement
	if p.check(rbTokUnless) {
		return p.parseUnlessStatement(loc)
	}

	// for statement
	if p.check(rbTokFor) {
		return p.parseForStatement(loc)
	}

	// return statement
	if p.check(rbTokReturn) {
		return p.parseReturnStatement(loc)
	}

	// super(args...) — parse as part of constructor
	if p.check(rbTokSuper) {
		return p.parseSuperCall(loc)
	}

	// Instance variable assignment: @var = expr, @var += expr
	if p.check(rbTokIvar) {
		return p.parseIvarStatement(loc)
	}

	// Variable declaration or expression statement starting with ident
	if p.check(rbTokIdent) {
		return p.parseIdentStatement(loc)
	}

	// Skip unknown
	p.advance()
	return nil
}

func (p *rbParser) parseAssertStatement(loc SourceLocation) Statement {
	p.advance() // 'assert'

	// Support both `assert expr` and `assert(expr)`
	if p.check(rbTokLParen) {
		p.advance()
		expr := p.parseExpression()
		p.expect(rbTokRParen)
		return ExpressionStmt{
			Expr:           CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{expr}},
			SourceLocation: loc,
		}
	}

	expr := p.parseExpression()
	return ExpressionStmt{
		Expr:           CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{expr}},
		SourceLocation: loc,
	}
}

func (p *rbParser) parseIfStatement(loc SourceLocation) Statement {
	p.advance() // 'if'
	condition := p.parseExpression()
	p.match(rbTokNewline)
	p.skipNewlines()

	thenBranch := p.parseStatements()

	var elseBranch []Statement

	if p.check(rbTokElsif) {
		elifLoc := p.loc()
		elseBranch = []Statement{p.parseElsifStatement(elifLoc)}
	} else if p.check(rbTokElse) {
		p.advance() // 'else'
		p.skipNewlines()
		elseBranch = p.parseStatements()
	}

	p.expect(rbTokEnd)

	return IfStmt{
		Condition:      condition,
		Then:           thenBranch,
		Else:           elseBranch,
		SourceLocation: loc,
	}
}

func (p *rbParser) parseElsifStatement(loc SourceLocation) Statement {
	p.advance() // 'elsif'
	condition := p.parseExpression()
	p.skipNewlines()

	thenBranch := p.parseStatements()

	var elseBranch []Statement

	if p.check(rbTokElsif) {
		elifLoc := p.loc()
		elseBranch = []Statement{p.parseElsifStatement(elifLoc)}
	} else if p.check(rbTokElse) {
		p.advance() // 'else'
		p.skipNewlines()
		elseBranch = p.parseStatements()
	}

	// Note: the outer `end` is consumed by the parent parseIfStatement
	// elsif branches do not consume their own `end`

	return IfStmt{
		Condition:      condition,
		Then:           thenBranch,
		Else:           elseBranch,
		SourceLocation: loc,
	}
}

func (p *rbParser) parseUnlessStatement(loc SourceLocation) Statement {
	p.advance() // 'unless'
	rawCondition := p.parseExpression()
	p.skipNewlines()

	body := p.parseStatements()

	p.expect(rbTokEnd)

	// Unless is if with negated condition
	condition := UnaryExpr{Op: "!", Operand: rawCondition}

	return IfStmt{
		Condition:      condition,
		Then:           body,
		SourceLocation: loc,
	}
}

func (p *rbParser) parseForStatement(loc SourceLocation) Statement {
	p.advance() // 'for'

	iterVar := p.advance() // loop variable
	varName := rbConvertName(iterVar.value)

	p.expect(rbTokIn)

	// Parse start expression
	startExpr := p.parseExpression()

	// Expect range operator: .. (inclusive) or ... (exclusive)
	isExclusive := false
	if p.check(rbTokDotDotDot) {
		isExclusive = true
		p.advance()
	} else if p.check(rbTokDotDot) {
		isExclusive = false
		p.advance()
	} else {
		p.addError(fmt.Sprintf("line %d: expected range operator '..' or '...' in for loop", p.peek().line))
	}

	endExpr := p.parseExpression()

	// Optional 'do' keyword
	p.match(rbTokDo)
	p.skipNewlines()

	body := p.parseStatements()
	p.expect(rbTokEnd)

	// Construct a C-style for loop AST node
	op := "<="
	if isExclusive {
		op = "<"
	}

	initStmt := VariableDeclStmt{
		Name:           varName,
		Type:           PrimitiveType{Name: "bigint"},
		Mutable:        true,
		Init:           startExpr,
		SourceLocation: loc,
	}

	condition := BinaryExpr{
		Op:    op,
		Left:  Identifier{Name: varName},
		Right: endExpr,
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

func (p *rbParser) parseReturnStatement(loc SourceLocation) Statement {
	p.advance() // 'return'
	var value Expression
	if !p.check(rbTokNewline) && !p.check(rbTokEnd) && !p.check(rbTokEOF) {
		value = p.parseExpression()
	}
	return ReturnStmt{Value: value, SourceLocation: loc}
}

func (p *rbParser) parseSuperCall(loc SourceLocation) Statement {
	p.advance() // 'super'
	p.expect(rbTokLParen)
	var args []Expression
	for !p.check(rbTokRParen) && !p.check(rbTokEOF) {
		args = append(args, p.parseExpression())
		if !p.match(rbTokComma) {
			break
		}
	}
	p.expect(rbTokRParen)

	return ExpressionStmt{
		Expr: CallExpr{
			Callee: Identifier{Name: "super"},
			Args:   args,
		},
		SourceLocation: loc,
	}
}

func (p *rbParser) parseIvarStatement(loc SourceLocation) Statement {
	ivarTok := p.advance() // ivar token
	rawName := ivarTok.value
	propName := rbConvertName(rawName)
	target := PropertyAccessExpr{Property: propName}

	// Simple assignment: @var = expr
	if p.match(rbTokAssign) {
		value := p.parseExpression()
		return AssignmentStmt{Target: target, Value: value, SourceLocation: loc}
	}

	// Compound assignment: @var += expr, etc.
	compoundOps := map[rbTokenKind]string{
		rbTokPlusEq:    "+",
		rbTokMinusEq:   "-",
		rbTokStarEq:    "*",
		rbTokSlashEq:   "/",
		rbTokPercentEq: "%",
	}

	for kind, binOp := range compoundOps {
		if p.match(kind) {
			right := p.parseExpression()
			value := BinaryExpr{Op: binOp, Left: target, Right: right}
			return AssignmentStmt{Target: target, Value: value, SourceLocation: loc}
		}
	}

	// Expression statement (e.g. @var.method(...))
	var expr Expression = target
	expr = p.parsePostfixFrom(expr)

	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

func (p *rbParser) parseIdentStatement(loc SourceLocation) Statement {
	nameTok := p.peek()
	rawName := nameTok.value

	// Check for simple name = expr pattern (variable declaration or assignment)
	if p.pos+1 < len(p.tokens) && p.tokens[p.pos+1].kind == rbTokAssign {
		p.advance() // consume ident
		p.advance() // consume '='
		value := p.parseExpression()
		camelName := rbConvertName(rawName)

		if p.declaredLocals[camelName] {
			// Already declared: this is an assignment
			return AssignmentStmt{
				Target:         Identifier{Name: camelName},
				Value:          value,
				SourceLocation: loc,
			}
		}
		// First assignment: variable declaration
		p.declaredLocals[camelName] = true
		return VariableDeclStmt{
			Name:           camelName,
			Mutable:        true,
			Init:           value,
			SourceLocation: loc,
		}
	}

	// Parse as expression first
	expr := p.parseExpression()

	// Simple assignment (e.g. a.b = expr)
	if p.match(rbTokAssign) {
		value := p.parseExpression()
		return AssignmentStmt{Target: expr, Value: value, SourceLocation: loc}
	}

	// Compound assignment
	compoundOps := map[rbTokenKind]string{
		rbTokPlusEq:    "+",
		rbTokMinusEq:   "-",
		rbTokStarEq:    "*",
		rbTokSlashEq:   "/",
		rbTokPercentEq: "%",
	}

	for kind, binOp := range compoundOps {
		if p.match(kind) {
			right := p.parseExpression()
			value := BinaryExpr{Op: binOp, Left: expr, Right: right}
			return AssignmentStmt{Target: expr, Value: value, SourceLocation: loc}
		}
	}

	// Expression statement
	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// Expression parsing (precedence climbing)
// ---------------------------------------------------------------------------

func (p *rbParser) parseExpression() Expression {
	return p.parseTernary()
}

// Ruby ternary: condition ? consequent : alternate
func (p *rbParser) parseTernary() Expression {
	expr := p.parseOr()

	if p.match(rbTokQuestion) {
		consequent := p.parseExpression()
		p.expect(rbTokColon)
		alternate := p.parseExpression()
		return TernaryExpr{
			Condition:  expr,
			Consequent: consequent,
			Alternate:  alternate,
		}
	}

	return expr
}

func (p *rbParser) parseOr() Expression {
	left := p.parseAnd()
	for p.match(rbTokOr) || p.match(rbTokPipePipe) {
		right := p.parseAnd()
		left = BinaryExpr{Op: "||", Left: left, Right: right}
	}
	return left
}

func (p *rbParser) parseAnd() Expression {
	left := p.parseNot()
	for p.match(rbTokAnd) || p.match(rbTokAmpAmp) {
		right := p.parseNot()
		left = BinaryExpr{Op: "&&", Left: left, Right: right}
	}
	return left
}

func (p *rbParser) parseNot() Expression {
	if p.match(rbTokNot) || p.match(rbTokBang) {
		operand := p.parseNot()
		return UnaryExpr{Op: "!", Operand: operand}
	}
	return p.parseBitwiseOr()
}

func (p *rbParser) parseBitwiseOr() Expression {
	left := p.parseBitwiseXor()
	for p.match(rbTokPipe) {
		right := p.parseBitwiseXor()
		left = BinaryExpr{Op: "|", Left: left, Right: right}
	}
	return left
}

func (p *rbParser) parseBitwiseXor() Expression {
	left := p.parseBitwiseAnd()
	for p.match(rbTokCaret) {
		right := p.parseBitwiseAnd()
		left = BinaryExpr{Op: "^", Left: left, Right: right}
	}
	return left
}

func (p *rbParser) parseBitwiseAnd() Expression {
	left := p.parseEquality()
	for p.match(rbTokAmp) {
		right := p.parseEquality()
		left = BinaryExpr{Op: "&", Left: left, Right: right}
	}
	return left
}

func (p *rbParser) parseEquality() Expression {
	left := p.parseComparison()
	for {
		if p.match(rbTokEqEq) {
			right := p.parseComparison()
			left = BinaryExpr{Op: "===", Left: left, Right: right} // Map == to ===
		} else if p.match(rbTokNotEq) {
			right := p.parseComparison()
			left = BinaryExpr{Op: "!==", Left: left, Right: right} // Map != to !==
		} else {
			break
		}
	}
	return left
}

func (p *rbParser) parseComparison() Expression {
	left := p.parseShift()
	for {
		if p.match(rbTokLt) {
			right := p.parseShift()
			left = BinaryExpr{Op: "<", Left: left, Right: right}
		} else if p.match(rbTokLtEq) {
			right := p.parseShift()
			left = BinaryExpr{Op: "<=", Left: left, Right: right}
		} else if p.match(rbTokGt) {
			right := p.parseShift()
			left = BinaryExpr{Op: ">", Left: left, Right: right}
		} else if p.match(rbTokGtEq) {
			right := p.parseShift()
			left = BinaryExpr{Op: ">=", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *rbParser) parseShift() Expression {
	left := p.parseAdditive()
	for {
		if p.match(rbTokLShift) {
			right := p.parseAdditive()
			left = BinaryExpr{Op: "<<", Left: left, Right: right}
		} else if p.match(rbTokRShift) {
			right := p.parseAdditive()
			left = BinaryExpr{Op: ">>", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *rbParser) parseAdditive() Expression {
	left := p.parseMultiplicative()
	for {
		if p.match(rbTokPlus) {
			right := p.parseMultiplicative()
			left = BinaryExpr{Op: "+", Left: left, Right: right}
		} else if p.match(rbTokMinus) {
			right := p.parseMultiplicative()
			left = BinaryExpr{Op: "-", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *rbParser) parseMultiplicative() Expression {
	left := p.parseUnary()
	for {
		if p.match(rbTokStar) {
			right := p.parseUnary()
			left = BinaryExpr{Op: "*", Left: left, Right: right}
		} else if p.match(rbTokSlash) {
			right := p.parseUnary()
			left = BinaryExpr{Op: "/", Left: left, Right: right}
		} else if p.match(rbTokPercent) {
			right := p.parseUnary()
			left = BinaryExpr{Op: "%", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *rbParser) parseUnary() Expression {
	if p.match(rbTokMinus) {
		operand := p.parseUnary()
		return UnaryExpr{Op: "-", Operand: operand}
	}
	if p.match(rbTokTilde) {
		operand := p.parseUnary()
		return UnaryExpr{Op: "~", Operand: operand}
	}
	if p.match(rbTokBang) {
		operand := p.parseUnary()
		return UnaryExpr{Op: "!", Operand: operand}
	}
	return p.parsePower()
}

// parsePower handles ** (right-associative, maps to pow() call)
func (p *rbParser) parsePower() Expression {
	base := p.parsePostfix()
	if p.match(rbTokStarStar) {
		exp := p.parsePower() // right-recursive for right-associativity
		return CallExpr{Callee: Identifier{Name: "pow"}, Args: []Expression{base, exp}}
	}
	return base
}

func (p *rbParser) parsePostfix() Expression {
	expr := p.parsePrimary()
	return p.parsePostfixFrom(expr)
}

// parsePostfixFrom parses postfix operations (method calls, property access, indexing) from a given expression.
func (p *rbParser) parsePostfixFrom(expr Expression) Expression {
	for {
		// Method call or property access: expr.name or expr.name(...)
		if p.match(rbTokDot) {
			propTok := p.advance()
			propName := rbConvertName(propTok.value)

			// Check if it is a method call
			if p.check(rbTokLParen) {
				args := p.parseCallArgs()
				expr = CallExpr{
					Callee: MemberExpr{Object: expr, Property: propName},
					Args:   args,
				}
			} else {
				// Property access
				expr = MemberExpr{Object: expr, Property: propName}
			}
			continue
		}

		// Function call: expr(...)
		if p.check(rbTokLParen) {
			args := p.parseCallArgs()
			expr = CallExpr{Callee: expr, Args: args}
			continue
		}

		// Index access: expr[index]
		if p.match(rbTokLBracket) {
			index := p.parseExpression()
			p.expect(rbTokRBracket)
			expr = IndexAccessExpr{Object: expr, Index: index}
			continue
		}

		break
	}

	return expr
}

func (p *rbParser) parsePrimary() Expression {
	tok := p.peek()

	// Number literal
	if tok.kind == rbTokNumber {
		p.advance()
		return p.parseRbNumber(tok.value)
	}

	// Boolean literals
	if tok.kind == rbTokTrue {
		p.advance()
		return BoolLiteral{Value: true}
	}
	if tok.kind == rbTokFalse {
		p.advance()
		return BoolLiteral{Value: false}
	}

	// Hex string literal (single-quoted)
	if tok.kind == rbTokHexString {
		p.advance()
		return ByteStringLiteral{Value: tok.value}
	}

	// String literal (double-quoted)
	if tok.kind == rbTokString {
		p.advance()
		return ByteStringLiteral{Value: tok.value}
	}

	// nil -> 0
	if tok.kind == rbTokNil {
		p.advance()
		return BigIntLiteral{Value: 0}
	}

	// Instance variable: @var -> property access
	if tok.kind == rbTokIvar {
		p.advance()
		propName := rbConvertName(tok.value)
		return PropertyAccessExpr{Property: propName}
	}

	// Parenthesised expression
	if tok.kind == rbTokLParen {
		p.advance()
		expr := p.parseExpression()
		p.expect(rbTokRParen)
		return expr
	}

	// Array literal: [elem, ...]
	if tok.kind == rbTokLBracket {
		p.advance()
		var elements []Expression
		for !p.check(rbTokRBracket) && !p.check(rbTokEOF) {
			elements = append(elements, p.parseExpression())
			if !p.match(rbTokComma) {
				break
			}
		}
		p.expect(rbTokRBracket)
		return ArrayLiteralExpr{Elements: elements}
	}

	// super keyword
	if tok.kind == rbTokSuper {
		p.advance()
		return Identifier{Name: "super"}
	}

	// assert as identifier (for assert in expressions)
	if tok.kind == rbTokAssert {
		p.advance()
		return Identifier{Name: "assert"}
	}

	// Identifier or function call
	if tok.kind == rbTokIdent {
		p.advance()
		rawName := tok.value
		name := rbConvertName(rawName)

		// Function call
		if p.check(rbTokLParen) {
			args := p.parseCallArgs()
			return CallExpr{Callee: Identifier{Name: name}, Args: args}
		}

		return Identifier{Name: name}
	}

	p.addError(fmt.Sprintf("line %d: unexpected token %q", tok.line, tok.value))
	p.advance()
	return BigIntLiteral{Value: 0}
}

func (p *rbParser) parseCallArgs() []Expression {
	p.expect(rbTokLParen)
	var args []Expression
	for !p.check(rbTokRParen) && !p.check(rbTokEOF) {
		arg := p.parseExpression()
		args = append(args, arg)
		if !p.match(rbTokComma) {
			break
		}
	}
	p.expect(rbTokRParen)
	return args
}

func (p *rbParser) parseRbNumber(s string) Expression {
	val, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		p.addError(fmt.Sprintf("line %d: invalid number literal %q: %v", p.peek().line, s, err))
		return BigIntLiteral{Value: 0}
	}
	return BigIntLiteral{Value: val}
}

// Ensure the unicode import is used
var _ = unicode.ToUpper

// rewriteBareMethodCallsGo converts bare function calls to declared contract methods
// into this.method() calls (PropertyAccessExpr as callee).
func rewriteBareMethodCallsGo(stmts []Statement, methodNames map[string]bool) {
	for i := range stmts {
		rewriteStmtGo(&stmts[i], methodNames)
	}
}

func rewriteExprGo(expr Expression, methodNames map[string]bool) Expression {
	switch e := expr.(type) {
	case CallExpr:
		for i := range e.Args {
			e.Args[i] = rewriteExprGo(e.Args[i], methodNames)
		}
		if ident, ok := e.Callee.(Identifier); ok {
			if methodNames[ident.Name] {
				e.Callee = PropertyAccessExpr{Property: ident.Name}
			}
		} else {
			e.Callee = rewriteExprGo(e.Callee, methodNames)
		}
		return e
	case BinaryExpr:
		e.Left = rewriteExprGo(e.Left, methodNames)
		e.Right = rewriteExprGo(e.Right, methodNames)
		return e
	case UnaryExpr:
		e.Operand = rewriteExprGo(e.Operand, methodNames)
		return e
	case TernaryExpr:
		e.Condition = rewriteExprGo(e.Condition, methodNames)
		e.Consequent = rewriteExprGo(e.Consequent, methodNames)
		e.Alternate = rewriteExprGo(e.Alternate, methodNames)
		return e
	}
	return expr
}

func rewriteStmtGo(stmt *Statement, methodNames map[string]bool) {
	switch s := (*stmt).(type) {
	case ExpressionStmt:
		s.Expr = rewriteExprGo(s.Expr, methodNames)
		*stmt = s
	case VariableDeclStmt:
		s.Init = rewriteExprGo(s.Init, methodNames)
		*stmt = s
	case AssignmentStmt:
		s.Value = rewriteExprGo(s.Value, methodNames)
		*stmt = s
	case ReturnStmt:
		if s.Value != nil {
			val := rewriteExprGo(s.Value, methodNames)
			s.Value = val
			*stmt = s
		}
	case IfStmt:
		s.Condition = rewriteExprGo(s.Condition, methodNames)
		rewriteBareMethodCallsGo(s.Then, methodNames)
		rewriteBareMethodCallsGo(s.Else, methodNames)
		*stmt = s
	case ForStmt:
		rewriteBareMethodCallsGo(s.Body, methodNames)
		*stmt = s
	}
}
