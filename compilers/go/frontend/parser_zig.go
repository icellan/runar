package frontend

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParseZig parses a Zig-syntax Rúnar contract (.runar.zig) and produces
// the standard AST.
func ParseZig(source []byte, fileName string) *ParseResult {
	p := &zigParser{
		fileName:             fileName,
		selfNames:            make(map[string]bool),
		statefulContextNames: make(map[string]bool),
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

type zigTokenKind int

const (
	zigTokEOF zigTokenKind = iota
	zigTokIdent
	zigTokNumber
	zigTokString
	// Delimiters
	zigTokLParen    // (
	zigTokRParen    // )
	zigTokLBrace    // {
	zigTokRBrace    // }
	zigTokLBracket  // [
	zigTokRBracket  // ]
	zigTokSemicolon // ;
	zigTokComma     // ,
	zigTokDot       // .
	zigTokColon     // :
	zigTokAt        // @
	// Operators
	zigTokPlus    // +
	zigTokMinus   // -
	zigTokStar    // *
	zigTokSlash   // /
	zigTokPercent // %
	zigTokBang    // !
	zigTokTilde   // ~
	zigTokAmp     // &
	zigTokPipe    // |
	zigTokCaret   // ^
	zigTokAssign  // =
	zigTokLt      // <
	zigTokGt      // >
	// Two-character operators
	zigTokEqEq      // ==
	zigTokNotEq     // !=
	zigTokLtEq      // <=
	zigTokGtEq      // >=
	zigTokLShift    // <<
	zigTokRShift    // >>
	zigTokAmpAmp    // &&
	zigTokPipePipe  // ||
	zigTokPlusEq    // +=
	zigTokMinusEq   // -=
	zigTokStarEq    // *=
	zigTokSlashEq   // /=
	zigTokPercentEq // %=
	// Keywords
	zigTokPub
	zigTokConst
	zigTokVar
	zigTokFn
	zigTokStruct
	zigTokIf
	zigTokElse
	zigTokFor
	zigTokWhile
	zigTokReturn
	zigTokTrue
	zigTokFalse
	zigTokVoid
)

type zigToken struct {
	kind  zigTokenKind
	value string
	line  int
	col   int
}

// ---------------------------------------------------------------------------
// Parser struct
// ---------------------------------------------------------------------------

type zigParser struct {
	fileName             string
	tokens               []zigToken
	pos                  int
	errors               []Diagnostic
	contractName         string
	parentClass          string
	selfNames            map[string]bool
	statefulContextNames map[string]bool
}

func (p *zigParser) addError(msg string) {
	p.errors = append(p.errors, Diagnostic{Message: msg, Severity: SeverityError})
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

var zigKeywords = map[string]zigTokenKind{
	"pub":    zigTokPub,
	"const":  zigTokConst,
	"var":    zigTokVar,
	"fn":     zigTokFn,
	"struct": zigTokStruct,
	"if":     zigTokIf,
	"else":   zigTokElse,
	"for":    zigTokFor,
	"while":  zigTokWhile,
	"return": zigTokReturn,
	"true":   zigTokTrue,
	"false":  zigTokFalse,
	"void":   zigTokVoid,
	"and":    zigTokAmpAmp,
	"or":     zigTokPipePipe,
}

func (p *zigParser) tokenize(source string) []zigToken {
	var tokens []zigToken
	pos := 0
	line := 1
	col := 1

	advance := func() byte {
		ch := source[pos]
		pos++
		if ch == '\n' {
			line++
			col = 1
		} else {
			col++
		}
		return ch
	}

	peek := func() byte {
		if pos >= len(source) {
			return 0
		}
		return source[pos]
	}

	peekN := func(n int) byte {
		if pos+n >= len(source) {
			return 0
		}
		return source[pos+n]
	}

	add := func(kind zigTokenKind, value string, tokenLine, tokenCol int) {
		tokens = append(tokens, zigToken{kind: kind, value: value, line: tokenLine, col: tokenCol})
	}

	for pos < len(source) {
		ch := peek()
		tokenLine := line
		tokenCol := col

		// Whitespace
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			advance()
			continue
		}

		// Line comment: //
		if ch == '/' && peekN(1) == '/' {
			for pos < len(source) && peek() != '\n' {
				advance()
			}
			continue
		}

		// Block comment: /* ... */
		if ch == '/' && peekN(1) == '*' {
			advance()
			advance()
			for pos < len(source)-1 {
				if peek() == '*' && peekN(1) == '/' {
					advance()
					advance()
					break
				}
				advance()
			}
			continue
		}

		// Two-character operators
		if pos+1 < len(source) {
			two := string(source[pos : pos+2])
			var twoKind zigTokenKind
			found := true
			switch two {
			case "==":
				twoKind = zigTokEqEq
			case "!=":
				twoKind = zigTokNotEq
			case "<=":
				twoKind = zigTokLtEq
			case ">=":
				twoKind = zigTokGtEq
			case "<<":
				twoKind = zigTokLShift
			case ">>":
				twoKind = zigTokRShift
			case "&&":
				twoKind = zigTokAmpAmp
			case "||":
				twoKind = zigTokPipePipe
			case "+=":
				twoKind = zigTokPlusEq
			case "-=":
				twoKind = zigTokMinusEq
			case "*=":
				twoKind = zigTokStarEq
			case "/=":
				twoKind = zigTokSlashEq
			case "%=":
				twoKind = zigTokPercentEq
			default:
				found = false
			}
			if found {
				advance()
				advance()
				add(twoKind, two, tokenLine, tokenCol)
				continue
			}
		}

		// Single-character operators and delimiters
		var oneKind zigTokenKind
		oneFound := true
		switch ch {
		case '(':
			oneKind = zigTokLParen
		case ')':
			oneKind = zigTokRParen
		case '{':
			oneKind = zigTokLBrace
		case '}':
			oneKind = zigTokRBrace
		case '[':
			oneKind = zigTokLBracket
		case ']':
			oneKind = zigTokRBracket
		case ';':
			oneKind = zigTokSemicolon
		case ',':
			oneKind = zigTokComma
		case '.':
			oneKind = zigTokDot
		case ':':
			oneKind = zigTokColon
		case '@':
			oneKind = zigTokAt
		case '+':
			oneKind = zigTokPlus
		case '-':
			oneKind = zigTokMinus
		case '*':
			oneKind = zigTokStar
		case '/':
			oneKind = zigTokSlash
		case '%':
			oneKind = zigTokPercent
		case '!':
			oneKind = zigTokBang
		case '~':
			oneKind = zigTokTilde
		case '&':
			oneKind = zigTokAmp
		case '|':
			oneKind = zigTokPipe
		case '^':
			oneKind = zigTokCaret
		case '=':
			oneKind = zigTokAssign
		case '<':
			oneKind = zigTokLt
		case '>':
			oneKind = zigTokGt
		default:
			oneFound = false
		}
		if oneFound {
			advance()
			add(oneKind, string(ch), tokenLine, tokenCol)
			continue
		}

		// String literals: "..."
		if ch == '"' {
			advance() // skip opening quote
			val := ""
			for pos < len(source) && peek() != '"' {
				if peek() == '\\' && pos+1 < len(source) {
					advance() // skip backslash
					val += string(advance())
				} else {
					val += string(advance())
				}
			}
			if pos < len(source) {
				advance() // skip closing quote
			}
			add(zigTokString, val, tokenLine, tokenCol)
			continue
		}

		// Numbers (decimal and hex)
		if ch >= '0' && ch <= '9' {
			num := ""
			if ch == '0' && pos+1 < len(source) && (source[pos+1] == 'x' || source[pos+1] == 'X') {
				num = "0x"
				advance() // '0'
				advance() // 'x'
				for pos < len(source) && (isHexDigit(peek()) || peek() == '_') {
					if peek() != '_' {
						num += string(peek())
					}
					advance()
				}
			} else {
				for pos < len(source) && ((peek() >= '0' && peek() <= '9') || peek() == '_') {
					if peek() != '_' {
						num += string(peek())
					}
					advance()
				}
			}
			add(zigTokNumber, num, tokenLine, tokenCol)
			continue
		}

		// Identifiers and keywords
		if zigIsIdentStart(ch) {
			val := ""
			for pos < len(source) && zigIsIdentPart(peek()) {
				val += string(advance())
			}
			if kw, ok := zigKeywords[val]; ok {
				add(kw, val, tokenLine, tokenCol)
			} else {
				add(zigTokIdent, val, tokenLine, tokenCol)
			}
			continue
		}

		// Skip unknown characters
		advance()
	}

	tokens = append(tokens, zigToken{kind: zigTokEOF, value: "", line: line, col: col})
	return tokens
}

func zigIsIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func zigIsIdentPart(ch byte) bool {
	return zigIsIdentStart(ch) || (ch >= '0' && ch <= '9')
}

// ---------------------------------------------------------------------------
// Type mapping
// ---------------------------------------------------------------------------

var zigTypeMap = map[string]string{
	"i8":           "bigint",
	"i16":          "bigint",
	"i32":          "bigint",
	"i64":          "bigint",
	"i128":         "bigint",
	"isize":        "bigint",
	"u8":           "bigint",
	"u16":          "bigint",
	"u32":          "bigint",
	"u64":          "bigint",
	"u128":         "bigint",
	"usize":        "bigint",
	"comptime_int": "bigint",
	"Bigint":       "bigint",
	"bool":         "boolean",
	"void":         "void",
	"ByteString":   "ByteString",
	"PubKey":       "PubKey",
	"Sig":          "Sig",
	"Sha256":       "Sha256",
	"Sha256Digest": "Sha256",
	"Ripemd160":    "Ripemd160",
	"Addr":         "Addr",
	"SigHashPreimage": "SigHashPreimage",
	"RabinSig":     "RabinSig",
	"RabinPubKey":  "RabinPubKey",
	"Point":        "Point",
	"P256Point":    "P256Point",
	"P384Point":    "P384Point",
}

func zigMapType(name string) string {
	if mapped, ok := zigTypeMap[name]; ok {
		return mapped
	}
	return name
}

func zigMakePrimitiveOrCustom(name string) TypeNode {
	if IsPrimitiveType(name) {
		return PrimitiveType{Name: name}
	}
	return CustomType{Name: name}
}

// ---------------------------------------------------------------------------
// Parser helpers
// ---------------------------------------------------------------------------

func (p *zigParser) peek() zigToken {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return zigToken{kind: zigTokEOF}
}

func (p *zigParser) peekAt(offset int) zigToken {
	idx := p.pos + offset
	if idx < len(p.tokens) {
		return p.tokens[idx]
	}
	return zigToken{kind: zigTokEOF}
}

func (p *zigParser) advance() zigToken {
	tok := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

func (p *zigParser) expect(kind zigTokenKind) zigToken {
	tok := p.advance()
	if tok.kind != kind {
		p.addError(fmt.Sprintf("line %d: expected token kind %d, got %d (%q)", tok.line, kind, tok.kind, tok.value))
	}
	return tok
}

func (p *zigParser) check(kind zigTokenKind) bool {
	return p.peek().kind == kind
}

func (p *zigParser) checkIdent(value string) bool {
	tok := p.peek()
	return tok.kind == zigTokIdent && tok.value == value
}

func (p *zigParser) match(kind zigTokenKind) bool {
	if p.check(kind) {
		p.advance()
		return true
	}
	return false
}

func (p *zigParser) loc() SourceLocation {
	tok := p.peek()
	return SourceLocation{File: p.fileName, Line: tok.line, Column: tok.col}
}

// ---------------------------------------------------------------------------
// Type parsing
// ---------------------------------------------------------------------------

type zigParsedType struct {
	typeNode TypeNode
	rawName  string
	readonly bool
}

func (p *zigParser) parseType() zigParsedType {
	// Array type: [N]T
	if p.check(zigTokLBracket) {
		p.advance() // '['
		lengthTok := p.expect(zigTokNumber)
		length, err := strconv.Atoi(lengthTok.value)
		if err != nil || length < 0 {
			p.addError(fmt.Sprintf("line %d: array length must be a non-negative integer, got %q", lengthTok.line, lengthTok.value))
			length = 0
		}
		p.expect(zigTokRBracket)
		elem := p.parseType()
		return zigParsedType{
			typeNode: FixedArrayType{Element: elem.typeNode, Length: length},
			rawName:  elem.rawName,
		}
	}

	// runar.TypeName or runar.Readonly(T)
	if p.checkIdent("runar") && p.peekAt(1).kind == zigTokDot {
		p.advance() // 'runar'
		p.expect(zigTokDot)
		name := p.expect(zigTokIdent).value
		if name == "Readonly" && p.check(zigTokLParen) {
			p.expect(zigTokLParen)
			inner := p.parseType()
			p.expect(zigTokRParen)
			inner.readonly = true
			return inner
		}
		mapped := zigMapType(name)
		return zigParsedType{typeNode: zigMakePrimitiveOrCustom(mapped), rawName: name}
	}

	// void keyword
	if p.check(zigTokVoid) {
		p.advance()
		return zigParsedType{typeNode: PrimitiveType{Name: "void"}, rawName: "void"}
	}

	// Simple identifier type
	if p.check(zigTokIdent) {
		name := p.advance().value
		mapped := zigMapType(name)
		return zigParsedType{typeNode: zigMakePrimitiveOrCustom(mapped), rawName: name}
	}

	// Fallback
	tok := p.advance()
	return zigParsedType{typeNode: CustomType{Name: "unknown"}, rawName: tok.value}
}

// parseParamType handles pointer/const qualifiers before the actual type
func (p *zigParser) parseParamType() zigParsedType {
	// Skip pointer/reference qualifiers: *, &
	for p.check(zigTokStar) || p.check(zigTokAmp) {
		p.advance()
	}
	// Skip const qualifier
	if p.check(zigTokConst) {
		p.advance()
	}
	return p.parseType()
}

// ---------------------------------------------------------------------------
// Contract parsing
// ---------------------------------------------------------------------------

func (p *zigParser) parseContract() (*ContractNode, error) {
	// Skip `const runar = @import("runar");`
	if !p.skipRunarImport() {
		p.addError("Expected `const runar = @import(\"runar\");` at the top of the file")
	}

	// Find `pub const Name = struct { ... };`
	for p.peek().kind != zigTokEOF {
		if p.check(zigTokPub) &&
			p.peekAt(1).kind == zigTokConst &&
			p.peekAt(3).kind == zigTokAssign {
			contract := p.tryParseContractDecl()
			if contract != nil {
				return contract, nil
			}
		}
		p.advance()
	}

	return nil, fmt.Errorf("expected Zig contract declaration `pub const Name = struct { ... };`")
}

func (p *zigParser) skipRunarImport() bool {
	start := p.pos
	if p.check(zigTokConst) {
		p.advance()
		if p.checkIdent("runar") {
			p.advance()
			if p.match(zigTokAssign) {
				if p.match(zigTokAt) {
					if p.checkIdent("import") {
						p.advance()
						p.expect(zigTokLParen)
						if p.check(zigTokString) {
							p.advance()
						}
						p.expect(zigTokRParen)
						p.match(zigTokSemicolon)
						return true
					}
				}
			}
		}
	}
	p.pos = start
	return false
}

func (p *zigParser) tryParseContractDecl() *ContractNode {
	start := p.pos

	p.expect(zigTokPub)
	p.expect(zigTokConst)
	nameTok := p.expect(zigTokIdent)
	if !p.check(zigTokAssign) {
		p.pos = start
		return nil
	}
	p.expect(zigTokAssign)
	if !p.check(zigTokStruct) {
		p.pos = start
		return nil
	}

	p.contractName = nameTok.value
	p.parentClass = "SmartContract"

	p.expect(zigTokStruct)
	p.expect(zigTokLBrace)

	var properties []PropertyNode
	var methods []MethodNode
	var constructor *MethodNode

	for !p.check(zigTokRBrace) && !p.check(zigTokEOF) {
		// Contract marker: `pub const Contract = runar.SmartContract;`
		if p.check(zigTokPub) &&
			p.peekAt(1).kind == zigTokConst &&
			p.peekAt(2).kind == zigTokIdent &&
			p.peekAt(2).value == "Contract" {
			p.parseContractMarker()
			continue
		}

		// Public method: `pub fn name(...)`
		if p.check(zigTokPub) && p.peekAt(1).kind == zigTokFn {
			method := p.parseMethod(true, &properties)
			if method != nil {
				if method.Name == "constructor" {
					constructor = method
				} else {
					methods = append(methods, *method)
				}
			}
			continue
		}

		// Private method: `fn name(...)`
		if p.check(zigTokFn) {
			method := p.parseMethod(false, &properties)
			if method != nil {
				if method.Name == "constructor" {
					constructor = method
				} else {
					methods = append(methods, *method)
				}
			}
			continue
		}

		// Field (property): `name: type [= init],`
		if p.check(zigTokIdent) {
			prop := p.parseField()
			properties = append(properties, prop)
			continue
		}

		p.advance()
	}

	p.expect(zigTokRBrace)
	p.match(zigTokSemicolon)

	// Collect set of property names that are mutated in any method body.
	mutatedProps := make(map[string]bool)
	for _, m := range methods {
		collectZigMutatedProperties(m.Body, mutatedProps)
	}

	// Auto-generate constructor if none provided
	if constructor == nil {
		ctor := p.autoGenerateConstructor(properties)
		constructor = &ctor
	}

	// Strip initializers for properties that are also constructor params
	// (the constructor param overrides the default; the Zig compiler reference
	// omits `initialValue` in this case) and finalize readonly flags.
	ctorParamSet := make(map[string]bool)
	if constructor != nil {
		for _, param := range constructor.Params {
			ctorParamSet[param.Name] = true
		}
	}
	for i := range properties {
		hadInitializer := properties[i].Initializer != nil
		if ctorParamSet[properties[i].Name] {
			properties[i].Initializer = nil
		}
		if p.parentClass == "SmartContract" {
			properties[i].Readonly = true
		} else if !properties[i].Readonly && !hadInitializer && !mutatedProps[properties[i].Name] {
			properties[i].Readonly = true
		}
	}

	// Rewrite bare method calls to this.method() calls
	methodNames := make(map[string]bool)
	for _, m := range methods {
		methodNames[m.Name] = true
	}
	methodNames["addOutput"] = true
	methodNames["addRawOutput"] = true
	methodNames["addDataOutput"] = true
	methodNames["getStateScript"] = true
	for i := range methods {
		rewriteBareMethodCallsGo(methods[i].Body, methodNames)
	}
	if constructor != nil {
		rewriteBareMethodCallsGo(constructor.Body, methodNames)
	}

	return &ContractNode{
		Name:        p.contractName,
		ParentClass: p.parentClass,
		Properties:  properties,
		Constructor: *constructor,
		Methods:     methods,
		SourceFile:  p.fileName,
	}
}

func (p *zigParser) parseContractMarker() {
	p.expect(zigTokPub)
	p.expect(zigTokConst)
	p.expect(zigTokIdent) // "Contract"
	p.expect(zigTokAssign)

	if p.checkIdent("runar") {
		p.advance()
		p.expect(zigTokDot)
		parent := p.expect(zigTokIdent).value
		if parent == "StatefulSmartContract" {
			p.parentClass = "StatefulSmartContract"
		} else {
			p.parentClass = "SmartContract"
		}
	}

	p.match(zigTokSemicolon)
}

func (p *zigParser) parseField() PropertyNode {
	loc := p.loc()
	name := p.expect(zigTokIdent).value
	p.expect(zigTokColon)
	parsedType := p.parseType()

	var initializer Expression
	if p.match(zigTokAssign) {
		initializer = p.parseExpression()
	}

	p.match(zigTokComma)

	return PropertyNode{
		Name:           name,
		Type:           parsedType.typeNode,
		Readonly:       parsedType.readonly,
		Initializer:    initializer,
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// Method parsing
// ---------------------------------------------------------------------------

func (p *zigParser) parseMethod(isPublic bool, properties *[]PropertyNode) *MethodNode {
	loc := p.loc()
	if isPublic {
		p.expect(zigTokPub)
	}
	p.expect(zigTokFn)
	name := p.expect(zigTokIdent).value

	params, receiverName, statefulCtxNames := p.parseParamList()

	// Skip return type if present (anything before '{')
	if !p.check(zigTokLBrace) {
		p.parseType()
	}

	// Set up self names for this method scope
	prevSelfNames := p.selfNames
	prevStatefulCtx := p.statefulContextNames
	p.selfNames = make(map[string]bool)
	if receiverName != "" {
		p.selfNames[receiverName] = true
	}
	p.statefulContextNames = make(map[string]bool)
	for k := range statefulCtxNames {
		p.statefulContextNames[k] = true
	}

	if name == "init" {
		ctor := p.parseConstructorMethod(loc, params, properties)
		p.selfNames = prevSelfNames
		p.statefulContextNames = prevStatefulCtx
		return &ctor
	}

	body := p.parseBlockStatements()
	p.selfNames = prevSelfNames
	p.statefulContextNames = prevStatefulCtx

	visibility := "private"
	if isPublic {
		visibility = "public"
	}

	return &MethodNode{
		Name:           name,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SourceLocation: loc,
	}
}

func (p *zigParser) parseParamList() (params []ParamNode, receiverName string, statefulCtxNames map[string]bool) {
	p.expect(zigTokLParen)
	statefulCtxNames = make(map[string]bool)
	index := 0

	for !p.check(zigTokRParen) && !p.check(zigTokEOF) {
		paramName := p.expect(zigTokIdent).value
		p.expect(zigTokColon)
		parsedType := p.parseParamType()

		isReceiver := index == 0 && parsedType.rawName == p.contractName

		if isReceiver {
			receiverName = paramName
		} else {
			if parsedType.rawName == "StatefulContext" {
				statefulCtxNames[paramName] = true
			}
			params = append(params, ParamNode{
				Name: paramName,
				Type: parsedType.typeNode,
			})
		}

		index++
		p.match(zigTokComma)
	}

	p.expect(zigTokRParen)
	return
}

func (p *zigParser) parseConstructorMethod(loc SourceLocation, params []ParamNode, properties *[]PropertyNode) MethodNode {
	body := p.parseConstructorBody(params, properties)
	return MethodNode{
		Name:           "constructor",
		Params:         params,
		Body:           body,
		Visibility:     "public",
		SourceLocation: loc,
	}
}

func (p *zigParser) parseConstructorBody(params []ParamNode, properties *[]PropertyNode) []Statement {
	p.expect(zigTokLBrace)

	superCall := p.createSuperCall(params)
	body := []Statement{superCall}
	foundReturnStruct := false

	for !p.check(zigTokRBrace) && !p.check(zigTokEOF) {
		// `return .{ .field = value, ... };`
		if p.check(zigTokReturn) &&
			p.peekAt(1).kind == zigTokDot &&
			p.peekAt(2).kind == zigTokLBrace {
			p.advance() // 'return'
			assignments := p.parseStructReturnAssignments()
			body = append(body, assignments...)
			foundReturnStruct = true
			p.match(zigTokSemicolon)
			continue
		}

		stmt := p.parseStatement()
		if stmt != nil {
			body = append(body, stmt)
		}
	}

	p.expect(zigTokRBrace)

	// If no return struct, auto-assign params to properties
	if !foundReturnStruct && properties != nil {
		paramNames := make(map[string]bool)
		for _, param := range params {
			paramNames[param.Name] = true
		}
		for _, prop := range *properties {
			if paramNames[prop.Name] {
				body = append(body, AssignmentStmt{
					Target:         PropertyAccessExpr{Property: prop.Name},
					Value:          Identifier{Name: prop.Name},
					SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
				})
			}
		}
	}

	return body
}

func (p *zigParser) parseStructReturnAssignments() []Statement {
	var assignments []Statement
	p.expect(zigTokDot)
	p.expect(zigTokLBrace)

	for !p.check(zigTokRBrace) && !p.check(zigTokEOF) {
		p.match(zigTokDot)
		field := p.expect(zigTokIdent).value
		p.expect(zigTokAssign)
		value := p.parseExpression()
		assignments = append(assignments, AssignmentStmt{
			Target:         PropertyAccessExpr{Property: field},
			Value:          value,
			SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
		})
		p.match(zigTokComma)
	}

	p.expect(zigTokRBrace)
	return assignments
}

// ---------------------------------------------------------------------------
// Helper: auto-generate constructor
// ---------------------------------------------------------------------------

func (p *zigParser) autoGenerateConstructor(properties []PropertyNode) MethodNode {
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
			Target:         PropertyAccessExpr{Property: prop.Name},
			Value:          Identifier{Name: prop.Name},
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

func (p *zigParser) createSuperCall(params []ParamNode) Statement {
	args := make([]Expression, len(params))
	for i, param := range params {
		args[i] = Identifier{Name: param.Name}
	}
	return ExpressionStmt{
		Expr: CallExpr{
			Callee: Identifier{Name: "super"},
			Args:   args,
		},
		SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
	}
}

// ---------------------------------------------------------------------------
// Block and statement parsing
// ---------------------------------------------------------------------------

func (p *zigParser) parseBlockStatements() []Statement {
	p.expect(zigTokLBrace)
	var body []Statement
	for !p.check(zigTokRBrace) && !p.check(zigTokEOF) {
		stmt := p.parseStatement()
		if stmt != nil {
			// Merge `var i = 0; while (i < N) : (i += 1) { ... }` into ForStmt
			if forStmt, ok := stmt.(ForStmt); ok {
				if forStmt.Init.Name == "__while_no_init" {
					loopTarget := zigGetLoopUpdateTargetName(forStmt)
					if loopTarget != "" && len(body) > 0 {
						if lastDecl, ok3 := body[len(body)-1].(VariableDeclStmt); ok3 && lastDecl.Name == loopTarget {
							body = body[:len(body)-1]
							forStmt.Init = lastDecl
							stmt = forStmt
						}
					}
				}
			}
			body = append(body, stmt)
		}
	}
	p.expect(zigTokRBrace)
	return body
}

func zigGetLoopUpdateTargetName(stmt ForStmt) string {
	if assign, ok := stmt.Update.(AssignmentStmt); ok {
		if ident, ok2 := assign.Target.(Identifier); ok2 {
			return ident.Name
		}
	}
	if exprStmt, ok := stmt.Update.(ExpressionStmt); ok {
		if ident, ok2 := exprStmt.Expr.(Identifier); ok2 {
			return ident.Name
		}
	}
	return ""
}

func (p *zigParser) parseStatement() Statement {
	loc := p.loc()

	// return statement
	if p.check(zigTokReturn) {
		p.advance()
		var value Expression
		if !p.check(zigTokSemicolon) {
			value = p.parseExpression()
		}
		p.match(zigTokSemicolon)
		return ReturnStmt{Value: value, SourceLocation: loc}
	}

	// if statement
	if p.check(zigTokIf) {
		return p.parseIfStatement(loc)
	}

	// const/var declaration
	if p.check(zigTokConst) || p.check(zigTokVar) {
		return p.parseVariableDecl(loc)
	}

	// Discard pattern: `_ = expr;`
	if p.checkIdent("_") && p.peekAt(1).kind == zigTokAssign {
		p.advance() // '_'
		p.advance() // '='
		p.parseExpression()
		p.match(zigTokSemicolon)
		return nil
	}

	// while statement
	if p.check(zigTokWhile) {
		return p.parseWhileStatement(loc)
	}

	// for statement (unsupported)
	if p.check(zigTokFor) {
		p.addError(fmt.Sprintf("line %d: unsupported Zig 'for' syntax -- use 'while' loops instead", loc.Line))
		p.skipUnsupportedBlock()
		return nil
	}

	// Expression or assignment statement
	target := p.parseExpression()

	// Simple assignment: target = value
	if p.match(zigTokAssign) {
		value := p.parseExpression()
		p.match(zigTokSemicolon)
		return AssignmentStmt{Target: target, Value: value, SourceLocation: loc}
	}

	// Compound assignment: +=, -=, *=, /=, %=
	compoundOp := p.parseCompoundAssignmentOp()
	if compoundOp != "" {
		rhs := p.parseExpression()
		p.match(zigTokSemicolon)
		return AssignmentStmt{
			Target: target,
			Value:  BinaryExpr{Op: compoundOp, Left: target, Right: rhs},
			SourceLocation: loc,
		}
	}

	p.match(zigTokSemicolon)
	return ExpressionStmt{Expr: target, SourceLocation: loc}
}

func (p *zigParser) parseVariableDecl(loc SourceLocation) Statement {
	mutable := p.check(zigTokVar)
	p.advance() // 'const' or 'var'
	name := p.expect(zigTokIdent).value

	var typeNode TypeNode
	if p.check(zigTokColon) {
		p.advance()
		typeNode = p.parseType().typeNode
	}

	p.expect(zigTokAssign)
	init := p.parseExpression()
	p.match(zigTokSemicolon)

	return VariableDeclStmt{
		Name:           name,
		Type:           typeNode,
		Mutable:        mutable,
		Init:           init,
		SourceLocation: loc,
	}
}

func (p *zigParser) parseIfStatement(loc SourceLocation) Statement {
	p.advance() // 'if'
	p.match(zigTokLParen)
	condition := p.parseExpression()
	p.match(zigTokRParen)
	thenBranch := p.parseBlockStatements()

	var elseBranch []Statement
	if p.match(zigTokElse) {
		if p.check(zigTokIf) {
			elseBranch = []Statement{p.parseIfStatement(p.loc())}
		} else {
			elseBranch = p.parseBlockStatements()
		}
	}

	return IfStmt{
		Condition:      condition,
		Then:           thenBranch,
		Else:           elseBranch,
		SourceLocation: loc,
	}
}

// parseWhileStatement parses `while (cond) : (continue_expr) { body }`
// and emits a ForStmt.
func (p *zigParser) parseWhileStatement(loc SourceLocation) Statement {
	p.advance() // 'while'

	// Condition: while (i < 5)
	p.match(zigTokLParen)
	condition := p.parseExpression()
	p.match(zigTokRParen)

	// Continue expression: : (i += 1)
	var update Statement
	if p.match(zigTokColon) {
		p.match(zigTokLParen)
		updateTarget := p.parseExpression()
		compoundOp := p.parseCompoundAssignmentOp()
		if compoundOp != "" {
			rhs := p.parseExpression()
			update = AssignmentStmt{
				Target: updateTarget,
				Value:  BinaryExpr{Op: compoundOp, Left: updateTarget, Right: rhs},
				SourceLocation: loc,
			}
		} else {
			update = ExpressionStmt{Expr: updateTarget, SourceLocation: loc}
		}
		p.match(zigTokRParen)
	} else {
		// No continue expression -- synthesize no-op
		update = ExpressionStmt{
			Expr:           BigIntLiteral{Value: big.NewInt(0)},
			SourceLocation: loc,
		}
	}

	body := p.parseBlockStatements()

	return ForStmt{
		Init: VariableDeclStmt{
			Name:           "__while_no_init",
			Mutable:        true,
			Init:           BigIntLiteral{Value: big.NewInt(0)},
			SourceLocation: loc,
		},
		Condition:      condition,
		Update:         update,
		Body:           body,
		SourceLocation: loc,
	}
}

func (p *zigParser) parseCompoundAssignmentOp() string {
	if p.match(zigTokPlusEq) {
		return "+"
	}
	if p.match(zigTokMinusEq) {
		return "-"
	}
	if p.match(zigTokStarEq) {
		return "*"
	}
	if p.match(zigTokSlashEq) {
		return "/"
	}
	if p.match(zigTokPercentEq) {
		return "%"
	}
	return ""
}

func (p *zigParser) skipUnsupportedBlock() {
	for !p.check(zigTokLBrace) && !p.check(zigTokSemicolon) && !p.check(zigTokEOF) {
		p.advance()
	}
	if p.match(zigTokSemicolon) {
		return
	}
	if !p.check(zigTokLBrace) {
		return
	}
	depth := 0
	for !p.check(zigTokEOF) {
		if p.check(zigTokLBrace) {
			depth++
		}
		if p.check(zigTokRBrace) {
			depth--
			p.advance()
			if depth <= 0 {
				break
			}
			continue
		}
		p.advance()
	}
}

// ---------------------------------------------------------------------------
// Expression parsing (precedence climbing)
// ---------------------------------------------------------------------------

func (p *zigParser) parseExpression() Expression {
	return p.parseOr()
}

func (p *zigParser) parseOr() Expression {
	left := p.parseAnd()
	for p.match(zigTokPipePipe) {
		right := p.parseAnd()
		left = BinaryExpr{Op: "||", Left: left, Right: right}
	}
	return left
}

func (p *zigParser) parseAnd() Expression {
	left := p.parseBitwiseOr()
	for p.match(zigTokAmpAmp) {
		right := p.parseBitwiseOr()
		left = BinaryExpr{Op: "&&", Left: left, Right: right}
	}
	return left
}

func (p *zigParser) parseBitwiseOr() Expression {
	left := p.parseBitwiseXor()
	for p.match(zigTokPipe) {
		right := p.parseBitwiseXor()
		left = BinaryExpr{Op: "|", Left: left, Right: right}
	}
	return left
}

func (p *zigParser) parseBitwiseXor() Expression {
	left := p.parseBitwiseAnd()
	for p.match(zigTokCaret) {
		right := p.parseBitwiseAnd()
		left = BinaryExpr{Op: "^", Left: left, Right: right}
	}
	return left
}

func (p *zigParser) parseBitwiseAnd() Expression {
	left := p.parseEquality()
	for p.match(zigTokAmp) {
		right := p.parseEquality()
		left = BinaryExpr{Op: "&", Left: left, Right: right}
	}
	return left
}

func (p *zigParser) parseEquality() Expression {
	left := p.parseComparison()
	for {
		if p.match(zigTokEqEq) {
			right := p.parseComparison()
			left = BinaryExpr{Op: "===", Left: left, Right: right} // == -> ===
		} else if p.match(zigTokNotEq) {
			right := p.parseComparison()
			left = BinaryExpr{Op: "!==", Left: left, Right: right} // != -> !==
		} else {
			break
		}
	}
	return left
}

func (p *zigParser) parseComparison() Expression {
	left := p.parseShift()
	for {
		if p.match(zigTokLt) {
			right := p.parseShift()
			left = BinaryExpr{Op: "<", Left: left, Right: right}
		} else if p.match(zigTokLtEq) {
			right := p.parseShift()
			left = BinaryExpr{Op: "<=", Left: left, Right: right}
		} else if p.match(zigTokGt) {
			right := p.parseShift()
			left = BinaryExpr{Op: ">", Left: left, Right: right}
		} else if p.match(zigTokGtEq) {
			right := p.parseShift()
			left = BinaryExpr{Op: ">=", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *zigParser) parseShift() Expression {
	left := p.parseAdditive()
	for {
		if p.match(zigTokLShift) {
			right := p.parseAdditive()
			left = BinaryExpr{Op: "<<", Left: left, Right: right}
		} else if p.match(zigTokRShift) {
			right := p.parseAdditive()
			left = BinaryExpr{Op: ">>", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *zigParser) parseAdditive() Expression {
	left := p.parseMultiplicative()
	for {
		if p.match(zigTokPlus) {
			right := p.parseMultiplicative()
			left = BinaryExpr{Op: "+", Left: left, Right: right}
		} else if p.match(zigTokMinus) {
			right := p.parseMultiplicative()
			left = BinaryExpr{Op: "-", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *zigParser) parseMultiplicative() Expression {
	left := p.parseUnary()
	for {
		if p.match(zigTokStar) {
			right := p.parseUnary()
			left = BinaryExpr{Op: "*", Left: left, Right: right}
		} else if p.match(zigTokSlash) {
			right := p.parseUnary()
			left = BinaryExpr{Op: "/", Left: left, Right: right}
		} else if p.match(zigTokPercent) {
			right := p.parseUnary()
			left = BinaryExpr{Op: "%", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *zigParser) parseUnary() Expression {
	if p.match(zigTokBang) {
		operand := p.parseUnary()
		return UnaryExpr{Op: "!", Operand: operand}
	}
	if p.match(zigTokMinus) {
		operand := p.parseUnary()
		return UnaryExpr{Op: "-", Operand: operand}
	}
	if p.match(zigTokTilde) {
		operand := p.parseUnary()
		return UnaryExpr{Op: "~", Operand: operand}
	}
	expr := p.parsePrimary()
	return p.parsePostfixChain(expr)
}

// ---------------------------------------------------------------------------
// Primary expressions
// ---------------------------------------------------------------------------

func (p *zigParser) parsePrimary() Expression {
	tok := p.peek()

	// Anonymous struct literal: .{ elem, ... } -> array literal
	if tok.kind == zigTokDot && p.peekAt(1).kind == zigTokLBrace {
		p.advance() // '.'
		p.advance() // '{'
		var elements []Expression
		for !p.check(zigTokRBrace) && !p.check(zigTokEOF) {
			elements = append(elements, p.parseExpression())
			p.match(zigTokComma)
		}
		p.expect(zigTokRBrace)
		return ArrayLiteralExpr{Elements: elements}
	}

	// Number literal
	if tok.kind == zigTokNumber {
		p.advance()
		return p.parseZigNumber(tok.value)
	}

	// String literal -> ByteStringLiteral
	if tok.kind == zigTokString {
		p.advance()
		return ByteStringLiteral{Value: tok.value}
	}

	// Boolean literals
	if tok.kind == zigTokTrue {
		p.advance()
		return BoolLiteral{Value: true}
	}
	if tok.kind == zigTokFalse {
		p.advance()
		return BoolLiteral{Value: false}
	}

	// Parenthesized expression
	if tok.kind == zigTokLParen {
		p.advance()
		expr := p.parseExpression()
		p.expect(zigTokRParen)
		return expr
	}

	// Array literal: [elem, ...]
	if tok.kind == zigTokLBracket {
		p.advance()
		var elements []Expression
		for !p.check(zigTokRBracket) && !p.check(zigTokEOF) {
			elements = append(elements, p.parseExpression())
			p.match(zigTokComma)
		}
		p.expect(zigTokRBracket)
		return ArrayLiteralExpr{Elements: elements}
	}

	// Zig @builtins: @divTrunc, @mod, @shlExact, @shrExact, @intCast, @truncate, @as, ...
	if tok.kind == zigTokAt {
		p.advance()
		builtinName := p.expect(zigTokIdent).value
		return p.parseZigBuiltin(builtinName, tok.line, tok.col)
	}

	// Identifier (including runar.builtin handling)
	if tok.kind == zigTokIdent {
		p.advance()

		// runar.builtin(...) -> strip prefix
		if tok.value == "runar" && p.check(zigTokDot) {
			p.advance() // '.'
			builtin := p.expect(zigTokIdent).value

			// runar.bytesEq(a, b) -> BinaryExpr{===}
			if builtin == "bytesEq" && p.check(zigTokLParen) {
				p.advance() // '('
				left := p.parseExpression()
				p.expect(zigTokComma)
				right := p.parseExpression()
				p.expect(zigTokRParen)
				return BinaryExpr{Op: "===", Left: left, Right: right}
			}

			return Identifier{Name: builtin}
		}

		return Identifier{Name: tok.value}
	}

	// Fallback
	p.addError(fmt.Sprintf("line %d: unexpected token %q", tok.line, tok.value))
	p.advance()
	return BigIntLiteral{Value: big.NewInt(0)}
}

func (p *zigParser) parseZigBuiltin(name string, tokLine, tokCol int) Expression {
	// @divTrunc(a, b) -> a / b
	// @mod(a, b) -> a % b
	// @shlExact(a, b) -> a << b
	// @shrExact(a, b) -> a >> b
	switch name {
	case "divTrunc", "mod", "shlExact", "shrExact":
		p.expect(zigTokLParen)
		left := p.parseExpression()
		p.expect(zigTokComma)
		right := p.parseExpression()
		p.expect(zigTokRParen)
		var op string
		switch name {
		case "divTrunc":
			op = "/"
		case "mod":
			op = "%"
		case "shlExact":
			op = "<<"
		case "shrExact":
			op = ">>"
		}
		return BinaryExpr{Op: op, Left: left, Right: right}

	case "intCast", "truncate":
		p.expect(zigTokLParen)
		inner := p.parseExpression()
		p.expect(zigTokRParen)
		return inner

	case "as":
		// @as(type, expr)
		p.expect(zigTokLParen)
		p.parseType() // skip type
		p.expect(zigTokComma)
		inner := p.parseExpression()
		p.expect(zigTokRParen)
		return inner

	case "import":
		p.expect(zigTokLParen)
		p.parseExpression()
		p.expect(zigTokRParen)
		return Identifier{Name: "__import"}

	case "embedFile":
		p.expect(zigTokLParen)
		arg := p.parseExpression()
		p.expect(zigTokRParen)
		return arg
	}

	// Unknown @builtin
	if p.check(zigTokLParen) {
		p.advance() // '('
		var args []Expression
		args = append(args, p.parseExpression())
		for p.match(zigTokComma) {
			args = append(args, p.parseExpression())
		}
		p.expect(zigTokRParen)
		p.addError(fmt.Sprintf("line %d: unsupported Zig builtin '@%s'", tokLine, name))
		return CallExpr{Callee: Identifier{Name: name}, Args: args}
	}

	p.addError(fmt.Sprintf("line %d: unsupported Zig builtin '@%s'", tokLine, name))
	return Identifier{Name: name}
}

// ---------------------------------------------------------------------------
// Postfix chain: calls, member access, indexing
// ---------------------------------------------------------------------------

func (p *zigParser) parsePostfixChain(expr Expression) Expression {
	for {
		// Function call: expr(args...)
		if p.check(zigTokLParen) {
			p.advance() // '('
			var args []Expression
			for !p.check(zigTokRParen) && !p.check(zigTokEOF) {
				args = append(args, p.parseExpression())
				p.match(zigTokComma)
			}
			p.expect(zigTokRParen)
			expr = CallExpr{Callee: expr, Args: args}
			continue
		}

		// Member access: expr.name
		if p.check(zigTokDot) {
			p.advance() // '.'
			prop := p.advance().value

			// self.prop -> PropertyAccessExpr
			if ident, ok := expr.(Identifier); ok && p.selfNames[ident.Name] {
				expr = PropertyAccessExpr{Property: prop}
			} else if ident, ok := expr.(Identifier); ok && p.statefulContextNames[ident.Name] {
				// StatefulContext member access -> PropertyAccessExpr for intrinsics
				if prop == "txPreimage" || prop == "getStateScript" || prop == "addOutput" || prop == "addRawOutput" || prop == "addDataOutput" {
					expr = PropertyAccessExpr{Property: prop}
				} else {
					expr = MemberExpr{Object: expr, Property: prop}
				}
			} else {
				expr = MemberExpr{Object: expr, Property: prop}
			}
			continue
		}

		// Index access: expr[index]
		if p.check(zigTokLBracket) {
			p.advance() // '['
			index := p.parseExpression()
			p.expect(zigTokRBracket)
			expr = IndexAccessExpr{Object: expr, Index: index}
			continue
		}

		break
	}
	return expr
}

// ---------------------------------------------------------------------------
// Number parsing
// ---------------------------------------------------------------------------

func (p *zigParser) parseZigNumber(s string) Expression {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		// Hex literal -> ByteStringLiteral
		hex := s[2:]
		// Ensure even length
		if len(hex)%2 != 0 {
			hex = "0" + hex
		}
		return ByteStringLiteral{Value: hex}
	}

	bi := new(big.Int)
	if _, ok := bi.SetString(s, 10); !ok {
		p.addError(fmt.Sprintf("line %d: invalid number literal %q", p.peek().line, s))
		return BigIntLiteral{Value: big.NewInt(0)}
	}
	return BigIntLiteral{Value: bi}
}

// Ensure the strings import is used
var _ = strings.HasPrefix

// collectZigMutatedProperties walks a list of statements and records the
// names of contract properties that are the target of an assignment or
// increment/decrement. Used to determine which StatefulSmartContract fields
// are mutable.
func collectZigMutatedProperties(body []Statement, out map[string]bool) {
	for _, stmt := range body {
		collectZigMutatedInStmt(stmt, out)
	}
}

func collectZigMutatedInStmt(stmt Statement, out map[string]bool) {
	switch s := stmt.(type) {
	case AssignmentStmt:
		if pa, ok := s.Target.(PropertyAccessExpr); ok {
			out[pa.Property] = true
		}
		collectZigMutatedInExpr(s.Target, out)
		collectZigMutatedInExpr(s.Value, out)
	case *AssignmentStmt:
		if pa, ok := s.Target.(PropertyAccessExpr); ok {
			out[pa.Property] = true
		}
		collectZigMutatedInExpr(s.Target, out)
		collectZigMutatedInExpr(s.Value, out)
	case VariableDeclStmt:
		collectZigMutatedInExpr(s.Init, out)
	case *VariableDeclStmt:
		collectZigMutatedInExpr(s.Init, out)
	case ExpressionStmt:
		collectZigMutatedInExpr(s.Expr, out)
	case *ExpressionStmt:
		collectZigMutatedInExpr(s.Expr, out)
	case ReturnStmt:
		if s.Value != nil {
			collectZigMutatedInExpr(s.Value, out)
		}
	case *ReturnStmt:
		if s.Value != nil {
			collectZigMutatedInExpr(s.Value, out)
		}
	case IfStmt:
		collectZigMutatedInExpr(s.Condition, out)
		collectZigMutatedProperties(s.Then, out)
		collectZigMutatedProperties(s.Else, out)
	case *IfStmt:
		collectZigMutatedInExpr(s.Condition, out)
		collectZigMutatedProperties(s.Then, out)
		collectZigMutatedProperties(s.Else, out)
	case ForStmt:
		collectZigMutatedInExpr(s.Init.Init, out)
		collectZigMutatedInExpr(s.Condition, out)
		collectZigMutatedInStmt(s.Update, out)
		collectZigMutatedProperties(s.Body, out)
	case *ForStmt:
		collectZigMutatedInExpr(s.Init.Init, out)
		collectZigMutatedInExpr(s.Condition, out)
		collectZigMutatedInStmt(s.Update, out)
		collectZigMutatedProperties(s.Body, out)
	}
}

func collectZigMutatedInExpr(expr Expression, out map[string]bool) {
	if expr == nil {
		return
	}
	switch e := expr.(type) {
	case BinaryExpr:
		collectZigMutatedInExpr(e.Left, out)
		collectZigMutatedInExpr(e.Right, out)
	case UnaryExpr:
		collectZigMutatedInExpr(e.Operand, out)
	case CallExpr:
		collectZigMutatedInExpr(e.Callee, out)
		for _, a := range e.Args {
			collectZigMutatedInExpr(a, out)
		}
	case MemberExpr:
		collectZigMutatedInExpr(e.Object, out)
	case TernaryExpr:
		collectZigMutatedInExpr(e.Condition, out)
		collectZigMutatedInExpr(e.Consequent, out)
		collectZigMutatedInExpr(e.Alternate, out)
	case IndexAccessExpr:
		collectZigMutatedInExpr(e.Object, out)
		collectZigMutatedInExpr(e.Index, out)
	case IncrementExpr:
		if pa, ok := e.Operand.(PropertyAccessExpr); ok {
			out[pa.Property] = true
		}
		collectZigMutatedInExpr(e.Operand, out)
	case DecrementExpr:
		if pa, ok := e.Operand.(PropertyAccessExpr); ok {
			out[pa.Property] = true
		}
		collectZigMutatedInExpr(e.Operand, out)
	}
}
