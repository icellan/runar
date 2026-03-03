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

// ParseMove parses a Move-style Rúnar contract and produces the standard AST.
func ParseMove(source []byte, fileName string) *ParseResult {
	p := &moveParser{
		fileName: fileName,
	}

	tokens := p.tokenize(string(source))
	p.tokens = tokens
	p.pos = 0

	contract, err := p.parseModule()
	if err != nil {
		return &ParseResult{Errors: []string{err.Error()}}
	}
	if len(p.errors) > 0 {
		return &ParseResult{Contract: contract, Errors: p.errors}
	}
	return &ParseResult{Contract: contract}
}

// ---------------------------------------------------------------------------
// Token types (reusing a similar model to the Solidity parser)
// ---------------------------------------------------------------------------

type moveTokenKind int

const (
	moveTokEOF moveTokenKind = iota
	moveTokIdent
	moveTokNumber
	moveTokString
	moveTokLBrace    // {
	moveTokRBrace    // }
	moveTokLParen    // (
	moveTokRParen    // )
	moveTokLBracket  // [
	moveTokRBracket  // ]
	moveTokSemicolon // ;
	moveTokComma     // ,
	moveTokDot       // .
	moveTokColon     // :
	moveTokColonColon // ::
	moveTokAssign    // =
	moveTokEqEq      // ==
	moveTokNotEq     // !=
	moveTokLt        // <
	moveTokLtEq      // <=
	moveTokGt        // >
	moveTokGtEq      // >=
	moveTokPlus      // +
	moveTokMinus     // -
	moveTokStar      // *
	moveTokSlash     // /
	moveTokPercent   // %
	moveTokBang      // !
	moveTokTilde     // ~
	moveTokAmp       // &
	moveTokPipe      // |
	moveTokCaret     // ^
	moveTokAmpAmp    // &&
	moveTokPipePipe  // ||
	moveTokPlusPlus  // (not native in Move, but we support it for flexibility)
	moveTokMinusMinus
	moveTokPlusEq    // +=
	moveTokMinusEq   // -=
	moveTokStarEq    // *=
	moveTokSlashEq   // /=
	moveTokPercentEq // %=
	moveTokQuestion  // ?
	moveTokArrow     // ->
)

type moveToken struct {
	kind  moveTokenKind
	value string
	line  int
	col   int
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

type moveParser struct {
	fileName string
	tokens   []moveToken
	pos      int
	errors   []string
}

func (p *moveParser) addError(msg string) {
	p.errors = append(p.errors, msg)
}

func (p *moveParser) tokenize(source string) []moveToken {
	var tokens []moveToken
	line := 1
	col := 0
	i := 0

	for i < len(source) {
		ch := source[i]

		// Newlines
		if ch == '\n' {
			line++
			col = 0
			i++
			continue
		}
		if ch == '\r' {
			i++
			if i < len(source) && source[i] == '\n' {
				i++
			}
			line++
			col = 0
			continue
		}

		// Whitespace
		if ch == ' ' || ch == '\t' {
			i++
			col++
			continue
		}

		// Single-line comment
		if i+1 < len(source) && ch == '/' && source[i+1] == '/' {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		}

		// Multi-line comment
		if i+1 < len(source) && ch == '/' && source[i+1] == '*' {
			i += 2
			col += 2
			for i+1 < len(source) {
				if source[i] == '*' && source[i+1] == '/' {
					i += 2
					col += 2
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
			continue
		}

		startCol := col

		// String literals
		if ch == '"' || ch == '\'' {
			quote := ch
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
			tokens = append(tokens, moveToken{kind: moveTokString, value: val, line: line, col: startCol})
			continue
		}

		// Numbers
		if ch >= '0' && ch <= '9' {
			start := i
			if ch == '0' && i+1 < len(source) && (source[i+1] == 'x' || source[i+1] == 'X') {
				i += 2
				col += 2
				for i < len(source) && moveIsHexDigit(source[i]) {
					i++
					col++
				}
			} else {
				for i < len(source) && source[i] >= '0' && source[i] <= '9' {
					i++
					col++
				}
			}
			// Skip trailing 'u8', 'u64', etc.
			if i < len(source) && source[i] == 'u' {
				i++
				col++
				for i < len(source) && source[i] >= '0' && source[i] <= '9' {
					i++
					col++
				}
			}
			tokens = append(tokens, moveToken{kind: moveTokNumber, value: source[start:i], line: line, col: startCol})
			continue
		}

		// Identifiers and keywords
		if moveIsIdentStart(ch) {
			start := i
			for i < len(source) && moveIsIdentPart(source[i]) {
				i++
				col++
			}
			// Handle assert! and assert_eq! macros
			if i < len(source) && source[i] == '!' {
				tokens = append(tokens, moveToken{kind: moveTokIdent, value: source[start:i] + "!", line: line, col: startCol})
				i++ // skip '!'
				col++
				continue
			}
			tokens = append(tokens, moveToken{kind: moveTokIdent, value: source[start:i], line: line, col: startCol})
			continue
		}

		// Two-character operators
		if i+1 < len(source) {
			two := source[i : i+2]
			var twoKind moveTokenKind
			found := true
			switch two {
			case "::":
				twoKind = moveTokColonColon
			case "==":
				twoKind = moveTokEqEq
			case "!=":
				twoKind = moveTokNotEq
			case "<=":
				twoKind = moveTokLtEq
			case ">=":
				twoKind = moveTokGtEq
			case "&&":
				twoKind = moveTokAmpAmp
			case "||":
				twoKind = moveTokPipePipe
			case "++":
				twoKind = moveTokPlusPlus
			case "--":
				twoKind = moveTokMinusMinus
			case "+=":
				twoKind = moveTokPlusEq
			case "-=":
				twoKind = moveTokMinusEq
			case "*=":
				twoKind = moveTokStarEq
			case "/=":
				twoKind = moveTokSlashEq
			case "%=":
				twoKind = moveTokPercentEq
			case "->":
				twoKind = moveTokArrow
			default:
				found = false
			}
			if found {
				tokens = append(tokens, moveToken{kind: twoKind, value: two, line: line, col: startCol})
				i += 2
				col += 2
				continue
			}
		}

		// Single-character operators
		var oneKind moveTokenKind
		oneFound := true
		switch ch {
		case '{':
			oneKind = moveTokLBrace
		case '}':
			oneKind = moveTokRBrace
		case '(':
			oneKind = moveTokLParen
		case ')':
			oneKind = moveTokRParen
		case '[':
			oneKind = moveTokLBracket
		case ']':
			oneKind = moveTokRBracket
		case ';':
			oneKind = moveTokSemicolon
		case ',':
			oneKind = moveTokComma
		case '.':
			oneKind = moveTokDot
		case ':':
			oneKind = moveTokColon
		case '=':
			oneKind = moveTokAssign
		case '<':
			oneKind = moveTokLt
		case '>':
			oneKind = moveTokGt
		case '+':
			oneKind = moveTokPlus
		case '-':
			oneKind = moveTokMinus
		case '*':
			oneKind = moveTokStar
		case '/':
			oneKind = moveTokSlash
		case '%':
			oneKind = moveTokPercent
		case '!':
			oneKind = moveTokBang
		case '~':
			oneKind = moveTokTilde
		case '&':
			oneKind = moveTokAmp
		case '|':
			oneKind = moveTokPipe
		case '^':
			oneKind = moveTokCaret
		case '?':
			oneKind = moveTokQuestion
		default:
			oneFound = false
		}

		if oneFound {
			tokens = append(tokens, moveToken{kind: oneKind, value: string(ch), line: line, col: startCol})
			i++
			col++
			continue
		}

		// Skip unknown characters
		i++
		col++
	}

	tokens = append(tokens, moveToken{kind: moveTokEOF, value: "", line: line, col: col})
	return tokens
}

func moveIsHexDigit(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

func moveIsIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func moveIsIdentPart(ch byte) bool {
	return moveIsIdentStart(ch) || (ch >= '0' && ch <= '9')
}

// ---------------------------------------------------------------------------
// Parser helpers
// ---------------------------------------------------------------------------

func (p *moveParser) peek() moveToken {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return moveToken{kind: moveTokEOF}
}

func (p *moveParser) advance() moveToken {
	tok := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

func (p *moveParser) expect(kind moveTokenKind) moveToken {
	tok := p.advance()
	if tok.kind != kind {
		p.addError(fmt.Sprintf("line %d: expected token kind %d, got %d (%q)", tok.line, kind, tok.kind, tok.value))
	}
	return tok
}

func (p *moveParser) expectIdent(value string) moveToken {
	tok := p.advance()
	if tok.kind != moveTokIdent || tok.value != value {
		p.addError(fmt.Sprintf("line %d: expected '%s', got %q", tok.line, value, tok.value))
	}
	return tok
}

func (p *moveParser) check(kind moveTokenKind) bool {
	return p.peek().kind == kind
}

func (p *moveParser) checkIdent(value string) bool {
	tok := p.peek()
	return tok.kind == moveTokIdent && tok.value == value
}

func (p *moveParser) match(kind moveTokenKind) bool {
	if p.check(kind) {
		p.advance()
		return true
	}
	return false
}

func (p *moveParser) matchIdent(value string) bool {
	if p.checkIdent(value) {
		p.advance()
		return true
	}
	return false
}

func (p *moveParser) loc() SourceLocation {
	tok := p.peek()
	return SourceLocation{File: p.fileName, Line: tok.line, Column: tok.col}
}

// ---------------------------------------------------------------------------
// Name conversion: snake_case to camelCase
// ---------------------------------------------------------------------------

func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	if len(parts) <= 1 {
		return s
	}
	result := parts[0]
	for _, part := range parts[1:] {
		if len(part) > 0 {
			result += string(unicode.ToUpper(rune(part[0]))) + part[1:]
		}
	}
	return result
}

// moveBuiltinMap maps Move-style snake_case builtins to Rúnar camelCase.
var moveBuiltinMap = map[string]string{
	"check_sig":       "checkSig",
	"check_multi_sig": "checkMultiSig",
	"check_preimage":  "checkPreimage",
	"hash_160":        "hash160",
	"hash_256":        "hash256",
	"sha_256":         "sha256",
	"ripemd_160":      "ripemd160",
	"num_2_bin":       "num2bin",
	"bin_2_num":       "bin2num",
	"reverse_bytes":   "reverseBytes",
	"hash160":         "hash160",
	"hash256":         "hash256",
	"sha256":          "sha256",
	"ripemd160":       "ripemd160",
	"num2bin":         "num2bin",
	"bin2num":         "bin2num",
	"abs":             "abs",
	"min":             "min",
	"max":             "max",
	"within":          "within",
	"len":             "len",
	"pack":            "pack",
	"unpack":          "unpack",
}

func moveMapBuiltin(name string) string {
	if mapped, ok := moveBuiltinMap[name]; ok {
		return mapped
	}
	return snakeToCamel(name)
}

// moveMapType maps Move-style type names to Rúnar types.
func moveMapType(name string) TypeNode {
	switch name {
	case "u64", "u128", "u256":
		return PrimitiveType{Name: "bigint"}
	case "bool":
		return PrimitiveType{Name: "boolean"}
	case "vector":
		return PrimitiveType{Name: "ByteString"}
	}
	// Handle snake_case type conversions
	camel := snakeToCamel(name)
	if IsPrimitiveType(camel) {
		return PrimitiveType{Name: camel}
	}
	if IsPrimitiveType(name) {
		return PrimitiveType{Name: name}
	}
	return CustomType{Name: camel}
}

// ---------------------------------------------------------------------------
// Module parsing
// ---------------------------------------------------------------------------

func (p *moveParser) parseModule() (*ContractNode, error) {
	// Skip use declarations at the top level before module
	for p.checkIdent("use") {
		p.skipUseDecl()
	}

	// module Name { ... }
	if !p.matchIdent("module") {
		return nil, fmt.Errorf("expected 'module' keyword")
	}

	nameTok := p.expect(moveTokIdent)
	moduleName := nameTok.value

	p.expect(moveTokLBrace)

	// Parse module body
	var properties []PropertyNode
	var methods []MethodNode
	parentClass := "SmartContract" // default

	for !p.check(moveTokRBrace) && !p.check(moveTokEOF) {
		// Skip use declarations inside the module
		if p.checkIdent("use") {
			p.skipUseDecl()
			continue
		}

		// resource struct or struct
		if p.checkIdent("resource") || p.checkIdent("struct") {
			isStateful := p.checkIdent("resource")
			if isStateful {
				p.advance() // skip "resource"
				parentClass = "StatefulSmartContract"
			}
			props, hasInductive := p.parseMoveStruct()
			properties = append(properties, props...)
			if hasInductive {
				parentClass = "InductiveSmartContract"
			}
			continue
		}

		// public fun or fun
		if p.checkIdent("public") || p.checkIdent("fun") {
			method := p.parseMoveFunction()
			methods = append(methods, method)
			continue
		}

		// Skip unknown tokens
		p.advance()
	}

	p.expect(moveTokRBrace)

	// Build constructor from properties
	constructor := p.buildMoveConstructor(properties)

	contract := &ContractNode{
		Name:        moduleName,
		ParentClass: parentClass,
		Properties:  properties,
		Constructor: constructor,
		Methods:     methods,
		SourceFile:  p.fileName,
	}

	if contract.ParentClass == "InductiveSmartContract" {
		injectInductiveInternalFields(contract)
	}

	return contract, nil
}

func (p *moveParser) skipUseDecl() {
	// use path::to::module::{Type1, Type2};
	for !p.check(moveTokSemicolon) && !p.check(moveTokEOF) {
		p.advance()
	}
	p.match(moveTokSemicolon)
}

// ---------------------------------------------------------------------------
// Struct parsing
// ---------------------------------------------------------------------------

func (p *moveParser) parseMoveStruct() ([]PropertyNode, bool) {
	p.expectIdent("struct")

	// struct name
	p.expect(moveTokIdent) // skip struct name (same as module name)

	// Optional: has key, store, copy, drop, inductive abilities
	hasInductive := false
	if p.checkIdent("has") {
		p.advance()
		for p.peek().kind == moveTokIdent || p.peek().kind == moveTokComma {
			if p.peek().kind == moveTokIdent && p.peek().value == "inductive" {
				hasInductive = true
			}
			p.advance()
		}
	}

	p.expect(moveTokLBrace)

	var props []PropertyNode
	for !p.check(moveTokRBrace) && !p.check(moveTokEOF) {
		nameTok := p.expect(moveTokIdent)
		fieldName := snakeToCamel(nameTok.value)

		p.expect(moveTokColon)

		typeName := p.parseMoveTypeName()
		typeNode := moveMapType(typeName)

		// Determine readonly: by default all fields in a Move resource are mutable
		// But if the module uses SmartContract parent, fields should be readonly
		readonly := true // default to readonly; will be overridden for StatefulSmartContract later

		props = append(props, PropertyNode{
			Name:           fieldName,
			Type:           typeNode,
			Readonly:       readonly,
			SourceLocation: p.loc(),
		})

		p.match(moveTokComma)
	}

	p.expect(moveTokRBrace)
	return props, hasInductive
}

func (p *moveParser) parseMoveTypeName() string {
	// Handle & references
	if p.match(moveTokAmp) {
		// &mut or &
		if p.matchIdent("mut") {
			// &mut Type
		}
	}

	nameTok := p.expect(moveTokIdent)
	name := nameTok.value

	// Handle path types: module::Type
	for p.match(moveTokColonColon) {
		nextTok := p.expect(moveTokIdent)
		name = nextTok.value // use the final component
	}

	// Handle generic types: Type<T>
	if p.match(moveTokLt) {
		depth := 1
		for depth > 0 && !p.check(moveTokEOF) {
			if p.check(moveTokLt) {
				depth++
			}
			if p.check(moveTokGt) {
				depth--
			}
			p.advance()
		}
	}

	return name
}

// ---------------------------------------------------------------------------
// Function parsing
// ---------------------------------------------------------------------------

func (p *moveParser) parseMoveFunction() MethodNode {
	loc := p.loc()
	visibility := "private"

	if p.matchIdent("public") {
		visibility = "public"
		// Skip optional (friend) or (script) visibility
		if p.check(moveTokLParen) {
			p.advance()
			for !p.check(moveTokRParen) && !p.check(moveTokEOF) {
				p.advance()
			}
			p.match(moveTokRParen)
		}
	}

	p.expectIdent("fun")

	nameTok := p.expect(moveTokIdent)
	name := snakeToCamel(nameTok.value)

	params := p.parseMoveParams()

	// Optional return type: : Type
	if p.match(moveTokColon) {
		p.parseMoveTypeName() // skip return type
	}

	body := p.parseMoveBlock()

	return MethodNode{
		Name:           name,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SourceLocation: loc,
	}
}

func (p *moveParser) parseMoveParams() []ParamNode {
	p.expect(moveTokLParen)
	var params []ParamNode

	for !p.check(moveTokRParen) && !p.check(moveTokEOF) {
		// Skip &self, self, &mut self, contract: &ContractName
		if p.checkIdent("self") {
			p.advance()
			if p.match(moveTokComma) {
				continue
			}
			break
		}

		// Check for & prefix
		isRef := false
		isMut := false
		if p.check(moveTokAmp) {
			isRef = true
			p.advance()
			if p.matchIdent("mut") {
				isMut = true
			}
			_ = isMut
		}

		nameTok := p.expect(moveTokIdent)
		paramName := nameTok.value

		p.expect(moveTokColon)

		// Check for & in type
		if p.check(moveTokAmp) {
			p.advance()
			if p.matchIdent("mut") {
				// &mut Type
			}
		}

		typeName := p.parseMoveTypeName()

		// Skip self/contract parameters
		if paramName == "self" || paramName == "contract" {
			if p.match(moveTokComma) {
				continue
			}
			break
		}

		// If param was a reference and there's no type (malformed), skip
		_ = isRef

		camelName := snakeToCamel(paramName)
		params = append(params, ParamNode{
			Name: camelName,
			Type: moveMapType(typeName),
		})

		if !p.match(moveTokComma) {
			break
		}
	}

	p.expect(moveTokRParen)
	return params
}

// ---------------------------------------------------------------------------
// Block parsing
// ---------------------------------------------------------------------------

func (p *moveParser) parseMoveBlock() []Statement {
	p.expect(moveTokLBrace)
	var stmts []Statement
	for !p.check(moveTokRBrace) && !p.check(moveTokEOF) {
		stmt := p.parseMoveStatement()
		if stmt != nil {
			stmts = append(stmts, stmt)
		}
	}
	p.expect(moveTokRBrace)
	return stmts
}

// ---------------------------------------------------------------------------
// Statement parsing
// ---------------------------------------------------------------------------

func (p *moveParser) parseMoveStatement() Statement {
	loc := p.loc()

	// let [mut] name [: Type] = expr;
	if p.checkIdent("let") {
		return p.parseMoveLetDecl(loc)
	}

	// assert!(expr, code) or assert_eq!(a, b, code)
	if p.checkIdent("assert!") || p.checkIdent("assert_eq!") {
		return p.parseMoveAssert(loc)
	}

	// if condition { ... } [else { ... }]
	if p.checkIdent("if") {
		return p.parseMoveIf(loc)
	}

	// loop / while / for (Move uses loop/while primarily)
	if p.checkIdent("while") {
		return p.parseMoveWhile(loc)
	}
	if p.checkIdent("loop") {
		return p.parseMoveLoop(loc)
	}

	// return expr;
	if p.checkIdent("return") {
		return p.parseMoveReturn(loc)
	}

	// Expression statement or assignment
	return p.parseMoveExprStatement(loc)
}

func (p *moveParser) parseMoveLetDecl(loc SourceLocation) Statement {
	p.expectIdent("let")

	mutable := false
	if p.matchIdent("mut") {
		mutable = true
	}

	nameTok := p.expect(moveTokIdent)
	varName := snakeToCamel(nameTok.value)

	var typeNode TypeNode
	if p.match(moveTokColon) {
		typeName := p.parseMoveTypeName()
		typeNode = moveMapType(typeName)
	}

	var init Expression
	if p.match(moveTokAssign) {
		init = p.parseMoveExpression()
	} else {
		init = BigIntLiteral{Value: 0}
	}

	p.expect(moveTokSemicolon)

	return VariableDeclStmt{
		Name:           varName,
		Type:           typeNode,
		Mutable:        mutable,
		Init:           init,
		SourceLocation: loc,
	}
}

func (p *moveParser) parseMoveAssert(loc SourceLocation) Statement {
	tok := p.advance() // consume assert! or assert_eq!

	p.expect(moveTokLParen)

	if tok.value == "assert_eq!" {
		// assert_eq!(a, b, code) -> assert(a === b)
		left := p.parseMoveExpression()
		p.expect(moveTokComma)
		right := p.parseMoveExpression()
		// Skip optional error code
		if p.match(moveTokComma) {
			p.parseMoveExpression()
		}
		p.expect(moveTokRParen)
		p.expect(moveTokSemicolon)

		return ExpressionStmt{
			Expr: CallExpr{
				Callee: Identifier{Name: "assert"},
				Args:   []Expression{BinaryExpr{Op: "===", Left: left, Right: right}},
			},
			SourceLocation: loc,
		}
	}

	// assert!(expr, code)
	expr := p.parseMoveExpression()
	// Skip optional error code
	if p.match(moveTokComma) {
		p.parseMoveExpression()
	}
	p.expect(moveTokRParen)
	p.expect(moveTokSemicolon)

	return ExpressionStmt{
		Expr:           CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{expr}},
		SourceLocation: loc,
	}
}

func (p *moveParser) parseMoveIf(loc SourceLocation) Statement {
	p.expectIdent("if")

	// Move uses parens around conditions optionally
	hasParen := p.match(moveTokLParen)
	condition := p.parseMoveExpression()
	if hasParen {
		p.expect(moveTokRParen)
	}

	thenBlock := p.parseMoveBlock()

	var elseBlock []Statement
	if p.matchIdent("else") {
		if p.checkIdent("if") {
			elseStmt := p.parseMoveIf(p.loc())
			elseBlock = []Statement{elseStmt}
		} else {
			elseBlock = p.parseMoveBlock()
		}
	}

	return IfStmt{
		Condition:      condition,
		Then:           thenBlock,
		Else:           elseBlock,
		SourceLocation: loc,
	}
}

func (p *moveParser) parseMoveWhile(loc SourceLocation) Statement {
	p.expectIdent("while")

	hasParen := p.match(moveTokLParen)
	condition := p.parseMoveExpression()
	if hasParen {
		p.expect(moveTokRParen)
	}

	body := p.parseMoveBlock()

	// Convert while loop to a for loop with no init/update for AST compatibility
	return ForStmt{
		Init: VariableDeclStmt{
			Name: "_w", Mutable: true, Init: BigIntLiteral{Value: 0}, SourceLocation: loc,
		},
		Condition:      condition,
		Update:         ExpressionStmt{Expr: BigIntLiteral{Value: 0}, SourceLocation: loc},
		Body:           body,
		SourceLocation: loc,
	}
}

func (p *moveParser) parseMoveLoop(loc SourceLocation) Statement {
	p.expectIdent("loop")

	body := p.parseMoveBlock()

	// Convert loop {} to for(;;) {} — infinite loop with true condition
	return ForStmt{
		Init: VariableDeclStmt{
			Name: "_l", Mutable: true, Init: BigIntLiteral{Value: 0}, SourceLocation: loc,
		},
		Condition:      BoolLiteral{Value: true},
		Update:         ExpressionStmt{Expr: BigIntLiteral{Value: 0}, SourceLocation: loc},
		Body:           body,
		SourceLocation: loc,
	}
}

func (p *moveParser) parseMoveReturn(loc SourceLocation) Statement {
	p.expectIdent("return")
	var value Expression
	if !p.check(moveTokSemicolon) && !p.check(moveTokRBrace) {
		value = p.parseMoveExpression()
	}
	p.match(moveTokSemicolon)
	return ReturnStmt{Value: value, SourceLocation: loc}
}

func (p *moveParser) parseMoveExprStatement(loc SourceLocation) Statement {
	expr := p.parseMoveExpression()
	if expr == nil {
		p.advance()
		return nil
	}

	// Check for assignment: expr = value
	if p.match(moveTokAssign) {
		value := p.parseMoveExpression()
		p.expect(moveTokSemicolon)
		return AssignmentStmt{Target: expr, Value: value, SourceLocation: loc}
	}

	// Check for compound assignment
	compoundOps := map[moveTokenKind]string{
		moveTokPlusEq:    "+",
		moveTokMinusEq:   "-",
		moveTokStarEq:    "*",
		moveTokSlashEq:   "/",
		moveTokPercentEq: "%",
	}
	for kind, binOp := range compoundOps {
		if p.match(kind) {
			right := p.parseMoveExpression()
			p.expect(moveTokSemicolon)
			value := BinaryExpr{Op: binOp, Left: expr, Right: right}
			return AssignmentStmt{Target: expr, Value: value, SourceLocation: loc}
		}
	}

	p.match(moveTokSemicolon)
	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// Expression parsing (recursive descent with precedence)
// ---------------------------------------------------------------------------

func (p *moveParser) parseMoveExpression() Expression {
	return p.parseMoveOr()
}

func (p *moveParser) parseMoveOr() Expression {
	left := p.parseMoveAnd()
	for p.match(moveTokPipePipe) {
		right := p.parseMoveAnd()
		left = BinaryExpr{Op: "||", Left: left, Right: right}
	}
	return left
}

func (p *moveParser) parseMoveAnd() Expression {
	left := p.parseMoveBitwiseOr()
	for p.match(moveTokAmpAmp) {
		right := p.parseMoveBitwiseOr()
		left = BinaryExpr{Op: "&&", Left: left, Right: right}
	}
	return left
}

func (p *moveParser) parseMoveBitwiseOr() Expression {
	left := p.parseMoveBitwiseXor()
	for p.match(moveTokPipe) {
		right := p.parseMoveBitwiseXor()
		left = BinaryExpr{Op: "|", Left: left, Right: right}
	}
	return left
}

func (p *moveParser) parseMoveBitwiseXor() Expression {
	left := p.parseMoveBitwiseAnd()
	for p.match(moveTokCaret) {
		right := p.parseMoveBitwiseAnd()
		left = BinaryExpr{Op: "^", Left: left, Right: right}
	}
	return left
}

func (p *moveParser) parseMoveBitwiseAnd() Expression {
	left := p.parseMoveEquality()
	for p.match(moveTokAmp) {
		right := p.parseMoveEquality()
		left = BinaryExpr{Op: "&", Left: left, Right: right}
	}
	return left
}

func (p *moveParser) parseMoveEquality() Expression {
	left := p.parseMoveComparison()
	for {
		if p.match(moveTokEqEq) {
			right := p.parseMoveComparison()
			left = BinaryExpr{Op: "===", Left: left, Right: right} // Map == to ===
		} else if p.match(moveTokNotEq) {
			right := p.parseMoveComparison()
			left = BinaryExpr{Op: "!==", Left: left, Right: right} // Map != to !==
		} else {
			break
		}
	}
	return left
}

func (p *moveParser) parseMoveComparison() Expression {
	left := p.parseMoveAdditive()
	for {
		if p.match(moveTokLt) {
			right := p.parseMoveAdditive()
			left = BinaryExpr{Op: "<", Left: left, Right: right}
		} else if p.match(moveTokLtEq) {
			right := p.parseMoveAdditive()
			left = BinaryExpr{Op: "<=", Left: left, Right: right}
		} else if p.match(moveTokGt) {
			right := p.parseMoveAdditive()
			left = BinaryExpr{Op: ">", Left: left, Right: right}
		} else if p.match(moveTokGtEq) {
			right := p.parseMoveAdditive()
			left = BinaryExpr{Op: ">=", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *moveParser) parseMoveAdditive() Expression {
	left := p.parseMoveMultiplicative()
	for {
		if p.match(moveTokPlus) {
			right := p.parseMoveMultiplicative()
			left = BinaryExpr{Op: "+", Left: left, Right: right}
		} else if p.match(moveTokMinus) {
			right := p.parseMoveMultiplicative()
			left = BinaryExpr{Op: "-", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *moveParser) parseMoveMultiplicative() Expression {
	left := p.parseMoveUnary()
	for {
		if p.match(moveTokStar) {
			right := p.parseMoveUnary()
			left = BinaryExpr{Op: "*", Left: left, Right: right}
		} else if p.match(moveTokSlash) {
			right := p.parseMoveUnary()
			left = BinaryExpr{Op: "/", Left: left, Right: right}
		} else if p.match(moveTokPercent) {
			right := p.parseMoveUnary()
			left = BinaryExpr{Op: "%", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *moveParser) parseMoveUnary() Expression {
	if p.match(moveTokBang) {
		operand := p.parseMoveUnary()
		return UnaryExpr{Op: "!", Operand: operand}
	}
	if p.match(moveTokMinus) {
		operand := p.parseMoveUnary()
		return UnaryExpr{Op: "-", Operand: operand}
	}
	if p.match(moveTokTilde) {
		operand := p.parseMoveUnary()
		return UnaryExpr{Op: "~", Operand: operand}
	}
	// Skip & (reference) — it's a no-op in the Rúnar context
	if p.match(moveTokAmp) {
		if p.matchIdent("mut") {
			// &mut expr — skip both
		}
		return p.parseMoveUnary()
	}
	// Dereference * — also a no-op
	if p.check(moveTokStar) && p.isDeref() {
		p.advance()
		return p.parseMoveUnary()
	}
	return p.parseMovePostfix()
}

func (p *moveParser) isDeref() bool {
	// Simple heuristic: if * is followed by an identifier or (, it's a dereference
	if p.pos+1 < len(p.tokens) {
		next := p.tokens[p.pos+1]
		return next.kind == moveTokIdent || next.kind == moveTokLParen
	}
	return false
}

func (p *moveParser) parseMovePostfix() Expression {
	expr := p.parseMovePrimary()
	for {
		if p.match(moveTokDot) {
			propTok := p.expect(moveTokIdent)
			propName := snakeToCamel(propTok.value)

			// Check if this is a method call
			if p.check(moveTokLParen) {
				args := p.parseMoveCallArgs()
				// Handle contract.field -> PropertyAccessExpr
				if ident, ok := expr.(Identifier); ok && (ident.Name == "self" || ident.Name == "contract") {
					// contract.method() or self.method()
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
				if ident, ok := expr.(Identifier); ok && (ident.Name == "self" || ident.Name == "contract") {
					expr = PropertyAccessExpr{Property: propName}
				} else {
					expr = MemberExpr{Object: expr, Property: propName}
				}
			}
		} else if p.match(moveTokLBracket) {
			index := p.parseMoveExpression()
			p.expect(moveTokRBracket)
			expr = IndexAccessExpr{Object: expr, Index: index}
		} else if p.match(moveTokPlusPlus) {
			expr = IncrementExpr{Operand: expr, Prefix: false}
		} else if p.match(moveTokMinusMinus) {
			expr = DecrementExpr{Operand: expr, Prefix: false}
		} else {
			break
		}
	}
	return expr
}

func (p *moveParser) parseMovePrimary() Expression {
	tok := p.peek()

	switch tok.kind {
	case moveTokNumber:
		p.advance()
		return parseMoveNumber(tok.value)
	case moveTokString:
		p.advance()
		return ByteStringLiteral{Value: tok.value}
	case moveTokIdent:
		p.advance()
		name := tok.value

		// Boolean literals
		if name == "true" {
			return BoolLiteral{Value: true}
		}
		if name == "false" {
			return BoolLiteral{Value: false}
		}
		if name == "self" || name == "contract" {
			return Identifier{Name: name}
		}

		// Handle path access: module::function(...)
		if p.match(moveTokColonColon) {
			nextTok := p.expect(moveTokIdent)
			name = nextTok.value
			// Continue consuming :: segments
			for p.match(moveTokColonColon) {
				nextTok = p.expect(moveTokIdent)
				name = nextTok.value
			}
		}

		// Map builtins
		mappedName := moveMapBuiltin(name)

		// Function call
		if p.check(moveTokLParen) {
			args := p.parseMoveCallArgs()
			return CallExpr{Callee: Identifier{Name: mappedName}, Args: args}
		}

		return Identifier{Name: mappedName}

	case moveTokLParen:
		p.advance()
		expr := p.parseMoveExpression()
		p.expect(moveTokRParen)
		return expr

	default:
		p.addError(fmt.Sprintf("line %d: unexpected token %q", tok.line, tok.value))
		p.advance()
		return BigIntLiteral{Value: 0}
	}
}

func (p *moveParser) parseMoveCallArgs() []Expression {
	p.expect(moveTokLParen)
	var args []Expression
	for !p.check(moveTokRParen) && !p.check(moveTokEOF) {
		arg := p.parseMoveExpression()
		args = append(args, arg)
		if !p.match(moveTokComma) {
			break
		}
	}
	p.expect(moveTokRParen)
	return args
}

func parseMoveNumber(s string) Expression {
	// Strip type suffixes like u64, u128, etc.
	for _, suffix := range []string{"u256", "u128", "u64", "u32", "u16", "u8"} {
		s = strings.TrimSuffix(s, suffix)
	}
	val, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return BigIntLiteral{Value: 0}
	}
	return BigIntLiteral{Value: val}
}

// ---------------------------------------------------------------------------
// Constructor builder
// ---------------------------------------------------------------------------

func (p *moveParser) buildMoveConstructor(properties []PropertyNode) MethodNode {
	var params []ParamNode
	for _, prop := range properties {
		params = append(params, ParamNode{Name: prop.Name, Type: prop.Type})
	}

	superArgs := make([]Expression, len(properties))
	for i, prop := range properties {
		superArgs[i] = Identifier{Name: prop.Name}
	}

	body := []Statement{
		ExpressionStmt{
			Expr: CallExpr{
				Callee: MemberExpr{Object: Identifier{Name: "super"}, Property: ""},
				Args:   superArgs,
			},
			SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
		},
	}

	return MethodNode{
		Name:       "constructor",
		Params:     params,
		Body:       body,
		Visibility: "public",
		SourceLocation: SourceLocation{
			File: p.fileName, Line: 1, Column: 0,
		},
	}
}
