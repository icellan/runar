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

// ParseSolidity parses a Solidity-like Rúnar contract and produces the standard AST.
func ParseSolidity(source []byte, fileName string) *ParseResult {
	p := &solParser{
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

type solTokenKind int

const (
	solTokEOF solTokenKind = iota
	solTokIdent
	solTokNumber
	solTokString
	solTokLBrace    // {
	solTokRBrace    // }
	solTokLParen    // (
	solTokRParen    // )
	solTokLBracket  // [
	solTokRBracket  // ]
	solTokSemicolon // ;
	solTokComma     // ,
	solTokDot       // .
	solTokColon     // :
	solTokAssign    // =
	solTokEqEq      // ==
	solTokNotEq     // !=
	solTokLt        // <
	solTokLtEq      // <=
	solTokGt        // >
	solTokGtEq      // >=
	solTokPlus      // +
	solTokMinus     // -
	solTokStar      // *
	solTokSlash     // /
	solTokPercent   // %
	solTokBang      // !
	solTokTilde     // ~
	solTokAmp       // &
	solTokPipe      // |
	solTokCaret     // ^
	solTokAmpAmp    // &&
	solTokPipePipe  // ||
	solTokPlusPlus  // ++
	solTokMinusMinus // --
	solTokPlusEq    // +=
	solTokMinusEq   // -=
	solTokStarEq    // *=
	solTokSlashEq   // /=
	solTokPercentEq // %=
	solTokQuestion  // ?
	solTokHat       // ^
)

type solToken struct {
	kind  solTokenKind
	value string
	line  int
	col   int
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

type solParser struct {
	fileName string
	tokens   []solToken
	pos      int
	errors   []string
}

func (p *solParser) addError(msg string) {
	p.errors = append(p.errors, msg)
}

func (p *solParser) tokenize(source string) []solToken {
	var tokens []solToken
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
			tokens = append(tokens, solToken{kind: solTokString, value: val, line: line, col: startCol})
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
				for i < len(source) && source[i] >= '0' && source[i] <= '9' {
					i++
					col++
				}
			}
			// Skip trailing 'n' for bigint literals
			if i < len(source) && source[i] == 'n' {
				i++
				col++
			}
			tokens = append(tokens, solToken{kind: solTokNumber, value: source[start:i], line: line, col: startCol})
			continue
		}

		// Identifiers and keywords
		if isIdentStart(ch) {
			start := i
			for i < len(source) && isIdentPart(source[i]) {
				i++
				col++
			}
			tokens = append(tokens, solToken{kind: solTokIdent, value: source[start:i], line: line, col: startCol})
			continue
		}

		// Two-character operators
		if i+1 < len(source) {
			two := source[i : i+2]
			var twoKind solTokenKind
			found := true
			switch two {
			case "==":
				twoKind = solTokEqEq
			case "!=":
				twoKind = solTokNotEq
			case "<=":
				twoKind = solTokLtEq
			case ">=":
				twoKind = solTokGtEq
			case "&&":
				twoKind = solTokAmpAmp
			case "||":
				twoKind = solTokPipePipe
			case "++":
				twoKind = solTokPlusPlus
			case "--":
				twoKind = solTokMinusMinus
			case "+=":
				twoKind = solTokPlusEq
			case "-=":
				twoKind = solTokMinusEq
			case "*=":
				twoKind = solTokStarEq
			case "/=":
				twoKind = solTokSlashEq
			case "%=":
				twoKind = solTokPercentEq
			default:
				found = false
			}
			if found {
				tokens = append(tokens, solToken{kind: twoKind, value: two, line: line, col: startCol})
				i += 2
				col += 2
				continue
			}
		}

		// Single-character operators
		var oneKind solTokenKind
		oneFound := true
		switch ch {
		case '{':
			oneKind = solTokLBrace
		case '}':
			oneKind = solTokRBrace
		case '(':
			oneKind = solTokLParen
		case ')':
			oneKind = solTokRParen
		case '[':
			oneKind = solTokLBracket
		case ']':
			oneKind = solTokRBracket
		case ';':
			oneKind = solTokSemicolon
		case ',':
			oneKind = solTokComma
		case '.':
			oneKind = solTokDot
		case ':':
			oneKind = solTokColon
		case '=':
			oneKind = solTokAssign
		case '<':
			oneKind = solTokLt
		case '>':
			oneKind = solTokGt
		case '+':
			oneKind = solTokPlus
		case '-':
			oneKind = solTokMinus
		case '*':
			oneKind = solTokStar
		case '/':
			oneKind = solTokSlash
		case '%':
			oneKind = solTokPercent
		case '!':
			oneKind = solTokBang
		case '~':
			oneKind = solTokTilde
		case '&':
			oneKind = solTokAmp
		case '|':
			oneKind = solTokPipe
		case '^':
			oneKind = solTokCaret
		case '?':
			oneKind = solTokQuestion
		default:
			oneFound = false
		}

		if oneFound {
			tokens = append(tokens, solToken{kind: oneKind, value: string(ch), line: line, col: startCol})
			i++
			col++
			continue
		}

		// Skip unknown characters
		i++
		col++
	}

	tokens = append(tokens, solToken{kind: solTokEOF, value: "", line: line, col: col})
	return tokens
}

func isHexDigit(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

func isIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '$'
}

func isIdentPart(ch byte) bool {
	return isIdentStart(ch) || (ch >= '0' && ch <= '9')
}

// ---------------------------------------------------------------------------
// Parser helpers
// ---------------------------------------------------------------------------

func (p *solParser) peek() solToken {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return solToken{kind: solTokEOF}
}

func (p *solParser) advance() solToken {
	tok := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

func (p *solParser) expect(kind solTokenKind) solToken {
	tok := p.advance()
	if tok.kind != kind {
		p.addError(fmt.Sprintf("line %d: expected token kind %d, got %d (%q)", tok.line, kind, tok.kind, tok.value))
	}
	return tok
}

func (p *solParser) expectIdent(value string) solToken {
	tok := p.advance()
	if tok.kind != solTokIdent || tok.value != value {
		p.addError(fmt.Sprintf("line %d: expected '%s', got %q", tok.line, value, tok.value))
	}
	return tok
}

func (p *solParser) check(kind solTokenKind) bool {
	return p.peek().kind == kind
}

func (p *solParser) checkIdent(value string) bool {
	tok := p.peek()
	return tok.kind == solTokIdent && tok.value == value
}

func (p *solParser) match(kind solTokenKind) bool {
	if p.check(kind) {
		p.advance()
		return true
	}
	return false
}

func (p *solParser) matchIdent(value string) bool {
	if p.checkIdent(value) {
		p.advance()
		return true
	}
	return false
}

func (p *solParser) loc() SourceLocation {
	tok := p.peek()
	return SourceLocation{File: p.fileName, Line: tok.line, Column: tok.col}
}

// ---------------------------------------------------------------------------
// Contract parsing
// ---------------------------------------------------------------------------

func (p *solParser) parseContract() (*ContractNode, error) {
	// Skip pragma
	if p.checkIdent("pragma") {
		for !p.check(solTokSemicolon) && !p.check(solTokEOF) {
			p.advance()
		}
		p.match(solTokSemicolon)
	}

	// Skip import statements
	for p.checkIdent("import") {
		for !p.check(solTokSemicolon) && !p.check(solTokEOF) {
			p.advance()
		}
		p.match(solTokSemicolon)
	}

	// contract Name is ParentClass {
	if !p.matchIdent("contract") {
		return nil, fmt.Errorf("expected 'contract' keyword")
	}

	nameTok := p.expect(solTokIdent)
	contractName := nameTok.value

	parentClass := "SmartContract"
	if p.matchIdent("is") {
		parentTok := p.expect(solTokIdent)
		parentClass = parentTok.value
	}

	if parentClass != "SmartContract" && parentClass != "StatefulSmartContract" {
		return nil, fmt.Errorf("unknown parent class: %s", parentClass)
	}

	p.expect(solTokLBrace)

	var properties []PropertyNode
	var constructor *MethodNode
	var methods []MethodNode

	for !p.check(solTokRBrace) && !p.check(solTokEOF) {
		if p.checkIdent("function") {
			method := p.parseFunction()
			methods = append(methods, method)
		} else if p.checkIdent("constructor") {
			ctor := p.parseSolConstructor(properties)
			constructor = &ctor
		} else {
			// Try to parse as a property: Type [immutable] name;
			prop := p.parseSolProperty()
			if prop != nil {
				properties = append(properties, *prop)
			}
		}
	}

	p.expect(solTokRBrace)

	if constructor == nil {
		constructor = &MethodNode{
			Name:       "constructor",
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

// ---------------------------------------------------------------------------
// Property parsing: Type [immutable] name;
// ---------------------------------------------------------------------------

func (p *solParser) parseSolProperty() *PropertyNode {
	loc := p.loc()

	// Read type name
	typeTok := p.advance()
	if typeTok.kind != solTokIdent {
		// Skip unknown tokens
		return nil
	}
	typeName := typeTok.value

	// Check for immutable keyword
	isReadonly := false
	if p.checkIdent("immutable") {
		p.advance()
		isReadonly = true
	}

	// Property name
	nameTok := p.expect(solTokIdent)
	propName := nameTok.value

	p.expect(solTokSemicolon)

	return &PropertyNode{
		Name:           propName,
		Type:           parseSolType(typeName),
		Readonly:       isReadonly,
		SourceLocation: loc,
	}
}

func parseSolType(name string) TypeNode {
	// Map Solidity-style types to Rúnar types
	switch name {
	case "uint", "uint256", "int", "int256":
		return PrimitiveType{Name: "bigint"}
	case "bool":
		return PrimitiveType{Name: "boolean"}
	case "bytes":
		return PrimitiveType{Name: "ByteString"}
	case "address":
		return PrimitiveType{Name: "Addr"}
	default:
		if IsPrimitiveType(name) {
			return PrimitiveType{Name: name}
		}
		return CustomType{Name: name}
	}
}

// ---------------------------------------------------------------------------
// Constructor parsing: constructor(Type _name, ...) { ... }
// ---------------------------------------------------------------------------

func (p *solParser) parseSolConstructor(properties []PropertyNode) MethodNode {
	loc := p.loc()
	p.expectIdent("constructor")
	params := p.parseSolParams()
	body := p.parseSolBlock()

	// Build proper constructor body with super() call and assignments
	var constructorBody []Statement

	// super(...) call with all param names
	superArgs := make([]Expression, len(params))
	for i, param := range params {
		superArgs[i] = Identifier{Name: param.Name}
	}
	constructorBody = append(constructorBody, ExpressionStmt{
		Expr: CallExpr{
			Callee: MemberExpr{Object: Identifier{Name: "super"}, Property: ""},
			Args:   superArgs,
		},
		SourceLocation: loc,
	})

	// Append any additional statements from the body (except simple assignments
	// that mirror constructor params — these are the "pubKeyHash = _pubKeyHash" patterns)
	for _, stmt := range body {
		constructorBody = append(constructorBody, stmt)
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
// Function parsing: function name(Type name, ...) [public|private] { ... }
// ---------------------------------------------------------------------------

func (p *solParser) parseFunction() MethodNode {
	loc := p.loc()
	p.expectIdent("function")

	nameTok := p.expect(solTokIdent)
	name := nameTok.value

	params := p.parseSolParams()

	// Parse visibility modifiers
	visibility := "private"
	for p.checkIdent("public") || p.checkIdent("private") || p.checkIdent("external") ||
		p.checkIdent("internal") || p.checkIdent("view") || p.checkIdent("pure") ||
		p.checkIdent("returns") || p.checkIdent("payable") {
		tok := p.advance()
		if tok.value == "public" || tok.value == "external" {
			visibility = "public"
		}
		// Skip 'returns (Type)' clause
		if tok.value == "returns" {
			if p.check(solTokLParen) {
				p.advance()
				depth := 1
				for depth > 0 && !p.check(solTokEOF) {
					if p.check(solTokLParen) {
						depth++
					}
					if p.check(solTokRParen) {
						depth--
					}
					p.advance()
				}
			}
		}
	}

	body := p.parseSolBlock()

	return MethodNode{
		Name:           name,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// Parameter parsing: (Type name, Type name, ...)
// ---------------------------------------------------------------------------

func (p *solParser) parseSolParams() []ParamNode {
	p.expect(solTokLParen)
	var params []ParamNode
	for !p.check(solTokRParen) && !p.check(solTokEOF) {
		typeTok := p.expect(solTokIdent)
		typeName := typeTok.value

		// Skip memory/storage/calldata qualifiers
		for p.checkIdent("memory") || p.checkIdent("storage") || p.checkIdent("calldata") {
			p.advance()
		}

		nameTok := p.expect(solTokIdent)
		paramName := nameTok.value
		// Strip leading underscore if present (Solidity convention)
		cleanName := strings.TrimPrefix(paramName, "_")

		params = append(params, ParamNode{
			Name: cleanName,
			Type: parseSolType(typeName),
		})

		if !p.match(solTokComma) {
			break
		}
	}
	p.expect(solTokRParen)
	return params
}

// ---------------------------------------------------------------------------
// Block parsing: { statements... }
// ---------------------------------------------------------------------------

func (p *solParser) parseSolBlock() []Statement {
	p.expect(solTokLBrace)
	var stmts []Statement
	for !p.check(solTokRBrace) && !p.check(solTokEOF) {
		stmt := p.parseSolStatement()
		if stmt != nil {
			stmts = append(stmts, stmt)
		}
	}
	p.expect(solTokRBrace)
	return stmts
}

// ---------------------------------------------------------------------------
// Statement parsing
// ---------------------------------------------------------------------------

func (p *solParser) parseSolStatement() Statement {
	loc := p.loc()

	// require(...) -> assert(...)
	if p.checkIdent("require") {
		return p.parseSolRequire(loc)
	}

	// if (...) { ... } [else { ... }]
	if p.checkIdent("if") {
		return p.parseSolIf(loc)
	}

	// for (...) { ... }
	if p.checkIdent("for") {
		return p.parseSolFor(loc)
	}

	// return ...;
	if p.checkIdent("return") {
		return p.parseSolReturn(loc)
	}

	// Variable declarations: Type name = expr;
	// We need to check if the current identifier is a type followed by another identifier
	if p.peek().kind == solTokIdent && p.isTypeStart() {
		return p.parseSolVarDecl(loc)
	}

	// Assignment or expression statement
	return p.parseSolExprStatement(loc)
}

func (p *solParser) isTypeStart() bool {
	// Look ahead to check if this is "Type name" pattern
	if p.pos+1 >= len(p.tokens) {
		return false
	}
	next := p.tokens[p.pos+1]
	// If next token is an identifier (and not an operator or punctuation), this might be a type
	if next.kind == solTokIdent {
		name := p.peek().value
		// Known types or capitalized names
		if IsPrimitiveType(name) || parseSolType(name) != (CustomType{Name: name}) {
			return true
		}
		if len(name) > 0 && unicode.IsUpper(rune(name[0])) {
			return true
		}
		// Common Solidity types
		switch name {
		case "uint", "uint256", "int", "int256", "bool", "bytes", "address", "string":
			return true
		}
	}
	return false
}

func (p *solParser) parseSolRequire(loc SourceLocation) Statement {
	p.expectIdent("require")
	p.expect(solTokLParen)
	expr := p.parseSolExpression()
	// Skip optional error message parameter
	if p.match(solTokComma) {
		// Consume and discard error message
		p.parseSolExpression()
	}
	p.expect(solTokRParen)
	p.expect(solTokSemicolon)
	return ExpressionStmt{
		Expr:           CallExpr{Callee: Identifier{Name: "assert"}, Args: []Expression{expr}},
		SourceLocation: loc,
	}
}

func (p *solParser) parseSolIf(loc SourceLocation) Statement {
	p.expectIdent("if")
	p.expect(solTokLParen)
	condition := p.parseSolExpression()
	p.expect(solTokRParen)

	thenBlock := p.parseSolBlock()

	var elseBlock []Statement
	if p.matchIdent("else") {
		if p.checkIdent("if") {
			// else if — recurse
			elseStmt := p.parseSolIf(p.loc())
			elseBlock = []Statement{elseStmt}
		} else {
			elseBlock = p.parseSolBlock()
		}
	}

	return IfStmt{
		Condition:      condition,
		Then:           thenBlock,
		Else:           elseBlock,
		SourceLocation: loc,
	}
}

func (p *solParser) parseSolFor(loc SourceLocation) Statement {
	p.expectIdent("for")
	p.expect(solTokLParen)

	// Initializer
	var initStmt VariableDeclStmt
	if p.isTypeStart() || p.checkIdent("uint") || p.checkIdent("int") {
		typeTok := p.advance()
		nameTok := p.expect(solTokIdent)
		p.expect(solTokAssign)
		initExpr := p.parseSolExpression()
		p.expect(solTokSemicolon)
		initStmt = VariableDeclStmt{
			Name:           nameTok.value,
			Type:           parseSolType(typeTok.value),
			Mutable:        true,
			Init:           initExpr,
			SourceLocation: loc,
		}
	} else {
		p.expect(solTokSemicolon)
		initStmt = VariableDeclStmt{
			Name: "_i", Mutable: true, Init: BigIntLiteral{Value: 0}, SourceLocation: loc,
		}
	}

	// Condition
	condition := p.parseSolExpression()
	p.expect(solTokSemicolon)

	// Update
	updateExpr := p.parseSolExpression()
	var update Statement
	update = ExpressionStmt{Expr: updateExpr, SourceLocation: loc}

	p.expect(solTokRParen)

	body := p.parseSolBlock()

	return ForStmt{
		Init:           initStmt,
		Condition:      condition,
		Update:         update,
		Body:           body,
		SourceLocation: loc,
	}
}

func (p *solParser) parseSolReturn(loc SourceLocation) Statement {
	p.expectIdent("return")
	var value Expression
	if !p.check(solTokSemicolon) {
		value = p.parseSolExpression()
	}
	p.expect(solTokSemicolon)
	return ReturnStmt{Value: value, SourceLocation: loc}
}

func (p *solParser) parseSolVarDecl(loc SourceLocation) Statement {
	typeTok := p.advance()
	typeName := typeTok.value

	nameTok := p.expect(solTokIdent)
	varName := nameTok.value

	var init Expression
	if p.match(solTokAssign) {
		init = p.parseSolExpression()
	} else {
		init = BigIntLiteral{Value: 0}
	}

	p.expect(solTokSemicolon)

	return VariableDeclStmt{
		Name:           varName,
		Type:           parseSolType(typeName),
		Mutable:        true, // Solidity variables are mutable by default
		Init:           init,
		SourceLocation: loc,
	}
}

func (p *solParser) parseSolExprStatement(loc SourceLocation) Statement {
	expr := p.parseSolExpression()
	if expr == nil {
		// Skip a token to avoid infinite loops
		p.advance()
		return nil
	}

	// Check for assignment
	if p.match(solTokAssign) {
		value := p.parseSolExpression()
		p.expect(solTokSemicolon)
		return AssignmentStmt{Target: expr, Value: value, SourceLocation: loc}
	}

	// Check for compound assignment
	compoundOps := map[solTokenKind]string{
		solTokPlusEq:    "+",
		solTokMinusEq:   "-",
		solTokStarEq:    "*",
		solTokSlashEq:   "/",
		solTokPercentEq: "%",
	}
	for kind, binOp := range compoundOps {
		if p.match(kind) {
			right := p.parseSolExpression()
			p.expect(solTokSemicolon)
			value := BinaryExpr{Op: binOp, Left: expr, Right: right}
			return AssignmentStmt{Target: expr, Value: value, SourceLocation: loc}
		}
	}

	p.expect(solTokSemicolon)
	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// Expression parsing (recursive descent with precedence)
// ---------------------------------------------------------------------------

func (p *solParser) parseSolExpression() Expression {
	return p.parseSolTernary()
}

func (p *solParser) parseSolTernary() Expression {
	expr := p.parseSolOr()
	if p.match(solTokQuestion) {
		consequent := p.parseSolExpression()
		p.expect(solTokColon)
		alternate := p.parseSolExpression()
		return TernaryExpr{Condition: expr, Consequent: consequent, Alternate: alternate}
	}
	return expr
}

func (p *solParser) parseSolOr() Expression {
	left := p.parseSolAnd()
	for p.match(solTokPipePipe) {
		right := p.parseSolAnd()
		left = BinaryExpr{Op: "||", Left: left, Right: right}
	}
	return left
}

func (p *solParser) parseSolAnd() Expression {
	left := p.parseSolBitwiseOr()
	for p.match(solTokAmpAmp) {
		right := p.parseSolBitwiseOr()
		left = BinaryExpr{Op: "&&", Left: left, Right: right}
	}
	return left
}

func (p *solParser) parseSolBitwiseOr() Expression {
	left := p.parseSolBitwiseXor()
	for p.match(solTokPipe) {
		right := p.parseSolBitwiseXor()
		left = BinaryExpr{Op: "|", Left: left, Right: right}
	}
	return left
}

func (p *solParser) parseSolBitwiseXor() Expression {
	left := p.parseSolBitwiseAnd()
	for p.match(solTokCaret) {
		right := p.parseSolBitwiseAnd()
		left = BinaryExpr{Op: "^", Left: left, Right: right}
	}
	return left
}

func (p *solParser) parseSolBitwiseAnd() Expression {
	left := p.parseSolEquality()
	for p.match(solTokAmp) {
		right := p.parseSolEquality()
		left = BinaryExpr{Op: "&", Left: left, Right: right}
	}
	return left
}

func (p *solParser) parseSolEquality() Expression {
	left := p.parseSolComparison()
	for {
		if p.match(solTokEqEq) {
			right := p.parseSolComparison()
			left = BinaryExpr{Op: "===", Left: left, Right: right} // Map == to ===
		} else if p.match(solTokNotEq) {
			right := p.parseSolComparison()
			left = BinaryExpr{Op: "!==", Left: left, Right: right} // Map != to !==
		} else {
			break
		}
	}
	return left
}

func (p *solParser) parseSolComparison() Expression {
	left := p.parseSolAdditive()
	for {
		if p.match(solTokLt) {
			right := p.parseSolAdditive()
			left = BinaryExpr{Op: "<", Left: left, Right: right}
		} else if p.match(solTokLtEq) {
			right := p.parseSolAdditive()
			left = BinaryExpr{Op: "<=", Left: left, Right: right}
		} else if p.match(solTokGt) {
			right := p.parseSolAdditive()
			left = BinaryExpr{Op: ">", Left: left, Right: right}
		} else if p.match(solTokGtEq) {
			right := p.parseSolAdditive()
			left = BinaryExpr{Op: ">=", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *solParser) parseSolAdditive() Expression {
	left := p.parseSolMultiplicative()
	for {
		if p.match(solTokPlus) {
			right := p.parseSolMultiplicative()
			left = BinaryExpr{Op: "+", Left: left, Right: right}
		} else if p.match(solTokMinus) {
			right := p.parseSolMultiplicative()
			left = BinaryExpr{Op: "-", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *solParser) parseSolMultiplicative() Expression {
	left := p.parseSolUnary()
	for {
		if p.match(solTokStar) {
			right := p.parseSolUnary()
			left = BinaryExpr{Op: "*", Left: left, Right: right}
		} else if p.match(solTokSlash) {
			right := p.parseSolUnary()
			left = BinaryExpr{Op: "/", Left: left, Right: right}
		} else if p.match(solTokPercent) {
			right := p.parseSolUnary()
			left = BinaryExpr{Op: "%", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *solParser) parseSolUnary() Expression {
	if p.match(solTokBang) {
		operand := p.parseSolUnary()
		return UnaryExpr{Op: "!", Operand: operand}
	}
	if p.match(solTokMinus) {
		operand := p.parseSolUnary()
		return UnaryExpr{Op: "-", Operand: operand}
	}
	if p.match(solTokTilde) {
		operand := p.parseSolUnary()
		return UnaryExpr{Op: "~", Operand: operand}
	}
	// Prefix increment/decrement
	if p.match(solTokPlusPlus) {
		operand := p.parseSolUnary()
		return IncrementExpr{Operand: operand, Prefix: true}
	}
	if p.match(solTokMinusMinus) {
		operand := p.parseSolUnary()
		return DecrementExpr{Operand: operand, Prefix: true}
	}
	return p.parseSolPostfix()
}

func (p *solParser) parseSolPostfix() Expression {
	expr := p.parseSolPrimary()
	for {
		if p.match(solTokDot) {
			propTok := p.expect(solTokIdent)
			propName := propTok.value

			// Check if this is a method call: obj.method(...)
			if p.check(solTokLParen) {
				args := p.parseSolCallArgs()
				// Handle this.addOutput(...)
				if ident, ok := expr.(Identifier); ok && ident.Name == "this" {
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
				if ident, ok := expr.(Identifier); ok && ident.Name == "this" {
					expr = PropertyAccessExpr{Property: propName}
				} else {
					expr = MemberExpr{Object: expr, Property: propName}
				}
			}
		} else if p.match(solTokLBracket) {
			index := p.parseSolExpression()
			p.expect(solTokRBracket)
			expr = IndexAccessExpr{Object: expr, Index: index}
		} else if p.match(solTokPlusPlus) {
			expr = IncrementExpr{Operand: expr, Prefix: false}
		} else if p.match(solTokMinusMinus) {
			expr = DecrementExpr{Operand: expr, Prefix: false}
		} else {
			break
		}
	}
	return expr
}

func (p *solParser) parseSolPrimary() Expression {
	tok := p.peek()

	switch tok.kind {
	case solTokNumber:
		p.advance()
		return parseSolNumber(tok.value)
	case solTokString:
		p.advance()
		return ByteStringLiteral{Value: tok.value}
	case solTokIdent:
		p.advance()
		name := tok.value

		// Boolean literals
		if name == "true" {
			return BoolLiteral{Value: true}
		}
		if name == "false" {
			return BoolLiteral{Value: false}
		}
		if name == "this" {
			return Identifier{Name: "this"}
		}

		// Function call
		if p.check(solTokLParen) {
			args := p.parseSolCallArgs()
			return CallExpr{Callee: Identifier{Name: name}, Args: args}
		}

		return Identifier{Name: name}
	case solTokLParen:
		p.advance()
		expr := p.parseSolExpression()
		p.expect(solTokRParen)
		return expr
	default:
		p.addError(fmt.Sprintf("line %d: unexpected token %q", tok.line, tok.value))
		p.advance()
		return BigIntLiteral{Value: 0}
	}
}

func (p *solParser) parseSolCallArgs() []Expression {
	p.expect(solTokLParen)
	var args []Expression
	for !p.check(solTokRParen) && !p.check(solTokEOF) {
		arg := p.parseSolExpression()
		args = append(args, arg)
		if !p.match(solTokComma) {
			break
		}
	}
	p.expect(solTokRParen)
	return args
}

func parseSolNumber(s string) Expression {
	// Strip trailing 'n'
	if strings.HasSuffix(s, "n") {
		s = s[:len(s)-1]
	}
	val, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return BigIntLiteral{Value: 0}
	}
	return BigIntLiteral{Value: val}
}
