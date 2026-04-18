package frontend

import (
	"fmt"
	"math/big"
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

type solTokenKind int

const (
	solTokEOF solTokenKind = iota
	solTokIdent
	solTokNumber
	solTokHexString
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
	solTokShl       // <<
	solTokShr       // >>
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
	errors   []Diagnostic
}

func (p *solParser) addError(msg string) {
	p.errors = append(p.errors, Diagnostic{Message: msg, Severity: SeverityError})
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
				// Hex byte string literal: 0x... -> ByteString
				i += 2
				col += 2
				hexStart := i
				for i < len(source) && isHexDigit(source[i]) {
					i++
					col++
				}
				tokens = append(tokens, solToken{kind: solTokHexString, value: source[hexStart:i], line: line, col: startCol})
				continue
			}
			for i < len(source) && source[i] >= '0' && source[i] <= '9' {
				i++
				col++
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
			case "<<":
				twoKind = solTokShl
			case ">>":
				twoKind = solTokShr
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

	// Resolve bare property references and bare method calls in method bodies
	// (Solidity allows referencing state variables and other contract methods
	// without the `this.` prefix).
	propNameSet := make(map[string]bool, len(properties))
	for _, prop := range properties {
		propNameSet[prop.Name] = true
	}
	methodNameSet := make(map[string]bool, len(methods))
	for _, m := range methods {
		methodNameSet[m.Name] = true
	}
	for i := range methods {
		paramSet := make(map[string]bool, len(methods[i].Params))
		for _, param := range methods[i].Params {
			paramSet[param.Name] = true
		}
		newBody := make([]Statement, len(methods[i].Body))
		for j, stmt := range methods[i].Body {
			newBody[j] = solRewriteStmtBareProps(stmt, propNameSet, paramSet, methodNameSet)
		}
		methods[i].Body = newBody
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

	// Optional initializer: = value
	var initializer Expression
	if p.match(solTokAssign) {
		initializer = p.parseSolExpression()
	}

	p.expect(solTokSemicolon)

	return &PropertyNode{
		Name:           propName,
		Type:           parseSolType(typeName),
		Readonly:       isReadonly,
		Initializer:    initializer,
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
			Callee: Identifier{Name: "super"},
			Args:   superArgs,
		},
		SourceLocation: loc,
	})

	// Build a rename map for _-prefixed param names (e.g., _pubKeyHash → pubKeyHash)
	renameMap := make(map[string]string)
	for _, param := range params {
		original := "_" + param.Name
		renameMap[original] = param.Name
	}

	// Build set of property names for identifying property assignments
	propNames := make(map[string]bool)
	for _, prop := range properties {
		propNames[prop.Name] = true
	}

	// Process body statements: rename _-prefixed identifiers and convert bare
	// identifier assignments to property access (e.g., pubKeyHash = _pk →
	// this.pubKeyHash = pk) to match validator expectations
	for _, stmt := range body {
		fixed := solRenameIdentifiersInStmt(stmt, renameMap)
		// Convert bare identifier assignments targeting a property name to PropertyAccessExpr
		if assign, ok := fixed.(AssignmentStmt); ok {
			if ident, ok := assign.Target.(Identifier); ok && propNames[ident.Name] {
				assign.Target = PropertyAccessExpr{Property: ident.Name}
				fixed = assign
			}
		}
		constructorBody = append(constructorBody, fixed)
	}

	return MethodNode{
		Name:           "constructor",
		Params:         params,
		Body:           constructorBody,
		Visibility:     "public",
		SourceLocation: loc,
	}
}

// solRenameIdentifiersInStmt recursively renames identifiers in a statement
// using the provided rename map. Used to fix _-prefixed constructor param
// references in the body.
func solRenameIdentifiersInStmt(stmt Statement, renameMap map[string]string) Statement {
	if len(renameMap) == 0 {
		return stmt
	}
	switch s := stmt.(type) {
	case AssignmentStmt:
		s.Target = solRenameIdentifiersInExpr(s.Target, renameMap)
		s.Value = solRenameIdentifiersInExpr(s.Value, renameMap)
		return s
	case ExpressionStmt:
		s.Expr = solRenameIdentifiersInExpr(s.Expr, renameMap)
		return s
	case VariableDeclStmt:
		if s.Init != nil {
			s.Init = solRenameIdentifiersInExpr(s.Init, renameMap)
		}
		return s
	case IfStmt:
		s.Condition = solRenameIdentifiersInExpr(s.Condition, renameMap)
		for i, st := range s.Then {
			s.Then[i] = solRenameIdentifiersInStmt(st, renameMap)
		}
		for i, st := range s.Else {
			s.Else[i] = solRenameIdentifiersInStmt(st, renameMap)
		}
		return s
	case ReturnStmt:
		if s.Value != nil {
			s.Value = solRenameIdentifiersInExpr(s.Value, renameMap)
		}
		return s
	default:
		return stmt
	}
}

// solRewriteExprBareProps recursively rewrites bare Identifier(name) references
// to PropertyAccessExpr when name matches a property of the contract, and bare
// CallExpr(Identifier(name), ...) calls to this.method() when name matches a
// contract method (and is not a built-in function or local variable).
func solRewriteExprBareProps(
	expr Expression,
	propNames map[string]bool,
	paramNames map[string]bool,
	methodNames map[string]bool,
) Expression {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case Identifier:
		if propNames[e.Name] && !paramNames[e.Name] {
			return PropertyAccessExpr{Property: e.Name}
		}
		return e
	case CallExpr:
		// Rewrite bare contract-method calls: foo(args) -> this.foo(args)
		if ident, ok := e.Callee.(Identifier); ok {
			if methodNames[ident.Name] && !paramNames[ident.Name] && !propNames[ident.Name] {
				newArgs := make([]Expression, len(e.Args))
				for i, a := range e.Args {
					newArgs[i] = solRewriteExprBareProps(a, propNames, paramNames, methodNames)
				}
				return CallExpr{
					Callee: MemberExpr{Object: Identifier{Name: "this"}, Property: ident.Name},
					Args:   newArgs,
				}
			}
		}
		newCallee := solRewriteExprBareProps(e.Callee, propNames, paramNames, methodNames)
		newArgs := make([]Expression, len(e.Args))
		for i, a := range e.Args {
			newArgs[i] = solRewriteExprBareProps(a, propNames, paramNames, methodNames)
		}
		return CallExpr{Callee: newCallee, Args: newArgs}
	case BinaryExpr:
		e.Left = solRewriteExprBareProps(e.Left, propNames, paramNames, methodNames)
		e.Right = solRewriteExprBareProps(e.Right, propNames, paramNames, methodNames)
		return e
	case UnaryExpr:
		e.Operand = solRewriteExprBareProps(e.Operand, propNames, paramNames, methodNames)
		return e
	case MemberExpr:
		e.Object = solRewriteExprBareProps(e.Object, propNames, paramNames, methodNames)
		return e
	case TernaryExpr:
		e.Condition = solRewriteExprBareProps(e.Condition, propNames, paramNames, methodNames)
		e.Consequent = solRewriteExprBareProps(e.Consequent, propNames, paramNames, methodNames)
		e.Alternate = solRewriteExprBareProps(e.Alternate, propNames, paramNames, methodNames)
		return e
	case IndexAccessExpr:
		e.Object = solRewriteExprBareProps(e.Object, propNames, paramNames, methodNames)
		e.Index = solRewriteExprBareProps(e.Index, propNames, paramNames, methodNames)
		return e
	case IncrementExpr:
		e.Operand = solRewriteExprBareProps(e.Operand, propNames, paramNames, methodNames)
		return e
	case DecrementExpr:
		e.Operand = solRewriteExprBareProps(e.Operand, propNames, paramNames, methodNames)
		return e
	default:
		return expr
	}
}

// solRewriteStmtBareProps recursively rewrites bare property/method references
// inside a statement, while tracking newly-declared local variables that
// should shadow property names.
func solRewriteStmtBareProps(
	stmt Statement,
	propNames map[string]bool,
	paramNames map[string]bool,
	methodNames map[string]bool,
) Statement {
	rwExpr := func(e Expression) Expression {
		return solRewriteExprBareProps(e, propNames, paramNames, methodNames)
	}
	switch s := stmt.(type) {
	case ExpressionStmt:
		s.Expr = rwExpr(s.Expr)
		return s
	case AssignmentStmt:
		s.Target = rwExpr(s.Target)
		s.Value = rwExpr(s.Value)
		return s
	case VariableDeclStmt:
		// Rewrite the initializer in the *current* scope (the new local does
		// not shadow until after the declaration), then add the new local to
		// the visible param/local set for subsequent statements.
		if s.Init != nil {
			s.Init = rwExpr(s.Init)
		}
		paramNames[s.Name] = true
		return s
	case IfStmt:
		s.Condition = rwExpr(s.Condition)
		thenLocals := copyStringSet(paramNames)
		newThen := make([]Statement, len(s.Then))
		for i, st := range s.Then {
			newThen[i] = solRewriteStmtBareProps(st, propNames, thenLocals, methodNames)
		}
		s.Then = newThen
		if s.Else != nil {
			elseLocals := copyStringSet(paramNames)
			newElse := make([]Statement, len(s.Else))
			for i, st := range s.Else {
				newElse[i] = solRewriteStmtBareProps(st, propNames, elseLocals, methodNames)
			}
			s.Else = newElse
		}
		return s
	case ForStmt:
		// The loop's init declaration is a VariableDeclStmt (Init field).
		bodyLocals := copyStringSet(paramNames)
		if s.Init.Init != nil {
			s.Init.Init = solRewriteExprBareProps(s.Init.Init, propNames, bodyLocals, methodNames)
		}
		bodyLocals[s.Init.Name] = true
		s.Condition = solRewriteExprBareProps(s.Condition, propNames, bodyLocals, methodNames)
		if s.Update != nil {
			s.Update = solRewriteStmtBareProps(s.Update, propNames, bodyLocals, methodNames)
		}
		newBody := make([]Statement, len(s.Body))
		for i, st := range s.Body {
			newBody[i] = solRewriteStmtBareProps(st, propNames, bodyLocals, methodNames)
		}
		s.Body = newBody
		return s
	case ReturnStmt:
		if s.Value != nil {
			s.Value = rwExpr(s.Value)
		}
		return s
	default:
		return stmt
	}
}

func copyStringSet(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// solRenameIdentifiersInExpr recursively renames identifiers in an expression.
func solRenameIdentifiersInExpr(expr Expression, renameMap map[string]string) Expression {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case Identifier:
		if newName, ok := renameMap[e.Name]; ok {
			e.Name = newName
		}
		return e
	case CallExpr:
		e.Callee = solRenameIdentifiersInExpr(e.Callee, renameMap)
		for i, arg := range e.Args {
			e.Args[i] = solRenameIdentifiersInExpr(arg, renameMap)
		}
		return e
	case BinaryExpr:
		e.Left = solRenameIdentifiersInExpr(e.Left, renameMap)
		e.Right = solRenameIdentifiersInExpr(e.Right, renameMap)
		return e
	case UnaryExpr:
		e.Operand = solRenameIdentifiersInExpr(e.Operand, renameMap)
		return e
	case MemberExpr:
		e.Object = solRenameIdentifiersInExpr(e.Object, renameMap)
		return e
	case IndexAccessExpr:
		e.Object = solRenameIdentifiersInExpr(e.Object, renameMap)
		e.Index = solRenameIdentifiersInExpr(e.Index, renameMap)
		return e
	case TernaryExpr:
		e.Condition = solRenameIdentifiersInExpr(e.Condition, renameMap)
		e.Consequent = solRenameIdentifiersInExpr(e.Consequent, renameMap)
		e.Alternate = solRenameIdentifiersInExpr(e.Alternate, renameMap)
		return e
	case PropertyAccessExpr:
		return e
	default:
		return expr
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

	// let Type name = expr; (TypeScript-style local declaration)
	if p.checkIdent("let") {
		p.advance() // consume 'let'
		return p.parseSolVarDecl(loc)
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
			Name: "_i", Mutable: true, Init: BigIntLiteral{Value: big.NewInt(0)}, SourceLocation: loc,
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
		init = BigIntLiteral{Value: big.NewInt(0)}
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
	left := p.parseSolShift()
	for {
		if p.match(solTokLt) {
			right := p.parseSolShift()
			left = BinaryExpr{Op: "<", Left: left, Right: right}
		} else if p.match(solTokLtEq) {
			right := p.parseSolShift()
			left = BinaryExpr{Op: "<=", Left: left, Right: right}
		} else if p.match(solTokGt) {
			right := p.parseSolShift()
			left = BinaryExpr{Op: ">", Left: left, Right: right}
		} else if p.match(solTokGtEq) {
			right := p.parseSolShift()
			left = BinaryExpr{Op: ">=", Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *solParser) parseSolShift() Expression {
	left := p.parseSolAdditive()
	for {
		if p.match(solTokShl) {
			right := p.parseSolAdditive()
			left = BinaryExpr{Op: "<<", Left: left, Right: right}
		} else if p.match(solTokShr) {
			right := p.parseSolAdditive()
			left = BinaryExpr{Op: ">>", Left: left, Right: right}
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
	case solTokHexString:
		p.advance()
		return ByteStringLiteral{Value: tok.value}
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
		return BigIntLiteral{Value: big.NewInt(0)}
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
	bi := new(big.Int)
	if _, ok := bi.SetString(s, 0); !ok {
		return BigIntLiteral{Value: big.NewInt(0)}
	}
	return BigIntLiteral{Value: bi}
}
