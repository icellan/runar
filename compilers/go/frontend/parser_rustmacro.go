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

// ParseRustMacro parses a Rust macro-style Rúnar contract (.runar.rs) and
// produces the standard Rúnar AST. Uses a hand-written tokenizer and
// recursive descent parser.
func ParseRustMacro(source []byte, fileName string) *ParseResult {
	tokens := rustTokenize(string(source))
	p := &rustMacroParser{
		tokens:   tokens,
		pos:      0,
		fileName: fileName,
	}

	contract := p.parse()
	return &ParseResult{
		Contract: contract,
		Errors:   p.errors,
	}
}

// ---------------------------------------------------------------------------
// Token types
// ---------------------------------------------------------------------------

type rustTokKind int

const (
	rustTokEOF rustTokKind = iota
	rustTokUse
	rustTokStruct
	rustTokImpl
	rustTokFn
	rustTokPub
	rustTokLet
	rustTokMut
	rustTokIf
	rustTokElse
	rustTokFor
	rustTokReturn
	rustTokIn
	rustTokTrue
	rustTokFalse
	rustTokSelf
	rustTokAssertMacro
	rustTokAssertEqMacro
	rustTokIdent
	rustTokNumber
	rustTokHexString // 0x... or double-quoted string
	rustTokHashBracket
	rustTokLParen
	rustTokRParen
	rustTokLBrace
	rustTokRBrace
	rustTokLBracket
	rustTokRBracket
	rustTokSemi
	rustTokComma
	rustTokDot
	rustTokColon
	rustTokColonColon
	rustTokArrow
	rustTokPlus
	rustTokMinus
	rustTokStar
	rustTokSlash
	rustTokPercent
	rustTokEqEq
	rustTokBangEq
	rustTokLt
	rustTokLtEq
	rustTokGt
	rustTokGtEq
	rustTokAmpAmp
	rustTokPipePipe
	rustTokAmp
	rustTokPipe
	rustTokCaret
	rustTokTilde
	rustTokBang
	rustTokEq
	rustTokPlusEq
	rustTokMinusEq
)

type rustToken struct {
	kind  rustTokKind
	value string
	line  int
	col   int
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

func rustTokenize(source string) []rustToken {
	chars := []rune(source)
	var tokens []rustToken
	pos := 0
	line := 1
	col := 1

	for pos < len(chars) {
		ch := chars[pos]
		l, c := line, col

		// Whitespace
		if ch == '\n' {
			line++
			col = 1
			pos++
			continue
		}
		if unicode.IsSpace(ch) {
			col++
			pos++
			continue
		}

		// Line comments: // and ///
		if ch == '/' && pos+1 < len(chars) && chars[pos+1] == '/' {
			for pos < len(chars) && chars[pos] != '\n' {
				pos++
				col++
			}
			continue
		}

		// Block comments: /* ... */
		if ch == '/' && pos+1 < len(chars) && chars[pos+1] == '*' {
			pos += 2
			col += 2
			for pos+1 < len(chars) {
				if chars[pos] == '\n' {
					line++
					col = 1
					pos++
				} else if chars[pos] == '*' && chars[pos+1] == '/' {
					pos += 2
					col += 2
					break
				} else {
					pos++
					col++
				}
			}
			continue
		}

		// #[ attribute opener
		if ch == '#' && pos+1 < len(chars) && chars[pos+1] == '[' {
			tokens = append(tokens, rustToken{kind: rustTokHashBracket, line: l, col: c})
			pos += 2
			col += 2
			continue
		}

		// Two-char operators
		if pos+1 < len(chars) {
			two := string(chars[pos : pos+2])
			var kind rustTokKind
			matched := true
			switch two {
			case "::":
				kind = rustTokColonColon
			case "->":
				kind = rustTokArrow
			case "==":
				kind = rustTokEqEq
			case "!=":
				kind = rustTokBangEq
			case "<=":
				kind = rustTokLtEq
			case ">=":
				kind = rustTokGtEq
			case "&&":
				kind = rustTokAmpAmp
			case "||":
				kind = rustTokPipePipe
			case "+=":
				kind = rustTokPlusEq
			case "-=":
				kind = rustTokMinusEq
			default:
				matched = false
			}
			if matched {
				tokens = append(tokens, rustToken{kind: kind, line: l, col: c})
				pos += 2
				col += 2
				continue
			}
		}

		// Single-char tokens
		var singleKind rustTokKind
		singleMatched := true
		switch ch {
		case '(':
			singleKind = rustTokLParen
		case ')':
			singleKind = rustTokRParen
		case '{':
			singleKind = rustTokLBrace
		case '}':
			singleKind = rustTokRBrace
		case '[':
			singleKind = rustTokLBracket
		case ']':
			singleKind = rustTokRBracket
		case ';':
			singleKind = rustTokSemi
		case ',':
			singleKind = rustTokComma
		case '.':
			singleKind = rustTokDot
		case ':':
			singleKind = rustTokColon
		case '+':
			singleKind = rustTokPlus
		case '-':
			singleKind = rustTokMinus
		case '*':
			singleKind = rustTokStar
		case '/':
			singleKind = rustTokSlash
		case '%':
			singleKind = rustTokPercent
		case '<':
			singleKind = rustTokLt
		case '>':
			singleKind = rustTokGt
		case '&':
			singleKind = rustTokAmp
		case '|':
			singleKind = rustTokPipe
		case '^':
			singleKind = rustTokCaret
		case '~':
			singleKind = rustTokTilde
		case '!':
			singleKind = rustTokBang
		case '=':
			singleKind = rustTokEq
		default:
			singleMatched = false
		}
		if singleMatched {
			tokens = append(tokens, rustToken{kind: singleKind, line: l, col: c})
			pos++
			col++
			continue
		}

		// Hex literal: 0x...
		if ch == '0' && pos+1 < len(chars) && chars[pos+1] == 'x' {
			var val strings.Builder
			pos += 2
			col += 2
			for pos < len(chars) && rustIsHexDigit(chars[pos]) {
				val.WriteRune(chars[pos])
				pos++
				col++
			}
			tokens = append(tokens, rustToken{kind: rustTokHexString, value: val.String(), line: l, col: c})
			continue
		}

		// Number
		if ch >= '0' && ch <= '9' {
			var val strings.Builder
			for pos < len(chars) && (chars[pos] >= '0' && chars[pos] <= '9' || chars[pos] == '_') {
				if chars[pos] != '_' {
					val.WriteRune(chars[pos])
				}
				pos++
				col++
			}
			tokens = append(tokens, rustToken{kind: rustTokNumber, value: val.String(), line: l, col: c})
			continue
		}

		// Identifier / keyword
		if ch == '_' || unicode.IsLetter(ch) {
			var val strings.Builder
			for pos < len(chars) && (chars[pos] == '_' || unicode.IsLetter(chars[pos]) || unicode.IsDigit(chars[pos])) {
				val.WriteRune(chars[pos])
				pos++
				col++
			}
			name := val.String()
			// Check for assert! / assert_eq!
			if (name == "assert" || name == "assert_eq") && pos < len(chars) && chars[pos] == '!' {
				pos++
				col++
				kind := rustTokAssertMacro
				if name == "assert_eq" {
					kind = rustTokAssertEqMacro
				}
				tokens = append(tokens, rustToken{kind: kind, line: l, col: c})
				continue
			}
			kind := rustKeyword(name)
			tokens = append(tokens, rustToken{kind: kind, value: name, line: l, col: c})
			continue
		}

		// Double-quoted string — treated as hex ByteString
		if ch == '"' {
			var val strings.Builder
			pos++
			col++
			for pos < len(chars) && chars[pos] != '"' {
				val.WriteRune(chars[pos])
				pos++
				col++
			}
			if pos < len(chars) {
				pos++ // skip closing "
				col++
			}
			tokens = append(tokens, rustToken{kind: rustTokHexString, value: val.String(), line: l, col: c})
			continue
		}

		// Skip unrecognised character
		pos++
		col++
	}

	tokens = append(tokens, rustToken{kind: rustTokEOF, line: line, col: col})
	return tokens
}

func rustKeyword(name string) rustTokKind {
	switch name {
	case "use":
		return rustTokUse
	case "struct":
		return rustTokStruct
	case "impl":
		return rustTokImpl
	case "fn":
		return rustTokFn
	case "pub":
		return rustTokPub
	case "let":
		return rustTokLet
	case "mut":
		return rustTokMut
	case "if":
		return rustTokIf
	case "else":
		return rustTokElse
	case "for":
		return rustTokFor
	case "return":
		return rustTokReturn
	case "in":
		return rustTokIn
	case "true":
		return rustTokTrue
	case "false":
		return rustTokFalse
	case "self":
		return rustTokSelf
	}
	return rustTokIdent
}

func rustIsHexDigit(ch rune) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// ---------------------------------------------------------------------------
// Parser internals
// ---------------------------------------------------------------------------

type rustMacroParser struct {
	tokens   []rustToken
	pos      int
	fileName string
	errors   []string
}

func (p *rustMacroParser) current() rustToken {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return rustToken{kind: rustTokEOF}
}

func (p *rustMacroParser) advance() rustToken {
	t := p.current()
	if p.pos < len(p.tokens)-1 {
		p.pos++
	}
	return t
}

func (p *rustMacroParser) peek() rustToken {
	if p.pos+1 < len(p.tokens) {
		return p.tokens[p.pos+1]
	}
	return rustToken{kind: rustTokEOF}
}

func (p *rustMacroParser) expect(kind rustTokKind) {
	if p.current().kind != kind {
		t := p.current()
		p.errors = append(p.errors, fmt.Sprintf(
			"expected token kind %d, got %d ('%s') at %s:%d:%d",
			kind, t.kind, t.value, p.fileName, t.line, t.col))
	}
	p.advance()
}

func (p *rustMacroParser) match(kind rustTokKind) bool {
	if p.current().kind == kind {
		p.advance()
		return true
	}
	return false
}

func (p *rustMacroParser) loc() SourceLocation {
	t := p.current()
	return SourceLocation{File: p.fileName, Line: t.line, Column: t.col}
}

// ---------------------------------------------------------------------------
// Top-level parse
// ---------------------------------------------------------------------------

func (p *rustMacroParser) parse() *ContractNode {
	// Skip use declarations
	for p.current().kind == rustTokUse {
		for p.current().kind != rustTokSemi && p.current().kind != rustTokEOF {
			p.advance()
		}
		p.match(rustTokSemi)
	}

	var contractName string
	var parentClass string
	var properties []PropertyNode
	var methods []MethodNode

	for p.current().kind != rustTokEOF {
		if p.current().kind == rustTokHashBracket {
			attr := p.parseAttribute()

			switch {
			case attr == "runar::contract" || attr == "runar::stateful_contract":
				if attr == "runar::stateful_contract" {
					parentClass = "StatefulSmartContract"
				}
				// Parse: (pub)? struct Name { ... }
				p.match(rustTokPub)
				p.expect(rustTokStruct)
				if p.current().kind == rustTokIdent {
					contractName = p.current().value
					p.advance()
				}
				p.expect(rustTokLBrace)

				for p.current().kind != rustTokRBrace && p.current().kind != rustTokEOF {
					// Field may have a #[readonly] attribute
					readonly := false
					if p.current().kind == rustTokHashBracket {
						fieldAttr := p.parseAttribute()
						if fieldAttr == "readonly" {
							readonly = true
						}
					}

					// Skip optional pub visibility on fields
					p.match(rustTokPub)

					loc := p.loc()
					if p.current().kind == rustTokIdent {
						fieldName := p.current().value
						p.advance()
						p.expect(rustTokColon)
						fieldType := p.parseRustType()
						p.match(rustTokComma)

						// Skip txPreimage — implicit stateful param, not a contract property
						camelName := rustSnakeToCamel(fieldName)
						if camelName != "txPreimage" {
							properties = append(properties, PropertyNode{
								Name:           camelName,
								Type:           fieldType,
								Readonly:       readonly,
								SourceLocation: loc,
							})
						}
					} else {
						p.advance() // skip unexpected token
					}
				}
				p.expect(rustTokRBrace)

			case strings.HasPrefix(attr, "runar::methods"):
				// Parse: impl Name { ... }
				p.match(rustTokImpl)
				// Skip type name
				if p.current().kind == rustTokIdent {
					p.advance()
				}
				p.expect(rustTokLBrace)

				for p.current().kind != rustTokRBrace && p.current().kind != rustTokEOF {
					visibility := "private"
					if p.current().kind == rustTokHashBracket {
						methodAttr := p.parseAttribute()
						if methodAttr == "public" {
							visibility = "public"
						}
					}
					// `pub fn` also makes it public
					if p.current().kind == rustTokPub {
						p.advance()
						visibility = "public"
					}
					m := p.parseFunction(visibility)
					methods = append(methods, m)
				}
				p.expect(rustTokRBrace)

			default:
				// Unknown attribute — skip
			}
		} else {
			p.advance()
		}
	}

	if contractName == "" {
		p.errors = append(p.errors, "no Rúnar contract struct found in Rust source")
		return nil
	}

	// Derive parent class from property mutability (any non-readonly = stateful)
	if parentClass == "" {
		allReadonly := true
		for _, prop := range properties {
			if !prop.Readonly {
				allReadonly = false
				break
			}
		}
		if allReadonly {
			parentClass = "SmartContract"
		} else {
			parentClass = "StatefulSmartContract"
		}
	}

	// Extract init() as property initializers
	var finalMethods []MethodNode
	for _, m := range methods {
		if m.Name == "init" && len(m.Params) == 0 {
			for _, stmt := range m.Body {
				if assign, ok := stmt.(AssignmentStmt); ok {
					if pa, ok := assign.Target.(PropertyAccessExpr); ok {
						for i := range properties {
							if properties[i].Name == pa.Property {
								properties[i].Initializer = assign.Value
								break
							}
						}
					}
				}
			}
		} else {
			finalMethods = append(finalMethods, m)
		}
	}
	methods = finalMethods

	// Build constructor (only non-initialized properties)
	var uninitProps []PropertyNode
	for _, prop := range properties {
		if prop.Initializer == nil {
			uninitProps = append(uninitProps, prop)
		}
	}

	constructorParams := make([]ParamNode, len(uninitProps))
	for i, prop := range uninitProps {
		constructorParams[i] = ParamNode{Name: prop.Name, Type: prop.Type}
	}

	superArgs := make([]Expression, len(uninitProps))
	for i, prop := range uninitProps {
		superArgs[i] = Identifier{Name: prop.Name}
	}

	ctorLoc := SourceLocation{File: p.fileName, Line: 1, Column: 1}
	superCall := ExpressionStmt{
		Expr: CallExpr{
			Callee: Identifier{Name: "super"},
			Args:   superArgs,
		},
		SourceLocation: ctorLoc,
	}

	ctorBody := make([]Statement, 0, 1+len(uninitProps))
	ctorBody = append(ctorBody, superCall)
	for _, prop := range uninitProps {
		ctorBody = append(ctorBody, AssignmentStmt{
			Target:         PropertyAccessExpr{Property: prop.Name},
			Value:          Identifier{Name: prop.Name},
			SourceLocation: ctorLoc,
		})
	}

	return &ContractNode{
		Name:        contractName,
		ParentClass: parentClass,
		Properties:  properties,
		Constructor: MethodNode{
			Name:           "constructor",
			Params:         constructorParams,
			Body:           ctorBody,
			Visibility:     "public",
			SourceLocation: ctorLoc,
		},
		Methods:    methods,
		SourceFile: p.fileName,
	}
}

// ---------------------------------------------------------------------------
// Attribute parsing
// ---------------------------------------------------------------------------

// parseAttribute consumes an already-peeked HashBracket (#[) and collects
// the attribute text up to the matching ].
func (p *rustMacroParser) parseAttribute() string {
	p.advance() // consume #[
	var attr strings.Builder
	depth := 1
	for depth > 0 && p.current().kind != rustTokEOF {
		switch p.current().kind {
		case rustTokLBracket:
			depth++
			p.advance()
		case rustTokRBracket:
			depth--
			p.advance()
		case rustTokIdent:
			attr.WriteString(p.current().value)
			p.advance()
		case rustTokColonColon:
			attr.WriteString("::")
			p.advance()
		case rustTokLParen:
			attr.WriteByte('(')
			p.advance()
		case rustTokRParen:
			attr.WriteByte(')')
			p.advance()
		default:
			p.advance()
		}
	}
	return attr.String()
}

// ---------------------------------------------------------------------------
// Type parsing
// ---------------------------------------------------------------------------

func (p *rustMacroParser) parseRustType() TypeNode {
	// Skip optional & and mut (reference types)
	p.match(rustTokAmp)
	p.match(rustTokMut)

	if p.current().kind == rustTokIdent {
		name := p.current().value
		p.advance()
		mapped := rustMapType(name)
		if IsPrimitiveType(mapped) {
			return PrimitiveType{Name: mapped}
		}
		return CustomType{Name: mapped}
	}
	p.advance()
	return CustomType{Name: "unknown"}
}

func rustMapType(name string) string {
	switch name {
	case "Bigint", "Int", "i64", "u64", "i128", "u128":
		return "bigint"
	case "Bool", "bool":
		return "boolean"
	case "ByteString", "Vec":
		return "ByteString"
	case "String":
		return "ByteString"
	}
	// Pass through Rúnar primitives: PubKey, Sig, Addr, Sha256, Ripemd160, etc.
	return name
}

// ---------------------------------------------------------------------------
// Function parsing
// ---------------------------------------------------------------------------

func (p *rustMacroParser) parseFunction(visibility string) MethodNode {
	loc := p.loc()
	p.expect(rustTokFn)

	rawName := "unknown"
	if p.current().kind == rustTokIdent {
		rawName = p.current().value
		p.advance()
	}
	name := rustSnakeToCamel(rawName)

	p.expect(rustTokLParen)
	var params []ParamNode

	for p.current().kind != rustTokRParen && p.current().kind != rustTokEOF {
		// Skip &self, &mut self, self
		if p.current().kind == rustTokAmp {
			p.advance()
			p.match(rustTokMut)
			if p.current().kind == rustTokSelf {
				p.advance()
				p.match(rustTokComma)
				continue
			}
		}
		if p.current().kind == rustTokSelf {
			p.advance()
			p.match(rustTokComma)
			continue
		}

		if p.current().kind == rustTokIdent {
			paramName := p.current().value
			p.advance()
			p.expect(rustTokColon)
			paramType := p.parseRustType()
			params = append(params, ParamNode{
				Name: rustSnakeToCamel(paramName),
				Type: paramType,
			})
		} else {
			p.advance()
		}
		p.match(rustTokComma)
	}
	p.expect(rustTokRParen)

	// Optional return type: -> Type
	if p.current().kind == rustTokArrow {
		p.advance()
		p.parseRustType() // consume and discard
	}

	p.expect(rustTokLBrace)
	var body []Statement
	for p.current().kind != rustTokRBrace && p.current().kind != rustTokEOF {
		if stmt := p.parseStatement(); stmt != nil {
			body = append(body, stmt)
		}
	}
	p.expect(rustTokRBrace)

	return MethodNode{
		Name:           name,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// Statement parsing
// ---------------------------------------------------------------------------

func (p *rustMacroParser) parseStatement() Statement {
	loc := p.loc()

	// assert!(expr)
	if p.current().kind == rustTokAssertMacro {
		p.advance()
		p.expect(rustTokLParen)
		expr := p.parseExpression()
		p.expect(rustTokRParen)
		p.match(rustTokSemi)
		return ExpressionStmt{
			Expr: CallExpr{
				Callee: Identifier{Name: "assert"},
				Args:   []Expression{expr},
			},
			SourceLocation: loc,
		}
	}

	// assert_eq!(a, b)
	if p.current().kind == rustTokAssertEqMacro {
		p.advance()
		p.expect(rustTokLParen)
		left := p.parseExpression()
		p.expect(rustTokComma)
		right := p.parseExpression()
		p.expect(rustTokRParen)
		p.match(rustTokSemi)
		return ExpressionStmt{
			Expr: CallExpr{
				Callee: Identifier{Name: "assert"},
				Args: []Expression{BinaryExpr{
					Op:    "===",
					Left:  left,
					Right: right,
				}},
			},
			SourceLocation: loc,
		}
	}

	// let [mut] name [: Type] = expr;
	if p.current().kind == rustTokLet {
		p.advance()
		mutable := p.match(rustTokMut)
		varName := "unknown"
		if p.current().kind == rustTokIdent {
			varName = rustSnakeToCamel(p.current().value)
			p.advance()
		}
		var typeNode TypeNode
		if p.current().kind == rustTokColon {
			p.advance()
			typeNode = p.parseRustType()
		}
		p.expect(rustTokEq)
		init := p.parseExpression()
		p.match(rustTokSemi)
		return VariableDeclStmt{
			Name:           varName,
			Type:           typeNode,
			Mutable:        mutable,
			Init:           init,
			SourceLocation: loc,
		}
	}

	// if expr { ... } [else { ... }]
	if p.current().kind == rustTokIf {
		p.advance()
		condition := p.parseExpression()
		p.expect(rustTokLBrace)
		var thenBranch []Statement
		for p.current().kind != rustTokRBrace && p.current().kind != rustTokEOF {
			if s := p.parseStatement(); s != nil {
				thenBranch = append(thenBranch, s)
			}
		}
		p.expect(rustTokRBrace)
		var elseBranch []Statement
		if p.current().kind == rustTokElse {
			p.advance()
			p.expect(rustTokLBrace)
			for p.current().kind != rustTokRBrace && p.current().kind != rustTokEOF {
				if s := p.parseStatement(); s != nil {
					elseBranch = append(elseBranch, s)
				}
			}
			p.expect(rustTokRBrace)
		}
		return IfStmt{
			Condition:      condition,
			Then:           thenBranch,
			Else:           elseBranch,
			SourceLocation: loc,
		}
	}

	// for var in expr { ... }
	if p.current().kind == rustTokFor {
		p.advance()
		varName := "_i"
		if p.current().kind == rustTokIdent {
			varName = rustSnakeToCamel(p.current().value)
			p.advance()
		}
		p.match(rustTokIn)
		rangeExpr := p.parseExpression()
		p.expect(rustTokLBrace)
		var body []Statement
		for p.current().kind != rustTokRBrace && p.current().kind != rustTokEOF {
			if s := p.parseStatement(); s != nil {
				body = append(body, s)
			}
		}
		p.expect(rustTokRBrace)
		// Desugar: for i in 0..n { body } → for (let i = 0; i < n; i++) { body }
		initStmt := VariableDeclStmt{
			Name:           varName,
			Mutable:        true,
			Init:           BigIntLiteral{Value: 0},
			SourceLocation: loc,
		}
		cond := BinaryExpr{
			Op:    "<",
			Left:  Identifier{Name: varName},
			Right: rangeExpr,
		}
		update := ExpressionStmt{
			Expr:           IncrementExpr{Operand: Identifier{Name: varName}, Prefix: false},
			SourceLocation: loc,
		}
		return ForStmt{
			Init:           initStmt,
			Condition:      cond,
			Update:         update,
			Body:           body,
			SourceLocation: loc,
		}
	}

	// return [expr];
	if p.current().kind == rustTokReturn {
		p.advance()
		var value Expression
		if p.current().kind != rustTokSemi && p.current().kind != rustTokRBrace && p.current().kind != rustTokEOF {
			value = p.parseExpression()
		}
		p.match(rustTokSemi)
		return ReturnStmt{Value: value, SourceLocation: loc}
	}

	// Expression statement (including assignments, compound assignments)
	expr := p.parseExpression()

	// Simple assignment: lhs = rhs
	if p.current().kind == rustTokEq {
		p.advance()
		value := p.parseExpression()
		p.match(rustTokSemi)
		return AssignmentStmt{
			Target:         rustConvertSelfAccess(expr),
			Value:          value,
			SourceLocation: loc,
		}
	}

	// Compound assignment: lhs += rhs  /  lhs -= rhs
	if p.current().kind == rustTokPlusEq {
		p.advance()
		rhs := p.parseExpression()
		p.match(rustTokSemi)
		target := rustConvertSelfAccess(expr)
		return AssignmentStmt{
			Target:         target,
			Value:          BinaryExpr{Op: "+", Left: target, Right: rhs},
			SourceLocation: loc,
		}
	}
	if p.current().kind == rustTokMinusEq {
		p.advance()
		rhs := p.parseExpression()
		p.match(rustTokSemi)
		target := rustConvertSelfAccess(expr)
		return AssignmentStmt{
			Target:         target,
			Value:          BinaryExpr{Op: "-", Left: target, Right: rhs},
			SourceLocation: loc,
		}
	}

	hadSemi := p.match(rustTokSemi)
	// Implicit return: expression without semicolon right before }
	if !hadSemi && p.current().kind == rustTokRBrace {
		return ReturnStmt{Value: expr, SourceLocation: loc}
	}

	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

// rustConvertSelfAccess turns self.field → PropertyAccessExpr{Property: "field"}.
func rustConvertSelfAccess(expr Expression) Expression {
	if me, ok := expr.(MemberExpr); ok {
		if id, ok := me.Object.(Identifier); ok && id.Name == "self" {
			return PropertyAccessExpr{Property: me.Property}
		}
	}
	return expr
}

// ---------------------------------------------------------------------------
// Expression parsing — precedence climbing
// ---------------------------------------------------------------------------

func (p *rustMacroParser) parseExpression() Expression { return p.parseOr() }

func (p *rustMacroParser) parseOr() Expression {
	left := p.parseAnd()
	for p.current().kind == rustTokPipePipe {
		p.advance()
		right := p.parseAnd()
		left = BinaryExpr{Op: "||", Left: left, Right: right}
	}
	return left
}

func (p *rustMacroParser) parseAnd() Expression {
	left := p.parseBitOr()
	for p.current().kind == rustTokAmpAmp {
		p.advance()
		right := p.parseBitOr()
		left = BinaryExpr{Op: "&&", Left: left, Right: right}
	}
	return left
}

func (p *rustMacroParser) parseBitOr() Expression {
	left := p.parseBitXor()
	for p.current().kind == rustTokPipe {
		p.advance()
		left = BinaryExpr{Op: "|", Left: left, Right: p.parseBitXor()}
	}
	return left
}

func (p *rustMacroParser) parseBitXor() Expression {
	left := p.parseBitAnd()
	for p.current().kind == rustTokCaret {
		p.advance()
		left = BinaryExpr{Op: "^", Left: left, Right: p.parseBitAnd()}
	}
	return left
}

func (p *rustMacroParser) parseBitAnd() Expression {
	left := p.parseEquality()
	for p.current().kind == rustTokAmp {
		p.advance()
		left = BinaryExpr{Op: "&", Left: left, Right: p.parseEquality()}
	}
	return left
}

func (p *rustMacroParser) parseEquality() Expression {
	left := p.parseComparison()
	for {
		var op string
		switch p.current().kind {
		case rustTokEqEq:
			op = "==="
		case rustTokBangEq:
			op = "!=="
		default:
			return left
		}
		p.advance()
		left = BinaryExpr{Op: op, Left: left, Right: p.parseComparison()}
	}
}

func (p *rustMacroParser) parseComparison() Expression {
	left := p.parseAddSub()
	for {
		var op string
		switch p.current().kind {
		case rustTokLt:
			op = "<"
		case rustTokLtEq:
			op = "<="
		case rustTokGt:
			op = ">"
		case rustTokGtEq:
			op = ">="
		default:
			return left
		}
		p.advance()
		left = BinaryExpr{Op: op, Left: left, Right: p.parseAddSub()}
	}
}

func (p *rustMacroParser) parseAddSub() Expression {
	left := p.parseMulDiv()
	for {
		var op string
		switch p.current().kind {
		case rustTokPlus:
			op = "+"
		case rustTokMinus:
			op = "-"
		default:
			return left
		}
		p.advance()
		left = BinaryExpr{Op: op, Left: left, Right: p.parseMulDiv()}
	}
}

func (p *rustMacroParser) parseMulDiv() Expression {
	left := p.parseUnary()
	for {
		var op string
		switch p.current().kind {
		case rustTokStar:
			op = "*"
		case rustTokSlash:
			op = "/"
		case rustTokPercent:
			op = "%"
		default:
			return left
		}
		p.advance()
		left = BinaryExpr{Op: op, Left: left, Right: p.parseUnary()}
	}
}

func (p *rustMacroParser) parseUnary() Expression {
	switch p.current().kind {
	case rustTokBang:
		p.advance()
		return UnaryExpr{Op: "!", Operand: p.parseUnary()}
	case rustTokMinus:
		p.advance()
		return UnaryExpr{Op: "-", Operand: p.parseUnary()}
	case rustTokTilde:
		p.advance()
		return UnaryExpr{Op: "~", Operand: p.parseUnary()}
	case rustTokAmp:
		// & and &mut are reference-taking operators — skip them
		p.advance()
		p.match(rustTokMut)
		return p.parsePostfix()
	}
	return p.parsePostfix()
}

func (p *rustMacroParser) parsePostfix() Expression {
	expr := p.parsePrimary()
	for {
		switch p.current().kind {
		case rustTokLParen:
			// Function call
			p.advance()
			var args []Expression
			for p.current().kind != rustTokRParen && p.current().kind != rustTokEOF {
				args = append(args, p.parseExpression())
				p.match(rustTokComma)
			}
			p.expect(rustTokRParen)
			expr = CallExpr{Callee: expr, Args: args}

		case rustTokDot:
			// Member access or method call
			p.advance()
			propName := "unknown"
			if p.current().kind == rustTokIdent {
				propName = rustSnakeToCamel(p.current().value)
				p.advance()
			}
			// self.field → PropertyAccessExpr
			if id, ok := expr.(Identifier); ok && id.Name == "self" {
				expr = PropertyAccessExpr{Property: propName}
			} else {
				expr = MemberExpr{Object: expr, Property: propName}
			}

		case rustTokColonColon:
			// Path separator (e.g. Type::method) — just take the last segment
			p.advance()
			if p.current().kind == rustTokIdent {
				name := rustSnakeToCamel(p.current().value)
				p.advance()
				expr = Identifier{Name: name}
			}

		case rustTokLBracket:
			// Index access
			p.advance()
			index := p.parseExpression()
			p.expect(rustTokRBracket)
			expr = IndexAccessExpr{Object: expr, Index: index}

		default:
			return expr
		}
	}
}

func (p *rustMacroParser) parsePrimary() Expression {
	t := p.current()
	switch t.kind {
	case rustTokNumber:
		p.advance()
		val, err := strconv.ParseInt(t.value, 10, 64)
		if err != nil {
			p.errors = append(p.errors, fmt.Sprintf(
				"invalid integer literal '%s' at %s:%d:%d", t.value, p.fileName, t.line, t.col))
			return BigIntLiteral{Value: 0}
		}
		return BigIntLiteral{Value: val}

	case rustTokHexString:
		p.advance()
		return ByteStringLiteral{Value: t.value}

	case rustTokTrue:
		p.advance()
		return BoolLiteral{Value: true}

	case rustTokFalse:
		p.advance()
		return BoolLiteral{Value: false}

	case rustTokSelf:
		p.advance()
		return Identifier{Name: "self"}

	case rustTokLParen:
		p.advance()
		expr := p.parseExpression()
		p.expect(rustTokRParen)
		return expr

	case rustTokIdent:
		p.advance()
		mapped := rustMapBuiltin(t.value)
		return Identifier{Name: mapped}

	default:
		p.advance()
		p.errors = append(p.errors, fmt.Sprintf(
			"unsupported token (kind=%d, value=%q) at %s:%d:%d — not valid in Rúnar contract",
			t.kind, t.value, p.fileName, t.line, t.col))
		return Identifier{Name: "unknown"}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// rustSnakeToCamel converts snake_case to camelCase.
// e.g. pub_key_hash → pubKeyHash, check_sig → checkSig, count → count.
func rustSnakeToCamel(name string) string {
	parts := strings.Split(name, "_")
	if len(parts) <= 1 {
		return name
	}
	var b strings.Builder
	b.WriteString(parts[0])
	for _, part := range parts[1:] {
		if len(part) == 0 {
			continue
		}
		runes := []rune(part)
		b.WriteRune(unicode.ToUpper(runes[0]))
		b.WriteString(string(runes[1:]))
	}
	return b.String()
}

// rustMapBuiltin maps Rust-style builtin names to canonical Rúnar names.
func rustMapBuiltin(name string) string {
	// Handle names that snake_to_camel can't produce correctly
	switch name {
	case "bool_cast":
		return "bool"
	case "verify_wots":
		return "verifyWOTS"
	case "verify_slh_dsa_sha2_128s":
		return "verifySLHDSA_SHA2_128s"
	case "verify_slh_dsa_sha2_128f":
		return "verifySLHDSA_SHA2_128f"
	case "verify_slh_dsa_sha2_192s":
		return "verifySLHDSA_SHA2_192s"
	case "verify_slh_dsa_sha2_192f":
		return "verifySLHDSA_SHA2_192f"
	case "verify_slh_dsa_sha2_256s":
		return "verifySLHDSA_SHA2_256s"
	case "verify_slh_dsa_sha2_256f":
		return "verifySLHDSA_SHA2_256f"
	case "bin_2_num":
		return "bin2num"
	case "num_2_bin":
		return "num2bin"
	case "to_byte_string":
		return "toByteString"
	}
	// General: snake_case → camelCase, then return as-is
	return rustSnakeToCamel(name)
}
