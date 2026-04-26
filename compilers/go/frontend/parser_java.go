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

// ParseJava parses a Java-syntax Rúnar contract (.runar.java) and produces
// the standard Rúnar AST. Uses a hand-written tokeniser and recursive
// descent parser — no javac/JavaParser library is available in the Go
// toolchain, so this reimplements the subset of Java syntax the Rúnar Java
// compiler (compilers/java/.../JavaParser.java) accepts.
//
// Surface subset supported:
//   - package decl (ignored), import decls (ignored, including static imports)
//   - one class extending SmartContract or StatefulSmartContract
//   - @Readonly fields (optional initializer), @Public methods
//   - constructor (class-named), with super(...) as first statement and
//     this.x = x assignments
//   - statements: typed local var-decls with initializer, this.x = ...
//     assignments, if/else, for, return, expression statements
//   - expressions: identifiers, int/bool literals, ByteString.fromHex("...")
//     BigInteger.valueOf(N), BigInteger.ZERO/ONE/TWO/TEN, binary ops, unary
//     (!, -, ~, prefix/postfix ++/--), method call, member access, this.foo,
//     ternary, array access, array literal via new T[] {...}
//   - type annotations: primitive types (boolean, BigInteger, Bigint, Boolean),
//     domain types (Addr, Sig, PubKey, ByteString, Sha256Digest, Ripemd160,
//     Point, P256Point, P384Point, SigHashPreimage, RabinSig, RabinPubKey,
//     OpCodeType); FixedArray<T, N> with integer-literal N.
func ParseJava(source []byte, fileName string) *ParseResult {
	tokens := javaTokenize(string(source))
	p := &javaParser{
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

type javaTokKind int

const (
	javaTokEOF javaTokKind = iota
	// Keywords / reserved names (token-valued when scanned as idents)
	javaTokPackage
	javaTokImport
	javaTokStatic
	javaTokClass
	javaTokExtends
	javaTokImplements
	javaTokIf
	javaTokElse
	javaTokFor
	javaTokWhile
	javaTokReturn
	javaTokTrue
	javaTokFalse
	javaTokNew
	javaTokSuper
	javaTokThis
	javaTokNull
	// Other
	javaTokIdent
	javaTokNumber
	javaTokString
	javaTokAt // @
	// Punctuation
	javaTokLParen
	javaTokRParen
	javaTokLBrace
	javaTokRBrace
	javaTokLBracket
	javaTokRBracket
	javaTokSemi
	javaTokComma
	javaTokDot
	javaTokColon
	javaTokQuestion
	// Operators
	javaTokAssign    // =
	javaTokEqEq      // ==
	javaTokBangEq    // !=
	javaTokLt        // <
	javaTokLtEq      // <=
	javaTokGt        // >
	javaTokGtEq      // >=
	javaTokPlus      // +
	javaTokMinus     // -
	javaTokStar      // *
	javaTokSlash     // /
	javaTokPercent   // %
	javaTokBang      // !
	javaTokTilde     // ~
	javaTokAmp       // &
	javaTokPipe      // |
	javaTokCaret     // ^
	javaTokAmpAmp    // &&
	javaTokPipePipe  // ||
	javaTokPlusEq    // +=
	javaTokMinusEq   // -=
	javaTokStarEq    // *=
	javaTokSlashEq   // /=
	javaTokPercentEq // %=
	javaTokPlusPlus  // ++
	javaTokMinusMinus // --
	javaTokShl       // <<
	javaTokShr       // >>
)

type javaToken struct {
	kind  javaTokKind
	value string
	line  int
	col   int
}

// ---------------------------------------------------------------------------
// Tokeniser
// ---------------------------------------------------------------------------

var javaKeywords = map[string]javaTokKind{
	"package":    javaTokPackage,
	"import":     javaTokImport,
	"static":     javaTokStatic,
	"class":      javaTokClass,
	"extends":    javaTokExtends,
	"implements": javaTokImplements,
	"if":         javaTokIf,
	"else":       javaTokElse,
	"for":        javaTokFor,
	"while":      javaTokWhile,
	"return":     javaTokReturn,
	"true":       javaTokTrue,
	"false":      javaTokFalse,
	"new":        javaTokNew,
	"super":      javaTokSuper,
	"this":       javaTokThis,
	"null":       javaTokNull,
}

func javaTokenize(source string) []javaToken {
	chars := []rune(source)
	var tokens []javaToken
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

		// Line comment: // ...
		if ch == '/' && pos+1 < len(chars) && chars[pos+1] == '/' {
			for pos < len(chars) && chars[pos] != '\n' {
				pos++
			}
			continue
		}

		// Block comment: /* ... */
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

		// Three-char operator: none we care about (>>> could be here but
		// unsigned right-shift is not supported). Fall through to two-char.

		// Two-char operators
		if pos+1 < len(chars) {
			two := string(chars[pos : pos+2])
			var kind javaTokKind
			matched := true
			switch two {
			case "==":
				kind = javaTokEqEq
			case "!=":
				kind = javaTokBangEq
			case "<=":
				kind = javaTokLtEq
			case ">=":
				kind = javaTokGtEq
			case "&&":
				kind = javaTokAmpAmp
			case "||":
				kind = javaTokPipePipe
			case "+=":
				kind = javaTokPlusEq
			case "-=":
				kind = javaTokMinusEq
			case "*=":
				kind = javaTokStarEq
			case "/=":
				kind = javaTokSlashEq
			case "%=":
				kind = javaTokPercentEq
			case "++":
				kind = javaTokPlusPlus
			case "--":
				kind = javaTokMinusMinus
			case "<<":
				kind = javaTokShl
			case ">>":
				kind = javaTokShr
			default:
				matched = false
			}
			if matched {
				tokens = append(tokens, javaToken{kind: kind, line: l, col: c})
				pos += 2
				col += 2
				continue
			}
		}

		// Single-char tokens
		var singleKind javaTokKind
		singleMatched := true
		switch ch {
		case '(':
			singleKind = javaTokLParen
		case ')':
			singleKind = javaTokRParen
		case '{':
			singleKind = javaTokLBrace
		case '}':
			singleKind = javaTokRBrace
		case '[':
			singleKind = javaTokLBracket
		case ']':
			singleKind = javaTokRBracket
		case ';':
			singleKind = javaTokSemi
		case ',':
			singleKind = javaTokComma
		case '.':
			singleKind = javaTokDot
		case ':':
			singleKind = javaTokColon
		case '?':
			singleKind = javaTokQuestion
		case '@':
			singleKind = javaTokAt
		case '=':
			singleKind = javaTokAssign
		case '<':
			singleKind = javaTokLt
		case '>':
			singleKind = javaTokGt
		case '+':
			singleKind = javaTokPlus
		case '-':
			singleKind = javaTokMinus
		case '*':
			singleKind = javaTokStar
		case '/':
			singleKind = javaTokSlash
		case '%':
			singleKind = javaTokPercent
		case '!':
			singleKind = javaTokBang
		case '~':
			singleKind = javaTokTilde
		case '&':
			singleKind = javaTokAmp
		case '|':
			singleKind = javaTokPipe
		case '^':
			singleKind = javaTokCaret
		default:
			singleMatched = false
		}
		if singleMatched {
			tokens = append(tokens, javaToken{kind: singleKind, line: l, col: c})
			pos++
			col++
			continue
		}

		// Numeric literal: integer (decimal or hex). No floats.
		if ch >= '0' && ch <= '9' {
			var val strings.Builder
			if ch == '0' && pos+1 < len(chars) && (chars[pos+1] == 'x' || chars[pos+1] == 'X') {
				val.WriteRune(chars[pos])
				val.WriteRune(chars[pos+1])
				pos += 2
				col += 2
				for pos < len(chars) && javaIsHexDigit(chars[pos]) {
					val.WriteRune(chars[pos])
					pos++
					col++
				}
			} else {
				for pos < len(chars) && (chars[pos] >= '0' && chars[pos] <= '9' || chars[pos] == '_') {
					if chars[pos] != '_' {
						val.WriteRune(chars[pos])
					}
					pos++
					col++
				}
			}
			// Optional L/l suffix (long literal)
			if pos < len(chars) && (chars[pos] == 'L' || chars[pos] == 'l') {
				pos++
				col++
			}
			tokens = append(tokens, javaToken{kind: javaTokNumber, value: val.String(), line: l, col: c})
			continue
		}

		// Identifier / keyword
		if ch == '_' || ch == '$' || unicode.IsLetter(ch) {
			var val strings.Builder
			for pos < len(chars) && (chars[pos] == '_' || chars[pos] == '$' ||
				unicode.IsLetter(chars[pos]) || unicode.IsDigit(chars[pos])) {
				val.WriteRune(chars[pos])
				pos++
				col++
			}
			name := val.String()
			if kw, ok := javaKeywords[name]; ok {
				tokens = append(tokens, javaToken{kind: kw, value: name, line: l, col: c})
			} else {
				tokens = append(tokens, javaToken{kind: javaTokIdent, value: name, line: l, col: c})
			}
			continue
		}

		// String literal: "..." (with escape handling)
		if ch == '"' {
			var val strings.Builder
			pos++
			col++
			for pos < len(chars) && chars[pos] != '"' {
				if chars[pos] == '\\' && pos+1 < len(chars) {
					// Minimal escape handling: preserve common escapes literally.
					esc := chars[pos+1]
					switch esc {
					case 'n':
						val.WriteRune('\n')
					case 't':
						val.WriteRune('\t')
					case 'r':
						val.WriteRune('\r')
					case '\\':
						val.WriteRune('\\')
					case '"':
						val.WriteRune('"')
					case '\'':
						val.WriteRune('\'')
					case '0':
						val.WriteRune(0)
					default:
						val.WriteRune(esc)
					}
					pos += 2
					col += 2
					continue
				}
				if chars[pos] == '\n' {
					line++
					col = 1
				} else {
					col++
				}
				val.WriteRune(chars[pos])
				pos++
			}
			if pos < len(chars) {
				pos++ // closing quote
				col++
			}
			tokens = append(tokens, javaToken{kind: javaTokString, value: val.String(), line: l, col: c})
			continue
		}

		// Character literal: skip (not supported). Consume one char to avoid
		// an infinite loop — the parser will surface an error if this is
		// reached during real parsing.
		if ch == '\'' {
			pos++
			col++
			for pos < len(chars) && chars[pos] != '\'' {
				if chars[pos] == '\\' && pos+1 < len(chars) {
					pos += 2
					col += 2
					continue
				}
				pos++
				col++
			}
			if pos < len(chars) {
				pos++
				col++
			}
			// Emit an error-ish placeholder by skipping; no token produced.
			continue
		}

		// Unknown char: skip
		pos++
		col++
	}

	tokens = append(tokens, javaToken{kind: javaTokEOF, line: line, col: col})
	return tokens
}

func javaIsHexDigit(ch rune) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// ---------------------------------------------------------------------------
// Parser struct
// ---------------------------------------------------------------------------

type javaParser struct {
	tokens   []javaToken
	pos      int
	fileName string
	errors   []Diagnostic
}

func (p *javaParser) current() javaToken {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return javaToken{kind: javaTokEOF}
}

func (p *javaParser) peekAt(offset int) javaToken {
	if p.pos+offset < len(p.tokens) {
		return p.tokens[p.pos+offset]
	}
	return javaToken{kind: javaTokEOF}
}

func (p *javaParser) advance() javaToken {
	t := p.current()
	if p.pos < len(p.tokens)-1 {
		p.pos++
	}
	return t
}

func (p *javaParser) match(kind javaTokKind) bool {
	if p.current().kind == kind {
		p.advance()
		return true
	}
	return false
}

func (p *javaParser) expect(kind javaTokKind) javaToken {
	t := p.current()
	if t.kind != kind {
		p.addErrorAt(fmt.Sprintf("expected token kind %d, got %d (%q)", kind, t.kind, t.value), t)
	}
	return p.advance()
}

func (p *javaParser) addError(msg string) {
	t := p.current()
	p.addErrorAt(msg, t)
}

func (p *javaParser) addErrorAt(msg string, t javaToken) {
	loc := SourceLocation{File: p.fileName, Line: t.line, Column: t.col}
	p.errors = append(p.errors, Diagnostic{
		Message:  fmt.Sprintf("%s:%d:%d: %s", p.fileName, t.line, t.col, msg),
		Severity: SeverityError,
		Loc:      &loc,
	})
}

func (p *javaParser) loc() SourceLocation {
	t := p.current()
	return SourceLocation{File: p.fileName, Line: t.line, Column: t.col}
}

// ---------------------------------------------------------------------------
// Top-level parse
// ---------------------------------------------------------------------------

func (p *javaParser) parse() *ContractNode {
	// Skip package decl
	if p.current().kind == javaTokPackage {
		for p.current().kind != javaTokSemi && p.current().kind != javaTokEOF {
			p.advance()
		}
		p.match(javaTokSemi)
	}

	// Skip imports (including `import static ...`)
	for p.current().kind == javaTokImport {
		for p.current().kind != javaTokSemi && p.current().kind != javaTokEOF {
			p.advance()
		}
		p.match(javaTokSemi)
	}

	// Seek forward past any leading annotations / modifiers on the class
	// itself. We drop them all; there's no Rúnar-level meaning here beyond
	// what the class declaration carries.
	for p.current().kind == javaTokAt {
		p.skipAnnotation()
	}
	// Skip leading class modifiers (public, final, abstract — we accept any
	// but don't encode them).
	for p.current().kind == javaTokIdent {
		v := p.current().value
		if v == "public" || v == "private" || v == "protected" || v == "final" ||
			v == "abstract" || v == "static" {
			p.advance()
			continue
		}
		break
	}

	if p.current().kind != javaTokClass {
		return p.failNoClass()
	}
	return p.parseClass()
}

func (p *javaParser) failNoClass() *ContractNode {
	p.addError("no class declaration found — expected `class Name extends SmartContract`")
	return nil
}

func (p *javaParser) parseClass() *ContractNode {
	classLoc := p.loc()
	p.expect(javaTokClass)

	nameTok := p.expect(javaTokIdent)
	className := nameTok.value

	// extends ParentClass
	if p.current().kind != javaTokExtends {
		p.addError(fmt.Sprintf("contract class %s must extend SmartContract or StatefulSmartContract", className))
		return nil
	}
	p.advance() // consume 'extends'

	// Java allows fully-qualified names; keep only the rightmost segment.
	parentName := p.parseQualifiedNameTail()

	var parentClass string
	switch parentName {
	case "SmartContract":
		parentClass = "SmartContract"
	case "StatefulSmartContract":
		parentClass = "StatefulSmartContract"
	default:
		p.addError(fmt.Sprintf("contract class %s must extend SmartContract or StatefulSmartContract, got %s", className, parentName))
		return nil
	}

	// Optional implements clause — ignore its contents.
	if p.current().kind == javaTokImplements {
		p.advance()
		// consume until {
		for p.current().kind != javaTokLBrace && p.current().kind != javaTokEOF {
			p.advance()
		}
	}

	p.expect(javaTokLBrace)

	var properties []PropertyNode
	var constructor *MethodNode
	var methods []MethodNode

	for p.current().kind != javaTokRBrace && p.current().kind != javaTokEOF {
		member := p.parseClassMember(className)
		if member == nil {
			continue
		}
		switch m := member.(type) {
		case *PropertyNode:
			properties = append(properties, *m)
		case *MethodNode:
			if m.Name == "constructor" {
				if constructor != nil {
					p.addError(fmt.Sprintf("%s has more than one constructor", className))
				}
				ctor := *m
				constructor = &ctor
			} else {
				methods = append(methods, *m)
			}
		}
	}
	p.expect(javaTokRBrace)

	// Synthesise a constructor if the source omitted one.
	if constructor == nil {
		ctor := javaSyntheticConstructor(properties, classLoc)
		constructor = &ctor
	}

	return &ContractNode{
		Name:        className,
		ParentClass: parentClass,
		Properties:  properties,
		Constructor: *constructor,
		Methods:     methods,
		SourceFile:  p.fileName,
	}
}

// parseQualifiedNameTail reads `a.b.c` and returns the last identifier.
func (p *javaParser) parseQualifiedNameTail() string {
	if p.current().kind != javaTokIdent {
		return ""
	}
	name := p.advance().value
	for p.current().kind == javaTokDot {
		p.advance()
		if p.current().kind == javaTokIdent {
			name = p.advance().value
		} else {
			break
		}
	}
	return name
}

// skipAnnotation consumes a full `@Name` or `@Name(args)` annotation.
func (p *javaParser) skipAnnotation() {
	p.expect(javaTokAt)
	// Name (possibly qualified)
	for p.current().kind == javaTokIdent {
		p.advance()
		if p.current().kind == javaTokDot {
			p.advance()
			continue
		}
		break
	}
	// Optional (args)
	if p.current().kind == javaTokLParen {
		depth := 1
		p.advance()
		for depth > 0 && p.current().kind != javaTokEOF {
			switch p.current().kind {
			case javaTokLParen:
				depth++
			case javaTokRParen:
				depth--
			}
			p.advance()
		}
	}
}

// readAnnotationName consumes an `@Name` (or `@pkg.Name`) and returns the
// simple name. Leaves the parser positioned after any `(...)` arg list.
func (p *javaParser) readAnnotationName() string {
	p.expect(javaTokAt)
	name := ""
	for p.current().kind == javaTokIdent {
		name = p.advance().value
		if p.current().kind == javaTokDot {
			p.advance()
			continue
		}
		break
	}
	// Skip (args)
	if p.current().kind == javaTokLParen {
		depth := 1
		p.advance()
		for depth > 0 && p.current().kind != javaTokEOF {
			switch p.current().kind {
			case javaTokLParen:
				depth++
			case javaTokRParen:
				depth--
			}
			p.advance()
		}
	}
	return name
}

// ---------------------------------------------------------------------------
// Class-member parsing
// ---------------------------------------------------------------------------

// parseClassMember returns *PropertyNode or *MethodNode (or nil on an error
// that was already reported).
func (p *javaParser) parseClassMember(className string) interface{} {
	// Collect annotations
	annotations := map[string]bool{}
	for p.current().kind == javaTokAt {
		name := p.readAnnotationName()
		if name != "" {
			annotations[name] = true
		}
	}

	// Collect modifiers (public/private/protected/static/final/etc)
	for p.current().kind == javaTokIdent {
		v := p.current().value
		if v == "public" || v == "private" || v == "protected" ||
			v == "final" || v == "static" || v == "abstract" {
			p.advance()
			continue
		}
		break
	}

	// At this point we expect either:
	//   - a return type / property type followed by an identifier (method or field)
	//   - the class name as a constructor
	//
	// Look ahead: if the first token is the class name followed by '(', it's a
	// constructor.
	if p.current().kind == javaTokIdent && p.current().value == className &&
		p.peekAt(1).kind == javaTokLParen {
		method := p.parseConstructor(className)
		return method
	}

	// Otherwise parse a type, then decide field vs method.
	if !p.isTypeStart() {
		// Unrecognised member — advance to recover.
		p.addError(fmt.Sprintf("unexpected token in class body: %q", p.current().value))
		p.advance()
		return nil
	}

	loc := p.loc()
	typ := p.parseType()

	// Field or method name
	if p.current().kind != javaTokIdent {
		p.addError("expected field or method name")
		p.advance()
		return nil
	}
	name := p.advance().value

	// Method: `name(...)`
	if p.current().kind == javaTokLParen {
		method := p.parseMethod(name, typ, annotations, loc)
		return method
	}

	// Field: `= init;` or `;`
	var init Expression
	if p.match(javaTokAssign) {
		init = p.parseExpression()
	}
	p.expect(javaTokSemi)

	readonly := annotations["Readonly"]
	return &PropertyNode{
		Name:           name,
		Type:           typ,
		Readonly:       readonly,
		Initializer:    init,
		SourceLocation: loc,
	}
}

// parseConstructor parses `ClassName(params) { body }`. The class-name
// identifier is still the current token on entry.
func (p *javaParser) parseConstructor(className string) *MethodNode {
	loc := p.loc()
	if p.current().kind != javaTokIdent || p.current().value != className {
		p.addError("internal: parseConstructor called without class name")
		return nil
	}
	p.advance() // class name

	params := p.parseParamList()

	// Optional throws clause — consume until the opening brace.
	for p.current().kind != javaTokLBrace && p.current().kind != javaTokEOF {
		p.advance()
	}

	body := p.parseBlock()

	return &MethodNode{
		Name:           "constructor",
		Params:         params,
		Body:           body,
		Visibility:     "public",
		SourceLocation: loc,
	}
}

// parseMethod parses `methodName(params) { body }` after the return type
// and method name have already been consumed.
func (p *javaParser) parseMethod(name string, returnType TypeNode, annotations map[string]bool, loc SourceLocation) *MethodNode {
	params := p.parseParamList()

	// Optional throws clause — consume until the opening brace.
	for p.current().kind != javaTokLBrace && p.current().kind != javaTokEOF &&
		p.current().kind != javaTokSemi {
		p.advance()
	}

	var body []Statement
	if p.match(javaTokSemi) {
		// abstract / interface method — no body
		body = nil
	} else {
		body = p.parseBlock()
	}

	visibility := "private"
	if annotations["Public"] {
		visibility = "public"
	}

	// Return type is not encoded in MethodNode; we accept void for public
	// methods but do not enforce it here. The typechecker handles rules.
	_ = returnType

	return &MethodNode{
		Name:           name,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SourceLocation: loc,
	}
}

func (p *javaParser) parseParamList() []ParamNode {
	p.expect(javaTokLParen)
	var params []ParamNode
	for p.current().kind != javaTokRParen && p.current().kind != javaTokEOF {
		// Parameter annotations (e.g. @Nullable) — skip.
		for p.current().kind == javaTokAt {
			p.skipAnnotation()
		}
		// Optional `final`
		if p.current().kind == javaTokIdent && p.current().value == "final" {
			p.advance()
		}
		typ := p.parseType()
		if p.current().kind != javaTokIdent {
			p.addError("expected parameter name")
			if p.current().kind != javaTokRParen {
				p.advance()
			}
			continue
		}
		paramName := p.advance().value
		params = append(params, ParamNode{Name: paramName, Type: typ})
		if !p.match(javaTokComma) {
			break
		}
	}
	p.expect(javaTokRParen)
	return params
}

// javaSyntheticConstructor builds a default constructor analogous to the
// Java side's `syntheticConstructor`: super(all-uninitialised) + this.x = x
// for each uninitialised property.
func javaSyntheticConstructor(properties []PropertyNode, loc SourceLocation) MethodNode {
	var params []ParamNode
	var superArgs []Expression
	for _, prop := range properties {
		if prop.Initializer != nil {
			continue
		}
		params = append(params, ParamNode{Name: prop.Name, Type: prop.Type})
		superArgs = append(superArgs, Identifier{Name: prop.Name})
	}
	body := []Statement{
		ExpressionStmt{
			Expr:           CallExpr{Callee: Identifier{Name: "super"}, Args: superArgs},
			SourceLocation: loc,
		},
	}
	for _, prop := range properties {
		if prop.Initializer != nil {
			continue
		}
		body = append(body, AssignmentStmt{
			Target:         PropertyAccessExpr{Property: prop.Name},
			Value:          Identifier{Name: prop.Name},
			SourceLocation: loc,
		})
	}
	return MethodNode{
		Name:           "constructor",
		Params:         params,
		Body:           body,
		Visibility:     "public",
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// Type parsing
// ---------------------------------------------------------------------------

func (p *javaParser) isTypeStart() bool {
	t := p.current()
	if t.kind != javaTokIdent {
		return false
	}
	// Any identifier that isn't a reserved modifier starts a type.
	switch t.value {
	case "public", "private", "protected", "final", "static", "abstract":
		return false
	}
	return true
}

// parseType parses a Java type reference: `TypeName`, `pkg.Qualified`,
// `FixedArray<T, N>`, `FixedArray<T,N>[]`, etc. The parser only encodes
// FixedArray generics; other generic types collapse to their base name
// after consuming the type-argument list.
func (p *javaParser) parseType() TypeNode {
	if p.current().kind != javaTokIdent {
		p.addError("expected type name")
		p.advance()
		return CustomType{Name: "unknown"}
	}
	// Read qualified name — the tail is the simple name we use.
	simple := p.advance().value
	for p.current().kind == javaTokDot {
		p.advance()
		if p.current().kind == javaTokIdent {
			simple = p.advance().value
		} else {
			break
		}
	}

	// Generic arguments: <...>
	var generic []TypeNode
	if p.current().kind == javaTokLt {
		p.advance()
		for p.current().kind != javaTokGt && p.current().kind != javaTokEOF {
			if p.current().kind == javaTokComma {
				p.advance()
				continue
			}
			// A type argument may be a type OR an integer literal (for
			// FixedArray<T, 32>). Record both possibilities as separate
			// "types" — integer literals surface through parseType() as an
			// error since there's no ident-start. Handle them inline.
			if p.current().kind == javaTokNumber {
				numTok := p.advance()
				// encode as a synthetic CustomType "N=<n>" — consumer detects.
				generic = append(generic, CustomType{Name: "<int:" + numTok.value + ">"})
				continue
			}
			generic = append(generic, p.parseType())
		}
		p.expect(javaTokGt)
	}

	// Trailing [] — multi-dim Java arrays are not part of the Rúnar subset,
	// but we accept the bracket pair and ignore it so declarations like
	// `int[] xs` produce a type name consumers can still reason about.
	for p.current().kind == javaTokLBracket {
		p.advance()
		p.match(javaTokRBracket)
	}

	// FixedArray<T, N>
	if simple == "FixedArray" {
		if len(generic) != 2 {
			p.addError("FixedArray requires 2 type arguments (element, length)")
			return CustomType{Name: "FixedArray"}
		}
		element := generic[0]
		length := 0
		if ct, ok := generic[1].(CustomType); ok && strings.HasPrefix(ct.Name, "<int:") {
			rawNum := strings.TrimSuffix(strings.TrimPrefix(ct.Name, "<int:"), ">")
			bi := new(big.Int)
			if _, ok := bi.SetString(rawNum, 0); !ok {
				p.addError(fmt.Sprintf("FixedArray length must be an integer literal, got %q", rawNum))
			} else if bi.Sign() < 0 || !bi.IsInt64() {
				p.addError(fmt.Sprintf("FixedArray length out of range: %s", rawNum))
			} else {
				length = int(bi.Int64())
			}
		} else {
			p.addError("FixedArray length must be an integer literal")
		}
		return FixedArrayType{Element: element, Length: length}
	}

	return javaMapType(simple)
}

// javaMapType converts a simple Java type name to the Rúnar AST TypeNode.
func javaMapType(name string) TypeNode {
	switch name {
	case "boolean", "Boolean":
		return PrimitiveType{Name: "boolean"}
	case "BigInteger", "Bigint":
		return PrimitiveType{Name: "bigint"}
	case "bigint":
		return PrimitiveType{Name: "bigint"}
	case "ByteString":
		return PrimitiveType{Name: "ByteString"}
	case "PubKey":
		return PrimitiveType{Name: "PubKey"}
	case "Sig":
		return PrimitiveType{Name: "Sig"}
	case "Addr":
		return PrimitiveType{Name: "Addr"}
	case "Sha256", "Sha256Digest":
		return PrimitiveType{Name: "Sha256"}
	case "Ripemd160", "Hash160":
		return PrimitiveType{Name: "Ripemd160"}
	case "SigHashPreimage":
		return PrimitiveType{Name: "SigHashPreimage"}
	case "RabinSig":
		return PrimitiveType{Name: "RabinSig"}
	case "RabinPubKey":
		return PrimitiveType{Name: "RabinPubKey"}
	case "Point":
		return PrimitiveType{Name: "Point"}
	case "P256Point":
		return PrimitiveType{Name: "P256Point"}
	case "P384Point":
		return PrimitiveType{Name: "P384Point"}
	case "OpCodeType":
		return CustomType{Name: "OpCodeType"}
	case "void":
		return PrimitiveType{Name: "void"}
	}
	if IsPrimitiveType(name) {
		return PrimitiveType{Name: name}
	}
	return CustomType{Name: name}
}

// ---------------------------------------------------------------------------
// Statement parsing
// ---------------------------------------------------------------------------

func (p *javaParser) parseBlock() []Statement {
	p.expect(javaTokLBrace)
	var stmts []Statement
	for p.current().kind != javaTokRBrace && p.current().kind != javaTokEOF {
		s := p.parseStatement()
		if s != nil {
			stmts = append(stmts, s)
		}
	}
	p.expect(javaTokRBrace)
	return stmts
}

func (p *javaParser) parseStatement() Statement {
	loc := p.loc()

	// Bare { ... } — a nested block. We don't model nested blocks as a
	// distinct statement, so flatten by parsing the inner statements and
	// surfacing them as an ExpressionStmt(no-op). In practice Rúnar
	// contracts don't use nested blocks; produce an error like the Java
	// side does.
	if p.current().kind == javaTokLBrace {
		p.addError("nested blocks are unsupported in Rúnar contracts")
		p.parseBlock()
		return nil
	}

	switch p.current().kind {
	case javaTokIf:
		return p.parseIf(loc)
	case javaTokFor:
		return p.parseFor(loc)
	case javaTokWhile:
		// while is not part of the Java subset — behave like if this were
		// a for-loop without an initializer would require more care; for
		// now, reject.
		p.addError("while-loops are unsupported — use for(;cond;update)")
		// Recover by skipping.
		for p.current().kind != javaTokRBrace && p.current().kind != javaTokEOF {
			p.advance()
		}
		return nil
	case javaTokReturn:
		return p.parseReturn(loc)
	case javaTokSemi:
		// empty statement
		p.advance()
		return nil
	}

	// Possibly a typed local var decl: `Type name = init;`
	if p.isVariableDeclStart() {
		return p.parseVariableDecl(loc)
	}

	// Otherwise: expression statement (assignment, method call, postfix ++/--).
	expr := p.parseExpression()

	// Assignment/compound assignment?
	switch p.current().kind {
	case javaTokAssign:
		p.advance()
		value := p.parseExpression()
		p.match(javaTokSemi)
		return AssignmentStmt{Target: expr, Value: value, SourceLocation: loc}
	case javaTokPlusEq, javaTokMinusEq, javaTokStarEq, javaTokSlashEq, javaTokPercentEq:
		opTok := p.advance()
		rhs := p.parseExpression()
		p.match(javaTokSemi)
		op := ""
		switch opTok.kind {
		case javaTokPlusEq:
			op = "+"
		case javaTokMinusEq:
			op = "-"
		case javaTokStarEq:
			op = "*"
		case javaTokSlashEq:
			op = "/"
		case javaTokPercentEq:
			op = "%"
		}
		return AssignmentStmt{
			Target:         expr,
			Value:          BinaryExpr{Op: op, Left: expr, Right: rhs},
			SourceLocation: loc,
		}
	}

	p.match(javaTokSemi)
	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

// isVariableDeclStart looks ahead to distinguish a typed local declaration
// (`Type name = init`) from an expression starting with an identifier.
// The heuristic: a TypeName (optionally qualified / with generics / []),
// followed by an identifier, followed by `=` or `;`, means a decl.
func (p *javaParser) isVariableDeclStart() bool {
	if p.current().kind != javaTokIdent {
		return false
	}
	save := p.pos
	// Scan a type pattern without emitting tokens-of-record.
	consumed := javaScanType(p.tokens, p.pos)
	if consumed < 0 {
		p.pos = save
		return false
	}
	// After the type we need Ident followed by `=` or `;`
	next := consumed
	if next >= len(p.tokens) || p.tokens[next].kind != javaTokIdent {
		p.pos = save
		return false
	}
	after := next + 1
	if after < len(p.tokens) {
		kind := p.tokens[after].kind
		if kind == javaTokAssign || kind == javaTokSemi {
			p.pos = save
			return true
		}
	}
	p.pos = save
	return false
}

// javaScanType advances through a type reference starting at pos and
// returns the index of the first token after the type, or -1 if no type
// was found.
func javaScanType(tokens []javaToken, pos int) int {
	if pos >= len(tokens) || tokens[pos].kind != javaTokIdent {
		return -1
	}
	// Qualified name
	pos++
	for pos < len(tokens) && tokens[pos].kind == javaTokDot {
		if pos+1 >= len(tokens) || tokens[pos+1].kind != javaTokIdent {
			break
		}
		pos += 2
	}
	// Generics: <...>
	if pos < len(tokens) && tokens[pos].kind == javaTokLt {
		depth := 1
		pos++
		for depth > 0 && pos < len(tokens) {
			switch tokens[pos].kind {
			case javaTokLt:
				depth++
			case javaTokGt:
				depth--
			}
			pos++
		}
	}
	// Trailing []
	for pos+1 < len(tokens) && tokens[pos].kind == javaTokLBracket && tokens[pos+1].kind == javaTokRBracket {
		pos += 2
	}
	return pos
}

func (p *javaParser) parseVariableDecl(loc SourceLocation) Statement {
	typ := p.parseType()
	nameTok := p.expect(javaTokIdent)
	name := nameTok.value

	var init Expression
	if p.match(javaTokAssign) {
		init = p.parseExpression()
	} else {
		p.addError(fmt.Sprintf("local variable %s must have an initializer", name))
	}
	p.match(javaTokSemi)

	return VariableDeclStmt{
		Name:           name,
		Type:           typ,
		Mutable:        true,
		Init:           init,
		SourceLocation: loc,
	}
}

func (p *javaParser) parseIf(loc SourceLocation) Statement {
	p.expect(javaTokIf)
	p.expect(javaTokLParen)
	cond := p.parseExpression()
	p.expect(javaTokRParen)

	var thenStmts []Statement
	if p.current().kind == javaTokLBrace {
		thenStmts = p.parseBlock()
	} else {
		s := p.parseStatement()
		if s != nil {
			thenStmts = []Statement{s}
		}
	}

	var elseStmts []Statement
	if p.match(javaTokElse) {
		if p.current().kind == javaTokLBrace {
			elseStmts = p.parseBlock()
		} else if p.current().kind == javaTokIf {
			// else if — wrap the chained if as a single-statement else block.
			nested := p.parseStatement()
			if nested != nil {
				elseStmts = []Statement{nested}
			}
		} else {
			s := p.parseStatement()
			if s != nil {
				elseStmts = []Statement{s}
			}
		}
	}

	return IfStmt{
		Condition:      cond,
		Then:           thenStmts,
		Else:           elseStmts,
		SourceLocation: loc,
	}
}

func (p *javaParser) parseFor(loc SourceLocation) Statement {
	p.expect(javaTokFor)
	p.expect(javaTokLParen)

	// Initializer — must be a typed variable declaration.
	initLoc := p.loc()
	var init VariableDeclStmt
	if p.isVariableDeclStart() {
		stmt := p.parseVariableDecl(initLoc)
		if vd, ok := stmt.(VariableDeclStmt); ok {
			init = vd
		}
	} else {
		p.addError("for-loop must declare a typed loop variable")
		// Skip to the first semicolon inside the for-header.
		for p.current().kind != javaTokSemi && p.current().kind != javaTokRParen &&
			p.current().kind != javaTokEOF {
			p.advance()
		}
		p.match(javaTokSemi)
	}

	// Condition
	var cond Expression
	if p.current().kind != javaTokSemi {
		cond = p.parseExpression()
	}
	p.expect(javaTokSemi)

	// Update — may be i++, ++i, i--, --i, i = expr, or an expression.
	updateLoc := p.loc()
	var update Statement
	if p.current().kind != javaTokRParen {
		updateExpr := p.parseExpression()
		switch p.current().kind {
		case javaTokAssign:
			p.advance()
			value := p.parseExpression()
			update = AssignmentStmt{Target: updateExpr, Value: value, SourceLocation: updateLoc}
		case javaTokPlusEq, javaTokMinusEq, javaTokStarEq, javaTokSlashEq, javaTokPercentEq:
			opTok := p.advance()
			rhs := p.parseExpression()
			op := ""
			switch opTok.kind {
			case javaTokPlusEq:
				op = "+"
			case javaTokMinusEq:
				op = "-"
			case javaTokStarEq:
				op = "*"
			case javaTokSlashEq:
				op = "/"
			case javaTokPercentEq:
				op = "%"
			}
			update = AssignmentStmt{
				Target:         updateExpr,
				Value:          BinaryExpr{Op: op, Left: updateExpr, Right: rhs},
				SourceLocation: updateLoc,
			}
		default:
			update = ExpressionStmt{Expr: updateExpr, SourceLocation: updateLoc}
		}
	}
	p.expect(javaTokRParen)

	var body []Statement
	if p.current().kind == javaTokLBrace {
		body = p.parseBlock()
	} else {
		s := p.parseStatement()
		if s != nil {
			body = []Statement{s}
		}
	}

	return ForStmt{
		Init:           init,
		Condition:      cond,
		Update:         update,
		Body:           body,
		SourceLocation: loc,
	}
}

func (p *javaParser) parseReturn(loc SourceLocation) Statement {
	p.expect(javaTokReturn)
	var value Expression
	if p.current().kind != javaTokSemi && p.current().kind != javaTokRBrace &&
		p.current().kind != javaTokEOF {
		value = p.parseExpression()
	}
	p.match(javaTokSemi)
	return ReturnStmt{Value: value, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// Expression parsing — precedence climbing
// ---------------------------------------------------------------------------

func (p *javaParser) parseExpression() Expression {
	return p.parseTernary()
}

func (p *javaParser) parseTernary() Expression {
	cond := p.parseOr()
	if p.current().kind == javaTokQuestion {
		p.advance()
		thenExpr := p.parseExpression()
		p.expect(javaTokColon)
		elseExpr := p.parseExpression()
		return TernaryExpr{Condition: cond, Consequent: thenExpr, Alternate: elseExpr}
	}
	return cond
}

func (p *javaParser) parseOr() Expression {
	left := p.parseAnd()
	for p.current().kind == javaTokPipePipe {
		p.advance()
		left = BinaryExpr{Op: "||", Left: left, Right: p.parseAnd()}
	}
	return left
}

func (p *javaParser) parseAnd() Expression {
	left := p.parseBitOr()
	for p.current().kind == javaTokAmpAmp {
		p.advance()
		left = BinaryExpr{Op: "&&", Left: left, Right: p.parseBitOr()}
	}
	return left
}

func (p *javaParser) parseBitOr() Expression {
	left := p.parseBitXor()
	for p.current().kind == javaTokPipe {
		p.advance()
		left = BinaryExpr{Op: "|", Left: left, Right: p.parseBitXor()}
	}
	return left
}

func (p *javaParser) parseBitXor() Expression {
	left := p.parseBitAnd()
	for p.current().kind == javaTokCaret {
		p.advance()
		left = BinaryExpr{Op: "^", Left: left, Right: p.parseBitAnd()}
	}
	return left
}

func (p *javaParser) parseBitAnd() Expression {
	left := p.parseEquality()
	for p.current().kind == javaTokAmp {
		p.advance()
		left = BinaryExpr{Op: "&", Left: left, Right: p.parseEquality()}
	}
	return left
}

func (p *javaParser) parseEquality() Expression {
	left := p.parseComparison()
	for {
		var op string
		switch p.current().kind {
		case javaTokEqEq:
			op = "==="
		case javaTokBangEq:
			op = "!=="
		default:
			return left
		}
		p.advance()
		left = BinaryExpr{Op: op, Left: left, Right: p.parseComparison()}
	}
}

func (p *javaParser) parseComparison() Expression {
	left := p.parseShift()
	for {
		var op string
		switch p.current().kind {
		case javaTokLt:
			op = "<"
		case javaTokLtEq:
			op = "<="
		case javaTokGt:
			op = ">"
		case javaTokGtEq:
			op = ">="
		default:
			return left
		}
		p.advance()
		left = BinaryExpr{Op: op, Left: left, Right: p.parseShift()}
	}
}

func (p *javaParser) parseShift() Expression {
	left := p.parseAddSub()
	for {
		var op string
		switch p.current().kind {
		case javaTokShl:
			op = "<<"
		case javaTokShr:
			op = ">>"
		default:
			return left
		}
		p.advance()
		left = BinaryExpr{Op: op, Left: left, Right: p.parseAddSub()}
	}
}

func (p *javaParser) parseAddSub() Expression {
	left := p.parseMulDiv()
	for {
		var op string
		switch p.current().kind {
		case javaTokPlus:
			op = "+"
		case javaTokMinus:
			op = "-"
		default:
			return left
		}
		p.advance()
		left = BinaryExpr{Op: op, Left: left, Right: p.parseMulDiv()}
	}
}

func (p *javaParser) parseMulDiv() Expression {
	left := p.parseUnary()
	for {
		var op string
		switch p.current().kind {
		case javaTokStar:
			op = "*"
		case javaTokSlash:
			op = "/"
		case javaTokPercent:
			op = "%"
		default:
			return left
		}
		p.advance()
		left = BinaryExpr{Op: op, Left: left, Right: p.parseUnary()}
	}
}

func (p *javaParser) parseUnary() Expression {
	switch p.current().kind {
	case javaTokBang:
		p.advance()
		return UnaryExpr{Op: "!", Operand: p.parseUnary()}
	case javaTokMinus:
		p.advance()
		return UnaryExpr{Op: "-", Operand: p.parseUnary()}
	case javaTokPlus:
		// +x == x
		p.advance()
		return p.parseUnary()
	case javaTokTilde:
		p.advance()
		return UnaryExpr{Op: "~", Operand: p.parseUnary()}
	case javaTokPlusPlus:
		p.advance()
		return IncrementExpr{Operand: p.parseUnary(), Prefix: true}
	case javaTokMinusMinus:
		p.advance()
		return DecrementExpr{Operand: p.parseUnary(), Prefix: true}
	}
	return p.parsePostfix()
}

func (p *javaParser) parsePostfix() Expression {
	expr := p.parsePrimary()
	for {
		switch p.current().kind {
		case javaTokDot:
			p.advance()
			// member access — `.Name`
			if p.current().kind != javaTokIdent {
				p.addError("expected identifier after '.'")
				return expr
			}
			propName := p.advance().value
			// `this.foo` → PropertyAccessExpr
			if id, ok := expr.(Identifier); ok && id.Name == "this" {
				expr = PropertyAccessExpr{Property: propName}
				continue
			}
			expr = MemberExpr{Object: expr, Property: propName}

		case javaTokLParen:
			// Method call
			p.advance()
			var args []Expression
			for p.current().kind != javaTokRParen && p.current().kind != javaTokEOF {
				args = append(args, p.parseExpression())
				if !p.match(javaTokComma) {
					break
				}
			}
			p.expect(javaTokRParen)
			expr = p.recogniseLiteralCall(expr, args)

		case javaTokLBracket:
			p.advance()
			idx := p.parseExpression()
			p.expect(javaTokRBracket)
			expr = IndexAccessExpr{Object: expr, Index: idx}

		case javaTokPlusPlus:
			p.advance()
			expr = IncrementExpr{Operand: expr, Prefix: false}

		case javaTokMinusMinus:
			p.advance()
			expr = DecrementExpr{Operand: expr, Prefix: false}

		default:
			return expr
		}
	}
}

// recogniseLiteralCall folds:
//   - Xxx.fromHex("deadbeef")             → ByteStringLiteral
//   - BigInteger.valueOf(<intlit>)        → BigIntLiteral
//   - Bigint.of(<intlit>)                 → BigIntLiteral
//   - Bigint.of(<expr>)                   → <expr>            (identity wrap)
//   - BigInteger.valueOf(<expr>)          → <expr>            (identity wrap)
//   - <expr>.value()                      → <expr>            (identity unwrap)
//   - a.plus(b) / a.minus(b) / ...        → BinaryExpr        (Bigint arith)
//   - a.neg()                             → UnaryExpr(-)
//   - a.abs()                             → CallExpr(abs, a)  (builtin)
//   - assertThat(c)                       → CallExpr(assert, c)
//
// Otherwise returns CallExpr{Callee, Args}.
func (p *javaParser) recogniseLiteralCall(callee Expression, args []Expression) Expression {
	if me, ok := callee.(MemberExpr); ok && me.Property == "fromHex" && len(args) == 1 {
		if bs, ok := args[0].(ByteStringLiteral); ok {
			return ByteStringLiteral{Value: bs.Value}
		}
	}
	// BigInteger.valueOf(<intlit>) / Bigint.of(<intlit>) → BigIntLiteral
	if me, ok := callee.(MemberExpr); ok && len(args) == 1 {
		if id, ok := me.Object.(Identifier); ok {
			if (id.Name == "BigInteger" && me.Property == "valueOf") ||
				(id.Name == "Bigint" && me.Property == "of") {
				if lit, ok := args[0].(BigIntLiteral); ok {
					return BigIntLiteral{Value: new(big.Int).Set(lit.Value)}
				}
			}
		}
	}
	// Bigint.of(<arbitrary expression>) / BigInteger.valueOf(<arbitrary expression>)
	// — identity at the Rúnar AST level. Bigint and BigInteger collapse to the
	// same BIGINT primitive, so the wrap is a no-op: lower to the inner
	// expression. Mirrors JavaParser.java's identity branch.
	if me, ok := callee.(MemberExpr); ok && len(args) == 1 {
		if id, ok := me.Object.(Identifier); ok {
			if (id.Name == "Bigint" && me.Property == "of") ||
				(id.Name == "BigInteger" && me.Property == "valueOf") {
				return args[0]
			}
		}
	}
	// <expr>.value() — unwrapping a Bigint back to its underlying BigInteger.
	// Symmetric no-op to Bigint.of(...) above.
	if me, ok := callee.(MemberExpr); ok && me.Property == "value" && len(args) == 0 {
		return me.Object
	}
	// Bigint-wrapper arithmetic methods: `a.plus(b)` → BinaryExpr(+, a, b),
	// `a.neg()` → UnaryExpr(-, a), `a.abs()` → CallExpr(abs, a). Matched by
	// method name + arity; receiver type is not consulted (the typechecker
	// catches misuse). Mirrors JavaParser.tryLowerBigintMethod.
	if me, ok := callee.(MemberExpr); ok {
		if op, ok := javaBigintBinaryMethods[me.Property]; ok && len(args) == 1 {
			return BinaryExpr{Op: op, Left: me.Object, Right: args[0]}
		}
		if me.Property == "neg" && len(args) == 0 {
			return UnaryExpr{Op: "-", Operand: me.Object}
		}
		if me.Property == "abs" && len(args) == 0 {
			return CallExpr{Callee: Identifier{Name: "abs"}, Args: []Expression{me.Object}}
		}
	}
	// Static-imported `assertThat(cond)` is a builtin alias for `assert` in
	// the canonical Java BuiltinRegistry. Peer typecheckers only know
	// `assert`, so rewrite the callee here.
	if id, ok := callee.(Identifier); ok && id.Name == "assertThat" {
		return CallExpr{Callee: Identifier{Name: "assert"}, Args: args}
	}
	return CallExpr{Callee: callee, Args: args}
}

// javaBigintBinaryMethods maps Bigint-wrapper method names to canonical
// Rúnar BinaryOp strings. Mirrors JavaParser.BIGINT_BINARY_METHODS; unary
// `neg`/`abs` are handled separately at the call site. Receiver type is not
// consulted (parser has no type info at this stage); the typechecker rejects
// misuse (e.g. `someBoolean.plus(other)`).
var javaBigintBinaryMethods = map[string]string{
	"plus":  "+",
	"minus": "-",
	"times": "*",
	"div":   "/",
	"mod":   "%",
	"shl":   "<<",
	"shr":   ">>",
	"and":   "&",
	"or":    "|",
	"xor":   "^",
	"gt":    ">",
	"lt":    "<",
	"ge":    ">=",
	"le":    "<=",
	"eq":    "===",
	"neq":   "!==",
}

func (p *javaParser) parsePrimary() Expression {
	t := p.current()
	switch t.kind {
	case javaTokNumber:
		p.advance()
		bi := new(big.Int)
		if _, ok := bi.SetString(t.value, 0); !ok {
			// Fall back to decimal parsing
			bi2 := new(big.Int)
			if _, ok := bi2.SetString(t.value, 10); !ok {
				p.addErrorAt(fmt.Sprintf("invalid integer literal %q", t.value), t)
				return BigIntLiteral{Value: big.NewInt(0)}
			}
			return BigIntLiteral{Value: bi2}
		}
		return BigIntLiteral{Value: bi}

	case javaTokString:
		p.advance()
		return ByteStringLiteral{Value: t.value}

	case javaTokTrue:
		p.advance()
		return BoolLiteral{Value: true}

	case javaTokFalse:
		p.advance()
		return BoolLiteral{Value: false}

	case javaTokThis:
		p.advance()
		return Identifier{Name: "this"}

	case javaTokSuper:
		p.advance()
		return Identifier{Name: "super"}

	case javaTokLParen:
		p.advance()
		// Type cast `(Type) expr` is not supported; assume parenthesised
		// expression.
		expr := p.parseExpression()
		p.expect(javaTokRParen)
		return expr

	case javaTokNew:
		return p.parseNewExpression()

	case javaTokIdent:
		p.advance()
		// Fold BigInteger.ZERO / ONE / TWO / TEN as BigIntLiteral at the
		// member-access parsing stage (postfix). Here we just emit the
		// identifier; postfix resolves `.ZERO` to a MemberExpr which we
		// then re-interpret below.
		name := t.value
		expr := Expression(Identifier{Name: name})
		// Peek for BigInteger.{ZERO,ONE,TWO,TEN} or Bigint.{ZERO,ONE,TWO,TEN}.
		// The Bigint wrapper re-exports BigInteger's constants so both
		// spellings are accepted (matches JavaParser.convertExpression).
		if (name == "BigInteger" || name == "Bigint") &&
			p.current().kind == javaTokDot &&
			p.peekAt(1).kind == javaTokIdent {
			switch p.peekAt(1).value {
			case "ZERO":
				p.advance()
				p.advance()
				return BigIntLiteral{Value: big.NewInt(0)}
			case "ONE":
				p.advance()
				p.advance()
				return BigIntLiteral{Value: big.NewInt(1)}
			case "TWO":
				p.advance()
				p.advance()
				return BigIntLiteral{Value: big.NewInt(2)}
			case "TEN":
				p.advance()
				p.advance()
				return BigIntLiteral{Value: big.NewInt(10)}
			}
		}
		return expr

	default:
		p.addErrorAt(fmt.Sprintf("unexpected token (kind=%d, value=%q) in expression", t.kind, t.value), t)
		p.advance()
		return Identifier{Name: "unknown"}
	}
}

// parseNewExpression parses `new T[] { e1, e2, ... }` and returns an
// ArrayLiteralExpr. Other `new` forms (constructor invocations) are not
// part of the Rúnar subset and produce an error.
func (p *javaParser) parseNewExpression() Expression {
	newTok := p.current()
	p.expect(javaTokNew)

	// Parse the element type by hand — we intentionally do NOT call
	// parseType() here because parseType() consumes a trailing `[]`, and
	// for `new T[] {...}` the `[]` needs to be visible to us so we can
	// confirm this is an array-literal form.
	if p.current().kind != javaTokIdent {
		p.addErrorAt("expected type after 'new'", newTok)
		return Identifier{Name: "unknown"}
	}
	for p.current().kind == javaTokIdent {
		p.advance()
		if p.current().kind == javaTokDot {
			p.advance()
			continue
		}
		break
	}
	// Optional generic args on the element type
	if p.current().kind == javaTokLt {
		depth := 1
		p.advance()
		for depth > 0 && p.current().kind != javaTokEOF {
			switch p.current().kind {
			case javaTokLt:
				depth++
			case javaTokGt:
				depth--
			}
			p.advance()
		}
	}

	// Expect [] pair — unsized
	if !p.match(javaTokLBracket) {
		p.addErrorAt("expected '[' after 'new T'", p.current())
		return Identifier{Name: "unknown"}
	}
	p.match(javaTokRBracket)

	// { elements }
	p.expect(javaTokLBrace)
	var elements []Expression
	for p.current().kind != javaTokRBrace && p.current().kind != javaTokEOF {
		elements = append(elements, p.parseExpression())
		if !p.match(javaTokComma) {
			break
		}
	}
	p.expect(javaTokRBrace)

	return ArrayLiteralExpr{Elements: elements}
}
