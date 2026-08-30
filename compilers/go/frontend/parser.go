package frontend

import (
	"context"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/icellan/runar/compilers/go/codegen"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParseResult holds the result of parsing a Rúnar source file.
type ParseResult struct {
	Contract *ContractNode
	Errors   []Diagnostic
	// SourceSizeErr is non-nil iff ParseSource rejected the input via the
	// DoS-bound source-size guard. Callers wanting typed detection can
	// check `result.SourceSizeErr != nil` (or `errors.As`) instead of
	// string-matching the diagnostic message. BUG-008 follow-up.
	SourceSizeErr *SourceSizeExceededError
}

// ErrorStrings returns error messages as strings (for backward compatibility).
func (r *ParseResult) ErrorStrings() []string {
	result := make([]string, len(r.Errors))
	for i, d := range r.Errors {
		result[i] = d.FormatMessage()
	}
	return result
}

// ParseSource detects the file extension and routes to the appropriate parser.
//   - .runar.sol -> ParseSolidity
//   - .runar.move -> ParseMove
//   - .runar.go -> ParseGoContract
//   - .runar.py -> ParsePython
//   - .runar.rs -> ParseRustMacro
//   - .runar.rb -> ParseRuby
//   - .runar.zig -> ParseZig
//   - .runar.java -> ParseJava
//   - default -> Parse (existing TypeScript parser)
// ackUnsoundSP1FriRE opts a contract in to the KNOWN-UNSOUND SP1 FRI verifier.
// Scanned over the RAW SOURCE in ParseSource so every surface format honours it
// identically — unlike @sighash / @embedAlways, which only the TypeScript
// parser reads. See sp1_fri_soundness_warning.go for what is unsound and why
// the default is a hard error.
var ackUnsoundSP1FriRE = regexp.MustCompile(`@acknowledgeUnsoundSP1FriVerifier\b`)

func ParseSource(source []byte, fileName string) *ParseResult {
	// DoS-bound size guard. Reject oversized source BEFORE any
	// format-specific parser touches the input. BUG-008 follow-up.
	if err := assertSourceBytesUnderLimit(source); err != nil {
		sse := err.(*SourceSizeExceededError)
		return &ParseResult{
			Errors: []Diagnostic{{
				Message:  sse.Error(),
				Severity: SeverityError,
			}},
			SourceSizeErr: sse,
		}
	}

	lower := strings.ToLower(fileName)

	// The TypeScript surface parser (Parse, the default branch) now honours the
	// `@sighash` (#123, per-method sighash type) and `@embedAlways` (#109,
	// readonly-field DCE opt-out) comment directives, matching the TS reference
	// compiler. The eight non-TS surface parsers below do NOT read comments, so
	// they would silently drop these directives and change signing / DCE
	// semantics. Fail closed on those formats rather than miscompile — this is
	// strictly safer than the TS reference (which silently ignores the
	// directives in its non-.ts frontends) and has zero conformance impact (no
	// fixture uses the directives). The `.runar.ts` surface is exempt because
	// Parse now implements the directives.
	switch {
	case strings.HasSuffix(lower, ".runar.sol"):
		if msg := unsupportedDirectiveError(source, "Solidity"); msg != "" {
			return directiveGuardResult(msg)
		}
		return ParseSolidity(source, fileName)
	case strings.HasSuffix(lower, ".runar.move"):
		if msg := unsupportedDirectiveError(source, "Move"); msg != "" {
			return directiveGuardResult(msg)
		}
		return stampSP1FriAck(ParseMove(source, fileName), source)
	case strings.HasSuffix(lower, ".runar.go"):
		if msg := unsupportedDirectiveError(source, "Go DSL"); msg != "" {
			return directiveGuardResult(msg)
		}
		return stampSP1FriAck(ParseGoContract(source, fileName), source)
	case strings.HasSuffix(lower, ".runar.py"):
		if msg := unsupportedDirectiveError(source, "Python"); msg != "" {
			return directiveGuardResult(msg)
		}
		return stampSP1FriAck(ParsePython(source, fileName), source)
	case strings.HasSuffix(lower, ".runar.rs"):
		if msg := unsupportedDirectiveError(source, "Rust"); msg != "" {
			return directiveGuardResult(msg)
		}
		return ParseRustMacro(source, fileName)
	case strings.HasSuffix(lower, ".runar.rb"):
		if msg := unsupportedDirectiveError(source, "Ruby"); msg != "" {
			return directiveGuardResult(msg)
		}
		return stampSP1FriAck(ParseRuby(source, fileName), source)
	case strings.HasSuffix(lower, ".runar.zig"):
		if msg := unsupportedDirectiveError(source, "Zig"); msg != "" {
			return directiveGuardResult(msg)
		}
		return stampSP1FriAck(ParseZig(source, fileName), source)
	case strings.HasSuffix(lower, ".runar.java"):
		if msg := unsupportedDirectiveError(source, "Java"); msg != "" {
			return directiveGuardResult(msg)
		}
		return stampSP1FriAck(ParseJava(source, fileName), source)
	default:
		// TypeScript surface: honours @sighash / @embedAlways directly.
		return stampSP1FriAck(Parse(source, fileName), source)
	}
}

// stampSP1FriAck records whether the raw source carried the
// @acknowledgeUnsoundSP1FriVerifier directive. Applied to the parse RESULT so
// it is independent of which surface parser ran.
func stampSP1FriAck(res *ParseResult, source []byte) *ParseResult {
	if res != nil && res.Contract != nil && ackUnsoundSP1FriRE.Match(source) {
		res.Contract.AckUnsoundSP1Fri = true
	}
	return res
}

// Directive markers for the fail-closed guard. Word-boundary anchored to
// mirror the TypeScript compiler's `/@sighash\b/` / `/@embedAlways\b/` scans,
// so an identifier like `sighashType` does not trip the guard.
var (
	sighashDirectiveRE     = regexp.MustCompile(`@sighash\b`)
	embedAlwaysDirectiveRE = regexp.MustCompile(`@embedAlways\b`)
)

func directiveGuardResult(msg string) *ParseResult {
	return &ParseResult{Errors: []Diagnostic{{Message: msg, Severity: SeverityError}}}
}

// unsupportedDirectiveError returns a non-empty diagnostic message when the
// source carries a `@sighash` (#123) or `@embedAlways` (#109) directive on a
// surface format whose parser does not read comments (so the directive would be
// silently dropped), or "" when the source is clean. surfaceName names the
// non-TS format for the diagnostic.
func unsupportedDirectiveError(source []byte, surfaceName string) string {
	if sighashDirectiveRE.Match(source) {
		return fmt.Sprintf("@sighash directive (issue #123) is not supported by the %s surface parser; write the contract in TypeScript (.runar.ts) where @sighash is honoured", surfaceName)
	}
	if embedAlwaysDirectiveRE.Match(source) {
		return fmt.Sprintf("@embedAlways directive (issue #109) is not supported by the %s surface parser; write the contract in TypeScript (.runar.ts) where @embedAlways is honoured", surfaceName)
	}
	return ""
}

// Parse parses a TypeScript source string and extracts the Rúnar contract AST.
func Parse(source []byte, fileName string) *ParseResult {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())

	tree, err := parser.ParseCtx(context.Background(), nil, source)
	if err != nil {
		return &ParseResult{Errors: []Diagnostic{{Message: fmt.Sprintf("parse error: %v", err), Severity: SeverityError}}}
	}

	root := tree.RootNode()
	p := &parseContext{
		source:   source,
		fileName: fileName,
	}

	// tree-sitter is error-tolerant: malformed source still yields a tree, with
	// the bad region marked ERROR/MISSING. Walking such a tree silently DROPS
	// whatever failed to resolve (a statement parser returning nil is simply
	// not appended), so `this.value = ;` used to compile to a script with the
	// state write missing, and a malformed `assert(...)` to a script with the
	// guard missing. Refuse the file instead — one check for every malformed
	// shape, rather than a nil-guard per statement kind.
	if root.HasError() {
		if bad := firstBadNode(root); bad != nil {
			p.addError(fmt.Sprintf(
				"syntax error at line %d: unparseable %s near %q",
				bad.StartPoint().Row+1, bad.Type(), p.snippet(bad),
			))
		} else {
			p.addError("syntax error: source is not valid Rúnar")
		}
		return &ParseResult{Errors: p.errors}
	}

	contract := p.findContract(root)
	if contract == nil {
		p.addError("no class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found")
		return &ParseResult{Errors: p.errors}
	}

	return &ParseResult{
		Contract: contract,
		Errors:   p.errors,
	}
}

// ---------------------------------------------------------------------------
// Parse context
// ---------------------------------------------------------------------------

type parseContext struct {
	source   []byte
	fileName string
	errors   []Diagnostic
}

// firstBadNode returns the first ERROR or MISSING node in the tree, so the
// diagnostic can point at the offending line instead of the whole file.
func firstBadNode(n *sitter.Node) *sitter.Node {
	if n.IsError() || n.IsMissing() {
		return n
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		if bad := firstBadNode(n.Child(i)); bad != nil {
			return bad
		}
	}
	return nil
}

// snippet renders a short, single-line excerpt of the node's source span for
// the diagnostic message.
func (p *parseContext) snippet(n *sitter.Node) string {
	start, end := int(n.StartByte()), int(n.EndByte())
	if start < 0 || end > len(p.source) || start >= end {
		return ""
	}
	text := strings.TrimSpace(string(p.source[start:end]))
	if idx := strings.IndexAny(text, "\r\n"); idx >= 0 {
		text = text[:idx]
	}
	if len(text) > 40 {
		text = text[:40] + "..."
	}
	return text
}

func (p *parseContext) addError(msg string) {
	p.errors = append(p.errors, Diagnostic{Message: msg, Severity: SeverityError})
}

func (p *parseContext) nodeText(node *sitter.Node) string {
	return node.Content(p.source)
}

func (p *parseContext) loc(node *sitter.Node) SourceLocation {
	pos := node.StartPoint()
	return SourceLocation{
		File:   p.fileName,
		Line:   int(pos.Row) + 1,
		Column: int(pos.Column),
	}
}

// ---------------------------------------------------------------------------
// Contract discovery
// ---------------------------------------------------------------------------

func (p *parseContext) findContract(root *sitter.Node) *ContractNode {
	var contract *ContractNode

	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}

		if child.Type() == "class_declaration" {
			c := p.tryParseContractClass(child)
			if c != nil {
				if contract != nil {
					p.addError("only one SmartContract subclass allowed per file")
				}
				contract = c
			}
		}
		// Also check export_statement wrapping a class
		if child.Type() == "export_statement" {
			for j := 0; j < int(child.ChildCount()); j++ {
				gc := child.Child(j)
				if gc == nil {
					continue
				}

				if gc.Type() == "class_declaration" {
					c := p.tryParseContractClass(gc)
					if c != nil {
						if contract != nil {
							p.addError("only one SmartContract subclass allowed per file")
						}
						contract = c
					}
				}
			}
		}
	}

	return contract
}

func (p *parseContext) tryParseContractClass(node *sitter.Node) *ContractNode {
	// Check if class extends SmartContract
	heritage := p.findChildByType(node, "class_heritage")
	if heritage == nil {
		return nil
	}

	// The heritage clause should contain "SmartContract",
	// "StatefulSmartContract", or "UnsafeSmartContract". Order matters:
	// both "StatefulSmartContract" and "UnsafeSmartContract" contain the
	// substring "SmartContract", so they must be checked first.
	heritageText := p.nodeText(heritage)
	parentClass := ""
	if strings.Contains(heritageText, "StatefulSmartContract") {
		parentClass = "StatefulSmartContract"
	} else if strings.Contains(heritageText, "UnsafeSmartContract") {
		parentClass = "UnsafeSmartContract"
	} else if strings.Contains(heritageText, "SmartContract") {
		parentClass = "SmartContract"
	} else {
		return nil
	}

	// Get class name
	nameNode := p.findChildByType(node, "type_identifier")
	if nameNode == nil {
		nameNode = p.findChildByType(node, "identifier")
	}
	className := "UnnamedContract"
	if nameNode != nil {
		className = p.nodeText(nameNode)
	}

	// Get class body
	body := p.findChildByType(node, "class_body")
	if body == nil {
		p.addError("class has no body")
		return nil
	}

	// Parse properties, constructor, and methods
	var properties []PropertyNode
	var constructor *MethodNode
	var methods []MethodNode

	for i := 0; i < int(body.ChildCount()); i++ {
		member := body.Child(i)
		switch member.Type() {
		case "public_field_definition":
			prop := p.parseProperty(member)
			if prop != nil {
				properties = append(properties, *prop)
			}
		case "method_definition":
			name := p.getMethodName(member)
			if name == "constructor" {
				ctor := p.parseConstructor(member)
				constructor = &ctor
			} else {
				method := p.parseMethod(member)
				methods = append(methods, method)
			}
		}
	}

	if constructor == nil {
		p.addError("contract must have a constructor")
		defaultCtor := MethodNode{
			Name:           "constructor",
			Visibility:     "public",
			SourceLocation: p.loc(node),
		}
		constructor = &defaultCtor
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

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

func (p *parseContext) parseProperty(node *sitter.Node) *PropertyNode {
	// public_field_definition contains: accessibility_modifier?, readonly?, property_name, type_annotation?, initializer?
	isReadonly := false
	var nameStr string
	var typeNode TypeNode

	var initializer Expression

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "readonly":
			isReadonly = true
		case "property_identifier":
			nameStr = p.nodeText(child)
		case "type_annotation":
			typeNode = p.parseTypeAnnotation(child)
		default:
			// SWC tree-sitter may expose the initializer as a child expression node
			if nameStr != "" && typeNode != nil && initializer == nil {
				initializer = p.parseExpression(child)
			}
		}
	}

	if nameStr == "" {
		return nil
	}

	if typeNode == nil {
		p.addError(fmt.Sprintf("property '%s' must have an explicit type annotation", nameStr))
		typeNode = CustomType{Name: "unknown"}
	}

	// Issue #109: `/** @embedAlways */` (or `// @embedAlways`) directive in the
	// field's leading comment trivia opts it out of DCE elimination.
	embedAlways := embedAlwaysDirectiveRE.MatchString(p.leadingCommentText(node))

	return &PropertyNode{
		Name:           nameStr,
		Type:           typeNode,
		Readonly:       isReadonly,
		Initializer:    initializer,
		EmbedAlways:    embedAlways,
		SourceLocation: p.loc(node),
	}
}

// leadingCommentText collects the text of consecutive `comment` sibling nodes
// immediately preceding a class-body member (property / method). tree-sitter
// exposes comments as siblings in the class_body, so a `/** @sighash ... */`
// or `// @embedAlways` directive is the immediately-preceding sibling of the
// member it annotates. Stacked comments are concatenated (mirrors the TS
// reference's JSDoc + leading-trivia scan).
func (p *parseContext) leadingCommentText(node *sitter.Node) string {
	var parts []string
	for prev := node.PrevSibling(); prev != nil && prev.Type() == "comment"; prev = prev.PrevSibling() {
		parts = append(parts, p.nodeText(prev))
	}
	return strings.Join(parts, "\n")
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func (p *parseContext) parseConstructor(node *sitter.Node) MethodNode {
	params := p.parseMethodParams(node)
	body := p.parseMethodBody(node)

	return MethodNode{
		Name:           "constructor",
		Params:         params,
		Body:           body,
		Visibility:     "public",
		SourceLocation: p.loc(node),
	}
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

func (p *parseContext) parseMethod(node *sitter.Node) MethodNode {
	name := p.getMethodName(node)
	params := p.parseMethodParams(node)
	body := p.parseMethodBody(node)

	visibility := "private"
	// Check for accessibility modifier
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "accessibility_modifier" {
			modText := p.nodeText(child)
			if modText == "public" {
				visibility = "public"
			}
		}
	}

	// Issue #123: `/** @sighash <FLAGS> */` directive → per-method sighash type.
	sighashType := p.parseSighashOnMethod(node, name, visibility)

	return MethodNode{
		Name:           name,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SighashType:    sighashType,
		SourceLocation: p.loc(node),
	}
}

// parseSighashOnMethod detects + parses a `/** @sighash <FLAGS> */` (or
// `// @sighash ...`) directive on a method from its leading comment trivia.
// Returns the numeric sighash type, or nil when no directive is present.
// Pushes an error for a malformed flag list or a directive on a non-public
// method (only public methods are spending entry points, so a `@sighash` on a
// private helper is meaningless). Mirrors the TS parseSighashOnMethod.
func (p *parseContext) parseSighashOnMethod(node *sitter.Node, name, visibility string) *int {
	comments := p.leadingCommentText(node)
	result, present := extractSighashDirective(comments)
	if !present {
		return nil
	}

	if visibility != "public" {
		p.addError(fmt.Sprintf(
			"@sighash directive on non-public method '%s' has no effect — only public methods are spending entry points",
			name))
		return nil
	}

	if !result.ok() {
		p.addError(fmt.Sprintf("Method '%s': %s", name, result.err))
		return nil
	}
	v := result.value
	return &v
}

func (p *parseContext) getMethodName(node *sitter.Node) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "property_identifier" {
			return p.nodeText(child)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

func (p *parseContext) parseMethodParams(node *sitter.Node) []ParamNode {
	formalParams := p.findChildByType(node, "formal_parameters")
	if formalParams == nil {
		return nil
	}

	var params []ParamNode
	for i := 0; i < int(formalParams.ChildCount()); i++ {
		child := formalParams.Child(i)
		if child.Type() == "required_parameter" || child.Type() == "optional_parameter" {
			param := p.parseParam(child)
			if param != nil {
				params = append(params, *param)
			}
		}
	}

	return params
}

func (p *parseContext) parseParam(node *sitter.Node) *ParamNode {
	var name string
	var typ TypeNode

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "identifier":
			name = p.nodeText(child)
		case "type_annotation":
			typ = p.parseTypeAnnotation(child)
		}
	}

	if name == "" {
		return nil
	}

	if typ == nil {
		p.addError(fmt.Sprintf("parameter '%s' must have an explicit type annotation", name))
		typ = CustomType{Name: "unknown"}
	}

	return &ParamNode{Name: name, Type: typ}
}

// ---------------------------------------------------------------------------
// Type annotations
// ---------------------------------------------------------------------------

func (p *parseContext) parseTypeAnnotation(node *sitter.Node) TypeNode {
	// type_annotation: ":" type
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		if child.Type() != ":" {
			return p.parseTypeExpr(child)
		}
	}
	return CustomType{Name: "unknown"}
}

func (p *parseContext) parseTypeExpr(node *sitter.Node) TypeNode {
	text := p.nodeText(node)

	switch node.Type() {
	case "predefined_type":
		// bigint, boolean, void, etc.
		switch text {
		case "bigint":
			return PrimitiveType{Name: "bigint"}
		case "boolean":
			return PrimitiveType{Name: "boolean"}
		case "void":
			return PrimitiveType{Name: "void"}
		case "number":
			p.addError("use 'bigint' instead of 'number' in Rúnar contracts")
			return PrimitiveType{Name: "bigint"}
		}
		return CustomType{Name: text}

	case "generic_type":
		// FixedArray<T, N>
		return p.parseGenericType(node)

	case "type_identifier":
		fallthrough
	default:
		// Try text match for primitive types
		if IsPrimitiveType(text) {
			return PrimitiveType{Name: text}
		}
		return CustomType{Name: text}
	}
}

func (p *parseContext) parseGenericType(node *sitter.Node) TypeNode {
	// generic_type: type_identifier type_arguments
	nameNode := p.findChildByType(node, "type_identifier")
	if nameNode == nil {
		return CustomType{Name: p.nodeText(node)}
	}

	typeName := p.nodeText(nameNode)
	if typeName != "FixedArray" {
		return CustomType{Name: typeName}
	}

	// Find type_arguments
	argsNode := p.findChildByType(node, "type_arguments")
	if argsNode == nil {
		p.addError("FixedArray requires exactly 2 type arguments")
		return CustomType{Name: typeName}
	}

	// Collect the type arguments (skip punctuation)
	var typeArgs []*sitter.Node
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil {
			continue
		}

		t := child.Type()
		if t != "<" && t != ">" && t != "," {
			typeArgs = append(typeArgs, child)
		}
	}

	if len(typeArgs) != 2 {
		p.addError("FixedArray requires exactly 2 type arguments")
		return CustomType{Name: typeName}
	}

	elemType := p.parseTypeExpr(typeArgs[0])
	sizeText := p.nodeText(typeArgs[1])
	size, err := strconv.Atoi(sizeText)
	if err != nil || size < 0 {
		p.addError(fmt.Sprintf("FixedArray size must be a non-negative integer literal, got '%s'", sizeText))
		return CustomType{Name: typeName}
	}

	return FixedArrayType{Element: elemType, Length: size}
}

// ---------------------------------------------------------------------------
// Method body / statements
// ---------------------------------------------------------------------------

func (p *parseContext) parseMethodBody(node *sitter.Node) []Statement {
	body := p.findChildByType(node, "statement_block")
	if body == nil {
		return nil
	}
	return p.parseStatements(body)
}

func (p *parseContext) parseStatements(block *sitter.Node) []Statement {
	var stmts []Statement
	for i := 0; i < int(block.ChildCount()); i++ {
		child := block.Child(i)
		stmt := p.parseStatement(child)
		if stmt != nil {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

func (p *parseContext) parseBlockStatements(node *sitter.Node) []Statement {
	if node.Type() == "statement_block" {
		return p.parseStatements(node)
	}
	// else_clause wraps a statement_block or single statement
	if node.Type() == "else_clause" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "statement_block" {
				return p.parseStatements(child)
			}
			if child.Type() == "if_statement" {
				stmt := p.parseIfStatement(child)
				if stmt != nil {
					return []Statement{stmt}
				}
			}
		}
		// Fallback: try parsing the last non-keyword child as a statement
		for i := int(node.ChildCount()) - 1; i >= 0; i-- {
			child := node.Child(i)
			if child.Type() != "else" {
				stmt := p.parseStatement(child)
				if stmt != nil {
					return []Statement{stmt}
				}
			}
		}
		return nil
	}
	// Single statement (no braces)
	stmt := p.parseStatement(node)
	if stmt != nil {
		return []Statement{stmt}
	}
	return nil
}

func (p *parseContext) parseStatement(node *sitter.Node) Statement {
	switch node.Type() {
	case "lexical_declaration":
		return p.parseVariableDecl(node)

	case "expression_statement":
		return p.parseExpressionStatement(node)

	case "if_statement":
		return p.parseIfStatement(node)

	case "for_statement":
		return p.parseForStatement(node)

	case "return_statement":
		return p.parseReturnStatement(node)

	case "{", "}", "(", ")", ";", ",", "comment":
		return nil

	default:
		// Skip unknown node types silently (e.g., punctuation)
		return nil
	}
}

// ---------------------------------------------------------------------------
// Variable declarations
// ---------------------------------------------------------------------------

func (p *parseContext) parseVariableDecl(node *sitter.Node) Statement {
	// lexical_declaration: (const|let) variable_declarator
	isConst := false
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "const" {
			isConst = true
		}
	}

	// Find variable_declarator
	declarator := p.findChildByType(node, "variable_declarator")
	if declarator == nil {
		return nil
	}

	var name string
	var typeNode TypeNode
	var initExpr Expression
	// The declarator has the form `<name> [type_annotation] [= <init>]`.
	// Once we've walked past the `=` token, remaining children belong to the
	// initializer (including bare identifiers like `const x = b`, which would
	// otherwise get mis-parsed as re-declaring `name`).
	seenEq := false

	for i := 0; i < int(declarator.ChildCount()); i++ {
		child := declarator.Child(i)
		switch child.Type() {
		case "=":
			seenEq = true
		case "identifier":
			if !seenEq {
				name = p.nodeText(child)
			} else {
				if expr := p.parseExpression(child); expr != nil {
					initExpr = expr
				}
			}
		case "type_annotation":
			typeNode = p.parseTypeAnnotation(child)
		default:
			if child.Type() != ";" && child.Type() != ":" {
				// Try to parse as init expression
				expr := p.parseExpression(child)
				if expr != nil {
					initExpr = expr
				}
			}
		}
	}

	if name == "" {
		return nil
	}
	if initExpr == nil {
		initExpr = BigIntLiteral{Value: big.NewInt(0)}
	}

	return VariableDeclStmt{
		Name:           name,
		Type:           typeNode,
		Mutable:        !isConst,
		Init:           initExpr,
		SourceLocation: p.loc(node),
	}
}

// ---------------------------------------------------------------------------
// Expression statements (including assignments)
// ---------------------------------------------------------------------------

func (p *parseContext) parseExpressionStatement(node *sitter.Node) Statement {
	loc := p.loc(node)

	// expression_statement contains a single expression child
	var exprNode *sitter.Node
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != ";" {
			exprNode = child
			break
		}
	}

	if exprNode == nil {
		return nil
	}

	// Check for assignment: a = b, this.x = b, compound assignments
	if exprNode.Type() == "assignment_expression" {
		return p.parseAssignment(exprNode, loc)
	}

	// Check for augmented_assignment_expression (+=, -=, etc.)
	if exprNode.Type() == "augmented_assignment_expression" {
		return p.parseAugmentedAssignment(exprNode, loc)
	}

	// Regular expression statement
	expr := p.parseExpression(exprNode)
	if expr == nil {
		return nil
	}
	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

func (p *parseContext) parseAssignment(node *sitter.Node, loc SourceLocation) Statement {
	// assignment_expression: left "=" right
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		// fallback: parse children manually
		if node.ChildCount() >= 3 {
			leftNode = node.Child(0)
			rightNode = node.Child(2)
		}
	}

	if leftNode == nil || rightNode == nil {
		return nil
	}

	target := p.parseExpression(leftNode)
	value := p.parseExpression(rightNode)
	if target == nil || value == nil {
		return nil
	}

	return AssignmentStmt{Target: target, Value: value, SourceLocation: loc}
}

func (p *parseContext) parseAugmentedAssignment(node *sitter.Node, loc SourceLocation) Statement {
	// augmented_assignment_expression: left op right
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")
	opNode := node.ChildByFieldName("operator")

	if leftNode == nil || rightNode == nil {
		// fallback to child indices
		if node.ChildCount() >= 3 {
			leftNode = node.Child(0)
			opNode = node.Child(1)
			rightNode = node.Child(2)
		}
	}

	if leftNode == nil || rightNode == nil {
		return nil
	}

	opText := ""
	if opNode != nil {
		opText = p.nodeText(opNode)
	}

	// Map compound ops to binary ops
	var binOp string
	switch opText {
	case "+=":
		binOp = "+"
	case "-=":
		binOp = "-"
	case "*=":
		binOp = "*"
	case "/=":
		binOp = "/"
	case "%=":
		binOp = "%"
	default:
		binOp = "+"
	}

	target := p.parseExpression(leftNode)
	right := p.parseExpression(rightNode)
	if target == nil || right == nil {
		return nil
	}

	// Desugar: a += b -> a = a + b
	value := BinaryExpr{Op: binOp, Left: target, Right: right}
	targetAgain := p.parseExpression(leftNode)

	return AssignmentStmt{Target: targetAgain, Value: value, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// If statements
// ---------------------------------------------------------------------------

func (p *parseContext) parseIfStatement(node *sitter.Node) Statement {
	loc := p.loc(node)

	condNode := node.ChildByFieldName("condition")
	consequentNode := node.ChildByFieldName("consequence")
	alternativeNode := node.ChildByFieldName("alternative")

	var condition Expression
	if condNode != nil {
		condition = p.parseParenExpression(condNode)
	}
	if condition == nil {
		condition = BoolLiteral{Value: false}
	}

	var thenStmts []Statement
	if consequentNode != nil {
		thenStmts = p.parseBlockStatements(consequentNode)
	}

	var elseStmts []Statement
	if alternativeNode != nil {
		elseStmts = p.parseBlockStatements(alternativeNode)
	}

	return IfStmt{
		Condition:      condition,
		Then:           thenStmts,
		Else:           elseStmts,
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// For statements
// ---------------------------------------------------------------------------

func (p *parseContext) parseForStatement(node *sitter.Node) Statement {
	loc := p.loc(node)

	initNode := node.ChildByFieldName("initializer")
	condNode := node.ChildByFieldName("condition")
	updateNode := node.ChildByFieldName("increment")
	bodyNode := node.ChildByFieldName("body")

	// Parse initializer
	var initStmt VariableDeclStmt
	if initNode != nil {
		stmt := p.parseStatement(initNode)
		if vd, ok := stmt.(VariableDeclStmt); ok {
			initStmt = vd
		} else {
			// Try parsing as a lexical_declaration or variable_declaration
			s := p.parseVariableDeclFromForInit(initNode)
			if s != nil {
				initStmt = *s
			} else {
				initStmt = VariableDeclStmt{
					Name:           "_i",
					Mutable:        true,
					Init:           BigIntLiteral{Value: big.NewInt(0)},
					SourceLocation: loc,
				}
			}
		}
	} else {
		initStmt = VariableDeclStmt{
			Name:           "_i",
			Mutable:        true,
			Init:           BigIntLiteral{Value: big.NewInt(0)},
			SourceLocation: loc,
		}
	}

	// Parse condition
	var condition Expression
	if condNode != nil {
		// The condition might be wrapped in an expression_statement node
		if condNode.Type() == "expression_statement" && condNode.ChildCount() > 0 {
			condition = p.parseExpression(condNode.Child(0))
		} else {
			condition = p.parseExpression(condNode)
		}
	}
	if condition == nil {
		condition = BoolLiteral{Value: false}
	}

	// Parse update
	var update Statement
	if updateNode != nil {
		update = p.parseForUpdate(updateNode, loc)
	} else {
		update = ExpressionStmt{Expr: BigIntLiteral{Value: big.NewInt(0)}, SourceLocation: loc}
	}

	// Parse body
	var body []Statement
	if bodyNode != nil {
		body = p.parseBlockStatements(bodyNode)
	}

	return ForStmt{
		Init:           initStmt,
		Condition:      condition,
		Update:         update,
		Body:           body,
		SourceLocation: loc,
	}
}

func (p *parseContext) parseVariableDeclFromForInit(node *sitter.Node) *VariableDeclStmt {
	// For-loop initializers might be directly a variable declarator type
	nodeType := node.Type()

	if nodeType == "lexical_declaration" {
		stmt := p.parseVariableDecl(node)
		if vd, ok := stmt.(VariableDeclStmt); ok {
			return &vd
		}
	}

	// Walk children looking for the declaration
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "lexical_declaration" {
			stmt := p.parseVariableDecl(child)
			if vd, ok := stmt.(VariableDeclStmt); ok {
				return &vd
			}
		}
	}

	return nil
}

func (p *parseContext) parseForUpdate(node *sitter.Node, loc SourceLocation) Statement {
	expr := p.parseExpression(node)
	if expr == nil {
		return ExpressionStmt{Expr: BigIntLiteral{Value: big.NewInt(0)}, SourceLocation: loc}
	}
	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// Return statements
// ---------------------------------------------------------------------------

func (p *parseContext) parseReturnStatement(node *sitter.Node) Statement {
	loc := p.loc(node)

	var value Expression
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "return" && child.Type() != ";" {
			value = p.parseExpression(child)
			break
		}
	}

	return ReturnStmt{Value: value, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

func (p *parseContext) parseExpression(node *sitter.Node) Expression {
	if node == nil {
		return nil
	}

	switch node.Type() {
	case "binary_expression":
		return p.parseBinaryExpression(node)

	case "unary_expression":
		return p.parseUnaryExpression(node)

	case "update_expression":
		return p.parseUpdateExpression(node)

	case "call_expression":
		return p.parseCallExpression(node)

	case "member_expression":
		return p.parseMemberExpression(node)

	case "subscript_expression":
		return p.parseSubscriptExpression(node)

	case "array":
		// TypeScript array literal: [a, b, c]. Match the dedicated
		// per-format parsers (sol, move, rust, python, zig, ruby, java)
		// which all emit an ArrayLiteralExpr so checkMultiSig and other
		// builtins that consume Sig[]/PubKey[] type-check across all
		// 7 compilers. Anything that recurses into a child here must
		// itself be a real expression — tree-sitter's "array" node
		// children are punctuation tokens ("[", "]", ",") and inner
		// expressions interleaved; filter to the parseable nodes.
		elements := []Expression{}
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			t := child.Type()
			if t == "[" || t == "]" || t == "," {
				continue
			}
			if expr := p.parseExpression(child); expr != nil {
				elements = append(elements, expr)
			}
		}
		return ArrayLiteralExpr{Elements: elements}

	case "identifier":
		name := p.nodeText(node)
		if name == "true" {
			return BoolLiteral{Value: true}
		}
		if name == "false" {
			return BoolLiteral{Value: false}
		}
		return Identifier{Name: name}

	case "number":
		text := p.nodeText(node)
		// BigInt literals end with 'n'
		if strings.HasSuffix(text, "n") {
			text = text[:len(text)-1]
		}
		// Parse with big.Int for arbitrary-precision support.
		bi := new(big.Int)
		if _, ok := bi.SetString(text, 0); !ok {
			// Retry with decimal base for edge cases
			bi2 := new(big.Int)
			if _, ok2 := bi2.SetString(text, 10); !ok2 {
				p.addError(fmt.Sprintf("invalid integer literal: %s", text))
				return BigIntLiteral{Value: big.NewInt(0)}
			}
			return BigIntLiteral{Value: bi2}
		}
		return BigIntLiteral{Value: bi}

	case "true":
		return BoolLiteral{Value: true}

	case "false":
		return BoolLiteral{Value: false}

	case "string":
		return p.parseStringLiteral(node)

	case "template_string":
		text := p.nodeText(node)
		// Remove backticks
		if len(text) >= 2 {
			text = text[1 : len(text)-1]
		}
		return ByteStringLiteral{Value: text}

	case "ternary_expression":
		return p.parseTernaryExpression(node)

	case "parenthesized_expression":
		return p.parseParenExpression(node)

	case "this":
		return Identifier{Name: "this"}

	case "super":
		return Identifier{Name: "super"}

	case "as_expression":
		// Type assertion: ignore type, parse expression
		return p.parseExpression(node.Child(0))

	case "non_null_expression":
		// Non-null assertion: parse inner expression
		return p.parseExpression(node.Child(0))

	case "type_assertion":
		// <Type>expr -- parse the expression
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() != "type_arguments" && child.Type() != "<" && child.Type() != ">" {
				expr := p.parseExpression(child)
				if expr != nil {
					return expr
				}
			}
		}
		return nil

	default:
		return nil
	}
}

func (p *parseContext) parseBinaryExpression(node *sitter.Node) Expression {
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")
	opNode := node.ChildByFieldName("operator")

	if leftNode == nil || rightNode == nil {
		// Fallback: children by index
		if node.ChildCount() >= 3 {
			leftNode = node.Child(0)
			opNode = node.Child(1)
			rightNode = node.Child(2)
		}
	}

	if leftNode == nil || rightNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	left := p.parseExpression(leftNode)
	right := p.parseExpression(rightNode)
	if left == nil {
		left = BigIntLiteral{Value: big.NewInt(0)}
	}
	if right == nil {
		right = BigIntLiteral{Value: big.NewInt(0)}
	}

	op := ""
	if opNode != nil {
		op = p.nodeText(opNode)
	}

	// Map == to ===, != to !==
	if op == "==" {
		op = "==="
	}
	if op == "!=" {
		op = "!=="
	}

	return BinaryExpr{Op: op, Left: left, Right: right}
}

func (p *parseContext) parseUnaryExpression(node *sitter.Node) Expression {
	opNode := node.ChildByFieldName("operator")
	argNode := node.ChildByFieldName("argument")

	if opNode == nil || argNode == nil {
		// Fallback
		if node.ChildCount() >= 2 {
			opNode = node.Child(0)
			argNode = node.Child(1)
		}
	}

	if argNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	operand := p.parseExpression(argNode)
	if operand == nil {
		operand = BigIntLiteral{Value: big.NewInt(0)}
	}

	op := ""
	if opNode != nil {
		op = p.nodeText(opNode)
	}

	return UnaryExpr{Op: op, Operand: operand}
}

func (p *parseContext) parseUpdateExpression(node *sitter.Node) Expression {
	// update_expression: i++ or ++i or i-- or --i
	argNode := node.ChildByFieldName("argument")
	opNode := node.ChildByFieldName("operator")

	if argNode == nil {
		// Fallback: figure out prefix vs postfix by child order
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			text := p.nodeText(child)
			if text == "++" || text == "--" {
				opNode = child
			} else {
				argNode = child
			}
		}
	}

	if argNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	operand := p.parseExpression(argNode)
	if operand == nil {
		operand = BigIntLiteral{Value: big.NewInt(0)}
	}

	opText := ""
	if opNode != nil {
		opText = p.nodeText(opNode)
	}

	// Determine prefix vs postfix: if operator comes before argument
	prefix := false
	if opNode != nil {
		prefix = opNode.StartByte() < argNode.StartByte()
	}

	if opText == "++" {
		return IncrementExpr{Operand: operand, Prefix: prefix}
	}
	return DecrementExpr{Operand: operand, Prefix: prefix}
}

func (p *parseContext) parseCallExpression(node *sitter.Node) Expression {
	funcNode := node.ChildByFieldName("function")
	argsNode := node.ChildByFieldName("arguments")

	if funcNode == nil {
		// Fallback
		funcNode = node.Child(0)
	}

	if funcNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	// Special-case asm({ body, in_arity?, out_arity? }) — normalise the
	// object-literal argument into a CallExpr with three positional args
	// (body, in_arity, out_arity) so downstream passes only have to know
	// how to walk a CallExpr. Both the hex-string body form and the
	// array-form body are supported; the array form is encoded to a hex
	// string at parse time so all downstream passes see identical IR.
	// The optional generic type argument asm<T>(...) flags the
	// expression form, captured on CallExpr.AsmReturnType.
	if funcNode.Type() == "identifier" && p.nodeText(funcNode) == "asm" {
		return p.parseAsmCall(node, argsNode)
	}

	callee := p.parseExpression(funcNode)
	if callee == nil {
		callee = Identifier{Name: "unknown"}
	}

	var args []Expression
	if argsNode != nil {
		args = p.parseCallArgs(argsNode)
	}

	return CallExpr{Callee: callee, Args: args}
}

// parseAsmCall decodes an asm({ body, in_arity?, out_arity? }) call into a
// CallExpr whose positional args are
//
//	[ByteStringLiteral(body), BigIntLiteral(in_arity), BigIntLiteral(out_arity)].
//
// Two surface body shapes are accepted:
//   - Hex string literal:  body: '76a90088ac'
//   - Array of opcode names / push() calls:
//     body: [OP_DUP, OP_HASH160, push('1234abcd'), OP_EQUALVERIFY]
//     Each element is encoded to its byte representation at parse time,
//     so the resulting IR is byte-identical to the equivalent hex body.
//
// The optional generic type argument asm<T>({...}) marks the expression
// form; the captured T is stashed on CallExpr.AsmReturnType. T must be one
// of bigint, boolean, or ByteString.
//
// On malformed input we still return a syntactically valid CallExpr so
// later passes can produce additional diagnostics without crashing.
func (p *parseContext) parseAsmCall(callNode, argsNode *sitter.Node) Expression {
	calleeExpr := Identifier{Name: "asm"}

	// Capture the generic type argument asm<T>({...}) if present, BEFORE
	// arg-shape diagnostics so the expression form still records its
	// return type even when other args are malformed.
	asmReturnType := p.parseAsmGenericTypeArg(callNode)

	// Collect the call arguments (skip punctuation).
	var callArgs []*sitter.Node
	if argsNode != nil {
		for i := 0; i < int(argsNode.ChildCount()); i++ {
			child := argsNode.Child(i)
			t := child.Type()
			if t == "(" || t == ")" || t == "," {
				continue
			}
			callArgs = append(callArgs, child)
		}
	}

	if len(callArgs) != 1 {
		p.addError(fmt.Sprintf("asm() expects exactly one object-literal argument { body, in_arity?, out_arity? }, got %d arguments", len(callArgs)))
		return CallExpr{Callee: calleeExpr, Args: nil, AsmReturnType: asmReturnType}
	}

	objNode := callArgs[0]
	if objNode.Type() != "object" {
		p.addError(fmt.Sprintf("asm() argument must be an object literal { body: '<hex>', in_arity?: <int>, out_arity?: <int> }, got '%s'", objNode.Type()))
		return CallExpr{Callee: calleeExpr, Args: nil, AsmReturnType: asmReturnType}
	}

	var bodyExpr Expression
	var inArityExpr Expression
	var outArityExpr Expression

	for i := 0; i < int(objNode.ChildCount()); i++ {
		prop := objNode.Child(i)
		if prop.Type() != "pair" {
			continue
		}
		keyNode := prop.ChildByFieldName("key")
		valNode := prop.ChildByFieldName("value")
		if keyNode == nil || valNode == nil {
			continue
		}
		key := p.nodeText(keyNode)

		switch key {
		case "body":
			if valNode.Type() == "string" || valNode.Type() == "template_string" {
				raw := p.nodeText(valNode)
				if len(raw) >= 2 {
					raw = raw[1 : len(raw)-1]
				}
				bodyExpr = ByteStringLiteral{Value: raw}
			} else if valNode.Type() == "array" {
				encoded := p.encodeAsmArrayBody(valNode)
				bodyExpr = ByteStringLiteral{Value: encoded}
			} else {
				p.addError(fmt.Sprintf("asm() body must be a hex string literal or an array of opcode names / push() calls; got '%s'.", valNode.Type()))
				bodyExpr = ByteStringLiteral{Value: ""}
			}
		case "in_arity":
			if parsed, ok := p.parseArityLiteral(valNode, "in_arity"); ok {
				inArityExpr = BigIntLiteral{Value: big.NewInt(parsed)}
			}
		case "out_arity":
			if parsed, ok := p.parseArityLiteral(valNode, "out_arity"); ok {
				outArityExpr = BigIntLiteral{Value: big.NewInt(parsed)}
			}
		default:
			p.addError(fmt.Sprintf("asm() does not accept the '%s' field; valid fields are 'body', 'in_arity', 'out_arity'.", key))
		}
	}

	if bodyExpr == nil {
		p.addError("asm() requires a 'body' field with a hex string literal value")
		bodyExpr = ByteStringLiteral{Value: ""}
	}
	// Defaults: in_arity=0, out_arity=1. The out_arity=1 default reflects
	// the public-method-must-terminate-truthy invariant.
	if inArityExpr == nil {
		inArityExpr = BigIntLiteral{Value: big.NewInt(0)}
	}
	if outArityExpr == nil {
		outArityExpr = BigIntLiteral{Value: big.NewInt(1)}
	}

	return CallExpr{
		Callee:        calleeExpr,
		Args:          []Expression{bodyExpr, inArityExpr, outArityExpr},
		AsmReturnType: asmReturnType,
	}
}

// parseAsmGenericTypeArg parses the optional generic type argument on
// asm<T>({...}). Returns the captured primitive type name when present and
// valid, or "" if the call has no type argument. Pushes a diagnostic (and
// returns "") when the type argument is present but not a primitive value
// type (bigint / boolean / ByteString).
func (p *parseContext) parseAsmGenericTypeArg(callNode *sitter.Node) string {
	typeArgsNode := p.findChildByType(callNode, "type_arguments")
	if typeArgsNode == nil {
		return ""
	}
	var typeArgs []*sitter.Node
	for i := 0; i < int(typeArgsNode.ChildCount()); i++ {
		child := typeArgsNode.Child(i)
		t := child.Type()
		if t == "<" || t == ">" || t == "," {
			continue
		}
		typeArgs = append(typeArgs, child)
	}
	if len(typeArgs) == 0 {
		return ""
	}
	if len(typeArgs) > 1 {
		p.addError(fmt.Sprintf("asm<T>() takes at most one type argument, got %d", len(typeArgs)))
		return ""
	}
	text := strings.TrimSpace(p.nodeText(typeArgs[0]))
	if text == "bigint" || text == "boolean" || text == "ByteString" {
		return text
	}
	p.addError(fmt.Sprintf("asm<T>() return type must be 'bigint', 'boolean', or 'ByteString'; got '%s'", text))
	return ""
}

// encodeAsmArrayBody encodes an asm({ body: [OP_DUP, push(0x42), ...] })
// array literal to its hex byte representation. Uses the same push-encoding
// helpers as the emit pass so the resulting bytes are byte-identical to what
// the emitter would produce for the equivalent literal.
func (p *parseContext) encodeAsmArrayBody(arrayNode *sitter.Node) string {
	var hexStr string
	for i := 0; i < int(arrayNode.ChildCount()); i++ {
		elem := arrayNode.Child(i)
		t := elem.Type()
		if t == "[" || t == "]" || t == "," {
			continue
		}

		if t == "identifier" {
			name := p.nodeText(elem)
			b, ok := codegen.OpcodeByte(name)
			if !ok {
				p.addError(fmt.Sprintf("Unknown opcode '%s' in asm() body array. Expected an OP_* identifier (e.g. OP_DUP, OP_HASH160) or a push(...) call.", name))
				continue
			}
			hexStr += fmt.Sprintf("%02x", b)
			continue
		}

		if t == "call_expression" {
			calleeNode := elem.ChildByFieldName("function")
			if calleeNode == nil || calleeNode.Type() != "identifier" || p.nodeText(calleeNode) != "push" {
				calleeText := ""
				if calleeNode != nil {
					calleeText = p.nodeText(calleeNode)
				}
				p.addError(fmt.Sprintf("asm() body array call must be 'push(<literal>)', got '%s(...)'", calleeText))
				continue
			}
			pushArgsNode := elem.ChildByFieldName("arguments")
			var pushArgs []*sitter.Node
			if pushArgsNode != nil {
				for j := 0; j < int(pushArgsNode.ChildCount()); j++ {
					c := pushArgsNode.Child(j)
					ct := c.Type()
					if ct == "(" || ct == ")" || ct == "," {
						continue
					}
					pushArgs = append(pushArgs, c)
				}
			}
			if len(pushArgs) != 1 {
				p.addError(fmt.Sprintf("push() takes exactly one literal argument, got %d", len(pushArgs)))
				continue
			}
			if pushed, ok := p.encodeAsmPushLiteral(pushArgs[0]); ok {
				hexStr += pushed
			}
			continue
		}

		p.addError(fmt.Sprintf("asm() body array element must be an opcode identifier (e.g. OP_DUP) or a push(<literal>) call; got '%s'", t))
	}
	return hexStr
}

// encodeAsmPushLiteral encodes a literal argument passed to push(...) inside
// an asm() body array. Returns the encoded hex string and true, or "" and
// false if the literal is unrecognised (with a diagnostic pushed).
func (p *parseContext) encodeAsmPushLiteral(node *sitter.Node) (string, bool) {
	switch node.Type() {
	case "number":
		text := p.nodeText(node)
		numStr := text
		if strings.HasSuffix(numStr, "n") {
			numStr = numStr[:len(numStr)-1]
		}
		bi := new(big.Int)
		if _, ok := bi.SetString(numStr, 0); !ok {
			if _, ok2 := bi.SetString(numStr, 10); !ok2 {
				p.addError(fmt.Sprintf("push() argument is not a valid integer literal: '%s'", text))
				return "", false
			}
		}
		h, _ := codegen.EncodePushBigInt(bi)
		return h, true

	case "unary_expression":
		opNode := node.ChildByFieldName("operator")
		argNode := node.ChildByFieldName("argument")
		if opNode != nil && argNode != nil && p.nodeText(opNode) == "-" && argNode.Type() == "number" {
			text := p.nodeText(argNode)
			numStr := text
			if strings.HasSuffix(numStr, "n") {
				numStr = numStr[:len(numStr)-1]
			}
			bi := new(big.Int)
			if _, ok := bi.SetString(numStr, 0); !ok {
				if _, ok2 := bi.SetString(numStr, 10); !ok2 {
					p.addError(fmt.Sprintf("push() argument is not a valid integer literal: '%s'", text))
					return "", false
				}
			}
			bi.Neg(bi)
			h, _ := codegen.EncodePushBigInt(bi)
			return h, true
		}
		p.addError("push() argument must be a literal value (bigint, number, boolean, or hex string), got prefix expression")
		return "", false

	case "true":
		return "51", true // OP_TRUE
	case "false":
		return "00", true // OP_FALSE (alias of OP_0)

	case "string", "template_string":
		raw := p.nodeText(node)
		if len(raw) >= 2 {
			raw = raw[1 : len(raw)-1]
		}
		if len(raw)%2 != 0 || !isHexString(raw) {
			p.addError(fmt.Sprintf("push() ByteString argument must be even-length hex (got '%s')", raw))
			return "", false
		}
		bytes := make([]byte, len(raw)/2)
		for i := range bytes {
			v := new(big.Int)
			v.SetString(raw[i*2:i*2+2], 16)
			bytes[i] = byte(v.Int64())
		}
		return codegen.EncodePushBytesHex(bytes), true
	}

	p.addError(fmt.Sprintf("push() argument must be a literal value (bigint, number, boolean, or hex string), got '%s'", node.Type()))
	return "", false
}

// parseArityLiteral decodes a non-negative integer literal arity field for
// asm(). Returns the value and true, or 0 and false (with a diagnostic) on
// error.
func (p *parseContext) parseArityLiteral(node *sitter.Node, fieldName string) (int64, bool) {
	switch node.Type() {
	case "number":
		text := p.nodeText(node)
		numStr := text
		if strings.HasSuffix(numStr, "n") {
			numStr = numStr[:len(numStr)-1]
		}
		bi := new(big.Int)
		if _, ok := bi.SetString(numStr, 0); !ok {
			if _, ok2 := bi.SetString(numStr, 10); !ok2 {
				p.addError(fmt.Sprintf("asm() %s must be a non-negative integer literal, got '%s'", fieldName, text))
				return 0, false
			}
		}
		if bi.Sign() < 0 {
			p.addError(fmt.Sprintf("asm() %s must be a non-negative integer literal, got '%s'", fieldName, text))
			return 0, false
		}
		return bi.Int64(), true
	case "unary_expression":
		p.addError(fmt.Sprintf("asm() %s must be a non-negative integer literal", fieldName))
		return 0, false
	default:
		p.addError(fmt.Sprintf("asm() %s must be a non-negative integer literal, got '%s'", fieldName, node.Type()))
		return 0, false
	}
}

func (p *parseContext) parseCallArgs(node *sitter.Node) []Expression {
	var args []Expression
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		t := child.Type()
		if t == "(" || t == ")" || t == "," {
			continue
		}
		expr := p.parseExpression(child)
		if expr != nil {
			args = append(args, expr)
		}
	}
	return args
}

func (p *parseContext) parseMemberExpression(node *sitter.Node) Expression {
	objNode := node.ChildByFieldName("object")
	propNode := node.ChildByFieldName("property")

	if objNode == nil || propNode == nil {
		// Fallback
		if node.ChildCount() >= 3 {
			objNode = node.Child(0)
			propNode = node.Child(2) // skip the "."
		}
	}

	if objNode == nil || propNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	propName := p.nodeText(propNode)

	// this.x -> PropertyAccessExpr
	if objNode.Type() == "this" {
		return PropertyAccessExpr{Property: propName}
	}

	object := p.parseExpression(objNode)
	if object == nil {
		object = Identifier{Name: "unknown"}
	}

	return MemberExpr{Object: object, Property: propName}
}

func (p *parseContext) parseSubscriptExpression(node *sitter.Node) Expression {
	objNode := node.ChildByFieldName("object")
	indexNode := node.ChildByFieldName("index")

	if objNode == nil || indexNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	object := p.parseExpression(objNode)
	index := p.parseExpression(indexNode)
	if object == nil || index == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	return IndexAccessExpr{Object: object, Index: index}
}

func (p *parseContext) parseTernaryExpression(node *sitter.Node) Expression {
	condNode := node.ChildByFieldName("condition")
	consNode := node.ChildByFieldName("consequence")
	altNode := node.ChildByFieldName("alternative")

	if condNode == nil || consNode == nil || altNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	condition := p.parseExpression(condNode)
	consequent := p.parseExpression(consNode)
	alternate := p.parseExpression(altNode)

	if condition == nil || consequent == nil || alternate == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	return TernaryExpr{
		Condition:  condition,
		Consequent: consequent,
		Alternate:  alternate,
	}
}

func (p *parseContext) parseStringLiteral(node *sitter.Node) Expression {
	text := p.nodeText(node)
	// Remove quotes
	if len(text) >= 2 {
		text = text[1 : len(text)-1]
	}
	return ByteStringLiteral{Value: text}
}

func (p *parseContext) parseParenExpression(node *sitter.Node) Expression {
	// parenthesized_expression: "(" expression ")"
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "(" && child.Type() != ")" {
			return p.parseExpression(child)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (p *parseContext) findChildByType(node *sitter.Node, typeName string) *sitter.Node {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == typeName {
			return child
		}
	}
	return nil
}
