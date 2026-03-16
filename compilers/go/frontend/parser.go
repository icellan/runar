package frontend

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParseResult holds the result of parsing a Rúnar source file.
type ParseResult struct {
	Contract *ContractNode
	Errors   []string
}

// ParseSource detects the file extension and routes to the appropriate parser.
//   - .runar.sol -> ParseSolidity
//   - .runar.move -> ParseMove
//   - .runar.go -> ParseGoContract
//   - .runar.py -> ParsePython
//   - .runar.rs -> ParseRustMacro
//   - .runar.rb -> ParseRuby
//   - default -> Parse (existing TypeScript parser)
func ParseSource(source []byte, fileName string) *ParseResult {
	lower := strings.ToLower(fileName)
	switch {
	case strings.HasSuffix(lower, ".runar.sol"):
		return ParseSolidity(source, fileName)
	case strings.HasSuffix(lower, ".runar.move"):
		return ParseMove(source, fileName)
	case strings.HasSuffix(lower, ".runar.go"):
		return ParseGoContract(source, fileName)
	case strings.HasSuffix(lower, ".runar.py"):
		return ParsePython(source, fileName)
	case strings.HasSuffix(lower, ".runar.rs"):
		return ParseRustMacro(source, fileName)
	case strings.HasSuffix(lower, ".runar.rb"):
		return ParseRuby(source, fileName)
	default:
		return Parse(source, fileName)
	}
}

// Parse parses a TypeScript source string and extracts the Rúnar contract AST.
func Parse(source []byte, fileName string) *ParseResult {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())

	tree, err := parser.ParseCtx(context.Background(), nil, source)
	if err != nil {
		return &ParseResult{Errors: []string{fmt.Sprintf("parse error: %v", err)}}
	}

	root := tree.RootNode()
	p := &parseContext{
		source:   source,
		fileName: fileName,
	}

	contract := p.findContract(root)
	if contract == nil {
		return &ParseResult{Errors: append(p.errors, "no class extending SmartContract or StatefulSmartContract found")}
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
	errors   []string
}

func (p *parseContext) addError(msg string) {
	p.errors = append(p.errors, msg)
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

	// The heritage clause should contain "SmartContract" or "StatefulSmartContract"
	heritageText := p.nodeText(heritage)
	parentClass := ""
	if strings.Contains(heritageText, "StatefulSmartContract") {
		parentClass = "StatefulSmartContract"
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

	return &PropertyNode{
		Name:           nameStr,
		Type:           typeNode,
		Readonly:       isReadonly,
		Initializer:    initializer,
		SourceLocation: p.loc(node),
	}
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

	return MethodNode{
		Name:           name,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SourceLocation: p.loc(node),
	}
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

	for i := 0; i < int(declarator.ChildCount()); i++ {
		child := declarator.Child(i)
		switch child.Type() {
		case "identifier":
			name = p.nodeText(child)
		case "type_annotation":
			typeNode = p.parseTypeAnnotation(child)
		default:
			if child.Type() != "=" && child.Type() != ";" && child.Type() != ":" {
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
		initExpr = BigIntLiteral{Value: 0}
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
					Init:           BigIntLiteral{Value: 0},
					SourceLocation: loc,
				}
			}
		}
	} else {
		initStmt = VariableDeclStmt{
			Name:           "_i",
			Mutable:        true,
			Init:           BigIntLiteral{Value: 0},
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
		update = ExpressionStmt{Expr: BigIntLiteral{Value: 0}, SourceLocation: loc}
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
		return ExpressionStmt{Expr: BigIntLiteral{Value: 0}, SourceLocation: loc}
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
		// Parse with big.Int to avoid silent truncation of values > 2^63-1.
		// Fall back to strconv.ParseInt for hex/octal/binary prefix support,
		// then validate the result fits in int64.
		bi := new(big.Int)
		if _, ok := bi.SetString(text, 0); !ok {
			// Retry without base prefix detection for edge cases
			val, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				p.addError(fmt.Sprintf("invalid integer literal: %s", text))
				return BigIntLiteral{Value: 0}
			}
			return BigIntLiteral{Value: val}
		}
		if !bi.IsInt64() {
			p.addError(fmt.Sprintf("integer literal %s overflows int64", text))
			return BigIntLiteral{Value: 0}
		}
		return BigIntLiteral{Value: bi.Int64()}

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
		return BigIntLiteral{Value: 0}
	}

	left := p.parseExpression(leftNode)
	right := p.parseExpression(rightNode)
	if left == nil {
		left = BigIntLiteral{Value: 0}
	}
	if right == nil {
		right = BigIntLiteral{Value: 0}
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
		return BigIntLiteral{Value: 0}
	}

	operand := p.parseExpression(argNode)
	if operand == nil {
		operand = BigIntLiteral{Value: 0}
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
		return BigIntLiteral{Value: 0}
	}

	operand := p.parseExpression(argNode)
	if operand == nil {
		operand = BigIntLiteral{Value: 0}
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
		return BigIntLiteral{Value: 0}
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
		return BigIntLiteral{Value: 0}
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
		return BigIntLiteral{Value: 0}
	}

	object := p.parseExpression(objNode)
	index := p.parseExpression(indexNode)
	if object == nil || index == nil {
		return BigIntLiteral{Value: 0}
	}

	return IndexAccessExpr{Object: object, Index: index}
}

func (p *parseContext) parseTernaryExpression(node *sitter.Node) Expression {
	condNode := node.ChildByFieldName("condition")
	consNode := node.ChildByFieldName("consequence")
	altNode := node.ChildByFieldName("alternative")

	if condNode == nil || consNode == nil || altNode == nil {
		return BigIntLiteral{Value: 0}
	}

	condition := p.parseExpression(condNode)
	consequent := p.parseExpression(consNode)
	alternate := p.parseExpression(altNode)

	if condition == nil || consequent == nil || alternate == nil {
		return BigIntLiteral{Value: 0}
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
