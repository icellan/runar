package frontend

import "fmt"

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ValidationResult holds the output of the validation pass.
type ValidationResult struct {
	Errors   []Diagnostic
	Warnings []Diagnostic
}

// ErrorStrings returns error messages as strings (for backward compatibility).
func (r *ValidationResult) ErrorStrings() []string {
	result := make([]string, len(r.Errors))
	for i, d := range r.Errors {
		result[i] = d.FormatMessage()
	}
	return result
}

// WarningStrings returns warning messages as strings (for backward compatibility).
func (r *ValidationResult) WarningStrings() []string {
	result := make([]string, len(r.Warnings))
	for i, d := range r.Warnings {
		result[i] = d.FormatMessage()
	}
	return result
}

// Validate checks the Rúnar AST against language subset constraints.
// It does NOT modify the AST; it only reports errors and warnings.
func Validate(contract *ContractNode) *ValidationResult {
	ctx := &validationContext{
		contract: contract,
	}

	if contract.Name == "" {
		ctx.addError("contract name must not be empty")
	}

	ctx.validateProperties()
	ctx.validateConstructor()
	ctx.validateMethods()
	ctx.checkNoRecursion()

	return &ValidationResult{
		Errors:   ctx.errors,
		Warnings: ctx.warnings,
	}
}

func (ctx *validationContext) addWarning(msg string) {
	ctx.warnings = append(ctx.warnings, Diagnostic{Message: msg, Severity: SeverityWarning})
}

func (ctx *validationContext) addWarningWithLoc(msg string, loc *SourceLocation) {
	ctx.warnings = append(ctx.warnings, Diagnostic{Message: msg, Severity: SeverityWarning, Loc: loc})
}

// ---------------------------------------------------------------------------
// Validation context
// ---------------------------------------------------------------------------

type validationContext struct {
	errors   []Diagnostic
	warnings []Diagnostic
	contract *ContractNode
}

func (ctx *validationContext) addError(msg string) {
	ctx.errors = append(ctx.errors, Diagnostic{Message: msg, Severity: SeverityError})
}

func (ctx *validationContext) addErrorWithLoc(msg string, loc *SourceLocation) {
	ctx.errors = append(ctx.errors, Diagnostic{Message: msg, Severity: SeverityError, Loc: loc})
}

// ---------------------------------------------------------------------------
// Property validation
// ---------------------------------------------------------------------------

var validPropTypes = map[string]bool{
	"bigint":         true,
	"boolean":        true,
	"ByteString":     true,
	"PubKey":         true,
	"Sig":            true,
	"Sha256":         true,
	"Ripemd160":      true,
	"Addr":           true,
	"SigHashPreimage": true,
	"RabinSig":       true,
	"RabinPubKey":    true,
	"Point":          true,
}

func (ctx *validationContext) validateProperties() {
	for _, prop := range ctx.contract.Properties {
		ctx.validatePropertyType(prop.Type, prop.SourceLocation)

		// txPreimage is an implicit property of StatefulSmartContract and must not be declared explicitly
		if ctx.contract.ParentClass == "StatefulSmartContract" && prop.Name == "txPreimage" {
			ctx.addErrorWithLoc("'txPreimage' is an implicit property of StatefulSmartContract and must not be declared", &prop.SourceLocation)
		}

		// Validate initializer if present. FixedArray properties accept an
		// array_literal of literal elements (recursively, for nested
		// arrays); other properties accept a plain literal value. This
		// mirrors the TS validator in `02-validate.ts`.
		if prop.Initializer != nil {
			if _, ok := prop.Type.(FixedArrayType); ok {
				if !isArrayLiteralOfLiterals(prop.Initializer) {
					ctx.addErrorWithLoc(
						fmt.Sprintf("property '%s' initializer must be an array literal of literal values", prop.Name),
						&prop.SourceLocation,
					)
				}
			} else if !isLiteralExpression(prop.Initializer) {
				ctx.addErrorWithLoc(
					fmt.Sprintf("property '%s' initializer must be a literal value", prop.Name),
					&prop.SourceLocation,
				)
			}
		}
	}

	// SmartContract requires all properties to be readonly
	if ctx.contract.ParentClass == "SmartContract" {
		for _, prop := range ctx.contract.Properties {
			if !prop.Readonly {
				ctx.addErrorWithLoc(fmt.Sprintf("property '%s' in SmartContract must be readonly. Use StatefulSmartContract for mutable state.", prop.Name), &prop.SourceLocation)
			}
		}
	}

	// Warn if StatefulSmartContract has no mutable properties
	if ctx.contract.ParentClass == "StatefulSmartContract" {
		hasMutable := false
		for _, prop := range ctx.contract.Properties {
			if !prop.Readonly {
				hasMutable = true
				break
			}
		}
		if !hasMutable {
			ctx.addWarningWithLoc("StatefulSmartContract has no mutable properties; consider using SmartContract instead", &ctx.contract.Constructor.SourceLocation)
		}
	}
}

// isLiteralExpression returns true if the expression is a literal
// allowed as a property initializer (bigint, bool, bytestring, or a
// negative bigint literal). Mirrors the TS validator helper.
func isLiteralExpression(expr Expression) bool {
	switch e := expr.(type) {
	case BigIntLiteral, BoolLiteral, ByteStringLiteral:
		return true
	case UnaryExpr:
		if e.Op == "-" {
			if _, ok := e.Operand.(BigIntLiteral); ok {
				return true
			}
		}
	}
	return false
}

// isArrayLiteralOfLiterals returns true if the expression is an array
// literal whose elements are all literal values (recursively, for
// nested FixedArray initializers). Mirrors the TS validator helper.
func isArrayLiteralOfLiterals(expr Expression) bool {
	arr, ok := expr.(ArrayLiteralExpr)
	if !ok {
		return false
	}
	for _, el := range arr.Elements {
		if _, isArr := el.(ArrayLiteralExpr); isArr {
			if !isArrayLiteralOfLiterals(el) {
				return false
			}
		} else if !isLiteralExpression(el) {
			return false
		}
	}
	return true
}

func (ctx *validationContext) validatePropertyType(t TypeNode, loc SourceLocation) {
	switch t := t.(type) {
	case PrimitiveType:
		if !validPropTypes[t.Name] {
			if t.Name == "void" {
				ctx.addErrorWithLoc(fmt.Sprintf("property type 'void' is not valid at %s:%d", loc.File, loc.Line), &loc)
			}
		}
	case FixedArrayType:
		if t.Length <= 0 {
			ctx.addErrorWithLoc(fmt.Sprintf("FixedArray length must be a positive integer at %s:%d", loc.File, loc.Line), &loc)
		}
		ctx.validatePropertyType(t.Element, loc)
	case CustomType:
		ctx.addErrorWithLoc(fmt.Sprintf("unsupported type '%s' in property declaration at %s:%d", t.Name, loc.File, loc.Line), &loc)
	}
}

// ---------------------------------------------------------------------------
// Constructor validation
// ---------------------------------------------------------------------------

func (ctx *validationContext) validateConstructor() {
	ctor := ctx.contract.Constructor
	propNames := make(map[string]bool)
	for _, p := range ctx.contract.Properties {
		propNames[p.Name] = true
	}

	// Check super() as first statement
	if len(ctor.Body) == 0 {
		ctx.addErrorWithLoc("constructor must call super() as its first statement", &ctor.SourceLocation)
		return
	}

	if !isSuperCall(ctor.Body[0]) {
		ctx.addErrorWithLoc("constructor must call super() as its first statement", &ctor.SourceLocation)
	}

	// Check all properties without initializers are assigned
	assignedProps := make(map[string]bool)
	for _, stmt := range ctor.Body {
		if assign, ok := stmt.(AssignmentStmt); ok {
			if pa, ok := assign.Target.(PropertyAccessExpr); ok {
				assignedProps[pa.Property] = true
			}
		}
	}
	// Properties with initializers don't need constructor assignments
	propsWithInit := make(map[string]bool)
	for _, prop := range ctx.contract.Properties {
		if prop.Initializer != nil {
			propsWithInit[prop.Name] = true
		}
	}
	for name := range propNames {
		if !assignedProps[name] && !propsWithInit[name] {
			ctx.addErrorWithLoc(fmt.Sprintf("property '%s' must be assigned in the constructor", name), &ctor.SourceLocation)
		}
	}

	// Reject FixedArray constructor params — arrays are only allowed as
	// contract properties.
	for _, param := range ctor.Params {
		if _, ok := param.Type.(FixedArrayType); ok {
			ctx.addErrorWithLoc(
				fmt.Sprintf("constructor parameter '%s' cannot be a FixedArray — use initialized properties or pass each element as a separate parameter", param.Name),
				&ctor.SourceLocation,
			)
		}
	}

	// Validate constructor body
	for _, stmt := range ctor.Body {
		ctx.validateStatement(stmt)
	}
}

func isSuperCall(stmt Statement) bool {
	es, ok := stmt.(ExpressionStmt)
	if !ok {
		return false
	}
	call, ok := es.Expr.(CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Callee.(Identifier)
	if !ok {
		return false
	}
	return id.Name == "super"
}

// ---------------------------------------------------------------------------
// Method validation
// ---------------------------------------------------------------------------

func (ctx *validationContext) validateMethods() {
	for _, method := range ctx.contract.Methods {
		ctx.validateMethod(method)
	}
}

func (ctx *validationContext) validateMethod(method MethodNode) {
	// Reject FixedArray method params — arrays are only allowed as
	// contract properties.
	for _, param := range method.Params {
		if _, ok := param.Type.(FixedArrayType); ok {
			ctx.addErrorWithLoc(
				fmt.Sprintf("parameter '%s' in method '%s' cannot be a FixedArray — arrays are only allowed as contract properties", param.Name, method.Name),
				&method.SourceLocation,
			)
		}
	}

	// Public methods must end with assert() (unless StatefulSmartContract,
	// where the compiler auto-injects the final assert)
	if method.Visibility == "public" && ctx.contract.ParentClass != "StatefulSmartContract" {
		if !endsWithAssert(method.Body) {
			ctx.addErrorWithLoc(fmt.Sprintf("public method '%s' must end with an assert() call", method.Name), &method.SourceLocation)
		}
	}

	// Warn on manual preimage boilerplate in StatefulSmartContract public methods
	if ctx.contract.ParentClass == "StatefulSmartContract" && method.Visibility == "public" {
		ctx.warnManualPreimageUsage(method)
	}

	// Validate statements
	for _, stmt := range method.Body {
		ctx.validateStatement(stmt)
	}
}

func endsWithAssert(body []Statement) bool {
	if len(body) == 0 {
		return false
	}
	last := body[len(body)-1]

	if es, ok := last.(ExpressionStmt); ok {
		return isAssertCall(es.Expr)
	}

	if ifStmt, ok := last.(IfStmt); ok {
		thenEnds := endsWithAssert(ifStmt.Then)
		elseEnds := len(ifStmt.Else) > 0 && endsWithAssert(ifStmt.Else)
		return thenEnds && elseEnds
	}

	return false
}

func isAssertCall(expr Expression) bool {
	call, ok := expr.(CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Callee.(Identifier)
	if !ok {
		return false
	}
	return id.Name == "assert"
}

// ---------------------------------------------------------------------------
// Statement validation
// ---------------------------------------------------------------------------

func (ctx *validationContext) validateStatement(stmt Statement) {
	switch s := stmt.(type) {
	case VariableDeclStmt:
		if s.Type != nil {
			if _, ok := s.Type.(FixedArrayType); ok {
				ctx.addErrorWithLoc(
					fmt.Sprintf("local variable '%s' cannot be a FixedArray — arrays are only allowed as contract properties", s.Name),
					&s.SourceLocation,
				)
			}
		}
		ctx.validateExpression(s.Init)
	case AssignmentStmt:
		ctx.validateExpression(s.Target)
		ctx.validateExpression(s.Value)
	case IfStmt:
		ctx.validateExpression(s.Condition)
		for _, st := range s.Then {
			ctx.validateStatement(st)
		}
		for _, st := range s.Else {
			ctx.validateStatement(st)
		}
	case ForStmt:
		ctx.validateForStatement(s)
	case ExpressionStmt:
		ctx.validateExpression(s.Expr)
	case ReturnStmt:
		if s.Value != nil {
			ctx.validateExpression(s.Value)
		}
	}
}

func (ctx *validationContext) validateForStatement(stmt ForStmt) {
	ctx.validateExpression(stmt.Condition)

	// Check constant bounds
	if bin, ok := stmt.Condition.(BinaryExpr); ok {
		if !isCompileTimeConstant(bin.Right) {
			ctx.addError("for loop bound must be a compile-time constant")
		}
	}

	ctx.validateExpression(stmt.Init.Init)
	for _, s := range stmt.Body {
		ctx.validateStatement(s)
	}
}

func isCompileTimeConstant(expr Expression) bool {
	switch e := expr.(type) {
	case BigIntLiteral:
		return true
	case BoolLiteral:
		return true
	case Identifier:
		return true // trust it's a const
	case UnaryExpr:
		if e.Op == "-" {
			return isCompileTimeConstant(e.Operand)
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Expression validation
// ---------------------------------------------------------------------------

func (ctx *validationContext) validateExpression(expr Expression) {
	switch e := expr.(type) {
	case BinaryExpr:
		ctx.validateExpression(e.Left)
		ctx.validateExpression(e.Right)
	case UnaryExpr:
		ctx.validateExpression(e.Operand)
	case CallExpr:
		ctx.validateExpression(e.Callee)
		// assert() message (2nd arg) is a human-readable string, not hex — skip validation
		isAssertExpr := false
		if id, ok := e.Callee.(Identifier); ok && id.Name == "assert" {
			isAssertExpr = true
		}
		for i, arg := range e.Args {
			if isAssertExpr && i >= 1 {
				continue
			}
			ctx.validateExpression(arg)
		}
	case MemberExpr:
		ctx.validateExpression(e.Object)
	case TernaryExpr:
		ctx.validateExpression(e.Condition)
		ctx.validateExpression(e.Consequent)
		ctx.validateExpression(e.Alternate)
	case IndexAccessExpr:
		ctx.validateExpression(e.Object)
		ctx.validateExpression(e.Index)
	case IncrementExpr:
		ctx.validateExpression(e.Operand)
	case DecrementExpr:
		ctx.validateExpression(e.Operand)
	case ByteStringLiteral:
		val := e.Value
		if len(val) > 0 {
			if len(val)%2 != 0 {
				ctx.addError(fmt.Sprintf("ByteString literal '%s' has odd length (%d) — hex strings must have an even number of characters", val, len(val)))
			} else if !isHexString(val) {
				ctx.addError(fmt.Sprintf("ByteString literal '%s' contains non-hex characters — only 0-9, a-f, A-F are allowed", val))
			}
		}
	}
}

// isHexString returns true if s contains only hexadecimal characters.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// StatefulSmartContract: warn on manual preimage boilerplate
// ---------------------------------------------------------------------------

func (ctx *validationContext) warnManualPreimageUsage(method MethodNode) {
	walkExpressionsInBody(method.Body, func(expr Expression) {
		// Detect manual checkPreimage(...)
		if call, ok := expr.(CallExpr); ok {
			if id, ok := call.Callee.(Identifier); ok && id.Name == "checkPreimage" {
				ctx.addWarningWithLoc(fmt.Sprintf("StatefulSmartContract auto-injects checkPreimage(); calling it manually in '%s' will cause a duplicate verification", method.Name), &method.SourceLocation)
			}
			// Detect manual this.getStateScript()
			if pa, ok := call.Callee.(PropertyAccessExpr); ok && pa.Property == "getStateScript" {
				ctx.addWarningWithLoc(fmt.Sprintf("StatefulSmartContract auto-injects state continuation; calling getStateScript() manually in '%s' is redundant", method.Name), &method.SourceLocation)
			}
		}
	})
}

func walkExpressionsInBody(stmts []Statement, visitor func(Expression)) {
	for _, stmt := range stmts {
		walkExpressionsInStatement(stmt, visitor)
	}
}

func walkExpressionsInStatement(stmt Statement, visitor func(Expression)) {
	switch s := stmt.(type) {
	case ExpressionStmt:
		walkExpr(s.Expr, visitor)
	case VariableDeclStmt:
		walkExpr(s.Init, visitor)
	case AssignmentStmt:
		walkExpr(s.Target, visitor)
		walkExpr(s.Value, visitor)
	case IfStmt:
		walkExpr(s.Condition, visitor)
		walkExpressionsInBody(s.Then, visitor)
		walkExpressionsInBody(s.Else, visitor)
	case ForStmt:
		walkExpr(s.Condition, visitor)
		walkExpressionsInBody(s.Body, visitor)
	case ReturnStmt:
		if s.Value != nil {
			walkExpr(s.Value, visitor)
		}
	}
}

func walkExpr(expr Expression, visitor func(Expression)) {
	visitor(expr)
	switch e := expr.(type) {
	case BinaryExpr:
		walkExpr(e.Left, visitor)
		walkExpr(e.Right, visitor)
	case UnaryExpr:
		walkExpr(e.Operand, visitor)
	case CallExpr:
		walkExpr(e.Callee, visitor)
		for _, arg := range e.Args {
			walkExpr(arg, visitor)
		}
	case MemberExpr:
		walkExpr(e.Object, visitor)
	case TernaryExpr:
		walkExpr(e.Condition, visitor)
		walkExpr(e.Consequent, visitor)
		walkExpr(e.Alternate, visitor)
	case IndexAccessExpr:
		walkExpr(e.Object, visitor)
		walkExpr(e.Index, visitor)
	case IncrementExpr:
		walkExpr(e.Operand, visitor)
	case DecrementExpr:
		walkExpr(e.Operand, visitor)
	}
}

// ---------------------------------------------------------------------------
// Recursion detection
// ---------------------------------------------------------------------------

func (ctx *validationContext) checkNoRecursion() {
	callGraph := make(map[string]map[string]bool)
	methodNames := make(map[string]bool)

	for _, method := range ctx.contract.Methods {
		methodNames[method.Name] = true
		calls := make(map[string]bool)
		collectMethodCalls(method.Body, calls)
		callGraph[method.Name] = calls
	}

	// Check for cycles using DFS
	for _, method := range ctx.contract.Methods {
		visited := make(map[string]bool)
		stack := make(map[string]bool)
		if hasCycle(method.Name, callGraph, methodNames, visited, stack) {
			ctx.addErrorWithLoc(fmt.Sprintf("recursion detected: method '%s' calls itself directly or indirectly", method.Name), &method.SourceLocation)
		}
	}
}

func collectMethodCalls(stmts []Statement, calls map[string]bool) {
	for _, stmt := range stmts {
		collectMethodCallsInStmt(stmt, calls)
	}
}

func collectMethodCallsInStmt(stmt Statement, calls map[string]bool) {
	switch s := stmt.(type) {
	case ExpressionStmt:
		collectMethodCallsInExpr(s.Expr, calls)
	case VariableDeclStmt:
		collectMethodCallsInExpr(s.Init, calls)
	case AssignmentStmt:
		collectMethodCallsInExpr(s.Target, calls)
		collectMethodCallsInExpr(s.Value, calls)
	case IfStmt:
		collectMethodCallsInExpr(s.Condition, calls)
		collectMethodCalls(s.Then, calls)
		collectMethodCalls(s.Else, calls)
	case ForStmt:
		collectMethodCallsInExpr(s.Condition, calls)
		collectMethodCalls(s.Body, calls)
	case ReturnStmt:
		if s.Value != nil {
			collectMethodCallsInExpr(s.Value, calls)
		}
	}
}

func collectMethodCallsInExpr(expr Expression, calls map[string]bool) {
	switch e := expr.(type) {
	case CallExpr:
		if pa, ok := e.Callee.(PropertyAccessExpr); ok {
			calls[pa.Property] = true
		}
		if me, ok := e.Callee.(MemberExpr); ok {
			if id, ok := me.Object.(Identifier); ok && id.Name == "this" {
				calls[me.Property] = true
			}
		}
		collectMethodCallsInExpr(e.Callee, calls)
		for _, arg := range e.Args {
			collectMethodCallsInExpr(arg, calls)
		}
	case BinaryExpr:
		collectMethodCallsInExpr(e.Left, calls)
		collectMethodCallsInExpr(e.Right, calls)
	case UnaryExpr:
		collectMethodCallsInExpr(e.Operand, calls)
	case MemberExpr:
		collectMethodCallsInExpr(e.Object, calls)
	case TernaryExpr:
		collectMethodCallsInExpr(e.Condition, calls)
		collectMethodCallsInExpr(e.Consequent, calls)
		collectMethodCallsInExpr(e.Alternate, calls)
	case IndexAccessExpr:
		collectMethodCallsInExpr(e.Object, calls)
		collectMethodCallsInExpr(e.Index, calls)
	case IncrementExpr:
		collectMethodCallsInExpr(e.Operand, calls)
	case DecrementExpr:
		collectMethodCallsInExpr(e.Operand, calls)
	}
}

func hasCycle(name string, callGraph map[string]map[string]bool, methodNames map[string]bool, visited, stack map[string]bool) bool {
	if stack[name] {
		return true
	}
	if visited[name] {
		return false
	}
	visited[name] = true
	stack[name] = true

	for callee := range callGraph[name] {
		if methodNames[callee] {
			if hasCycle(callee, callGraph, methodNames, visited, stack) {
				return true
			}
		}
	}

	delete(stack, name)
	return false
}
