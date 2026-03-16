package frontend

import "fmt"

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ValidationResult holds the output of the validation pass.
type ValidationResult struct {
	Errors   []string
	Warnings []string
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
	ctx.warnings = append(ctx.warnings, msg)
}

// ---------------------------------------------------------------------------
// Validation context
// ---------------------------------------------------------------------------

type validationContext struct {
	errors   []string
	warnings []string
	contract *ContractNode
}

func (ctx *validationContext) addError(msg string) {
	ctx.errors = append(ctx.errors, msg)
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
			ctx.addError("'txPreimage' is an implicit property of StatefulSmartContract and must not be declared")
		}
	}

	// SmartContract requires all properties to be readonly
	if ctx.contract.ParentClass == "SmartContract" {
		for _, prop := range ctx.contract.Properties {
			if !prop.Readonly {
				ctx.addError(fmt.Sprintf("property '%s' in SmartContract must be readonly. Use StatefulSmartContract for mutable state.", prop.Name))
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
			ctx.addWarning("StatefulSmartContract has no mutable properties; consider using SmartContract instead")
		}
	}
}

func (ctx *validationContext) validatePropertyType(t TypeNode, loc SourceLocation) {
	switch t := t.(type) {
	case PrimitiveType:
		if !validPropTypes[t.Name] {
			if t.Name == "void" {
				ctx.addError(fmt.Sprintf("property type 'void' is not valid at %s:%d", loc.File, loc.Line))
			}
		}
	case FixedArrayType:
		if t.Length <= 0 {
			ctx.addError(fmt.Sprintf("FixedArray length must be a positive integer at %s:%d", loc.File, loc.Line))
		}
		ctx.validatePropertyType(t.Element, loc)
	case CustomType:
		ctx.addError(fmt.Sprintf("unsupported type '%s' in property declaration at %s:%d", t.Name, loc.File, loc.Line))
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
		ctx.addError("constructor must call super() as its first statement")
		return
	}

	if !isSuperCall(ctor.Body[0]) {
		ctx.addError("constructor must call super() as its first statement")
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
			ctx.addError(fmt.Sprintf("property '%s' must be assigned in the constructor", name))
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
	// Public methods must end with assert() (unless StatefulSmartContract,
	// where the compiler auto-injects the final assert)
	if method.Visibility == "public" && ctx.contract.ParentClass != "StatefulSmartContract" {
		if !endsWithAssert(method.Body) {
			ctx.addError(fmt.Sprintf("public method '%s' must end with an assert() call", method.Name))
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
		for _, arg := range e.Args {
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
	}
}

// ---------------------------------------------------------------------------
// StatefulSmartContract: warn on manual preimage boilerplate
// ---------------------------------------------------------------------------

func (ctx *validationContext) warnManualPreimageUsage(method MethodNode) {
	walkExpressionsInBody(method.Body, func(expr Expression) {
		// Detect manual checkPreimage(...)
		if call, ok := expr.(CallExpr); ok {
			if id, ok := call.Callee.(Identifier); ok && id.Name == "checkPreimage" {
				ctx.addWarning(fmt.Sprintf("StatefulSmartContract auto-injects checkPreimage(); calling it manually in '%s' will cause a duplicate verification", method.Name))
			}
			// Detect manual this.getStateScript()
			if pa, ok := call.Callee.(PropertyAccessExpr); ok && pa.Property == "getStateScript" {
				ctx.addWarning(fmt.Sprintf("StatefulSmartContract auto-injects state continuation; calling getStateScript() manually in '%s' is redundant", method.Name))
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
			ctx.addError(fmt.Sprintf("recursion detected: method '%s' calls itself directly or indirectly", method.Name))
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
