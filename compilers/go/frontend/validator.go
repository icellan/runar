package frontend

import (
	"fmt"
	"math/big"
)

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

	// Issue #123: reject preimage-field reads / output bindings that are
	// unsound under a method's declared @sighash mode (security core). This
	// pass emits both errors (unsound usages) and warnings (e.g. an explicit
	// single-output SINGLE covenant whose same-index value cannot be pinned
	// statically), so route each diagnostic to the matching bucket.
	for _, d := range ValidateSighashUsage(contract) {
		if d.Severity == SeverityWarning {
			ctx.warnings = append(ctx.warnings, d)
		} else {
			ctx.errors = append(ctx.errors, d)
		}
	}

	// See sp1_fri_soundness_warning.go: the deployable SP1 FRI verifier accepts
	// forged Merkle openings at the PoC parameter set. Say so at compile time,
	// not only in a doc a caller of the built-in would never open.
	if contractCallsSP1FriVerifier(contract) {
		if contract.AckUnsoundSP1Fri {
			// Explicitly opted in (verifier development / the PoC contract):
			// still say it, loudly, on every compile.
			ctx.addWarning(sp1FriSoundnessWarning)
		} else {
			// Default: REFUSE. Documenting an unsound verifier is not the same
			// as preventing its deployment, and this one accepts forged proofs.
			ctx.addError(sp1FriSoundnessError)
		}
	}

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
	"P256Point":      true,
	"P384Point":      true,
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

	// SmartContract (and the asm-escape-hatch UnsafeSmartContract) require
	// all properties to be readonly.
	if ctx.contract.ParentClass == "SmartContract" || ctx.contract.ParentClass == "UnsafeSmartContract" {
		for _, prop := range ctx.contract.Properties {
			if !prop.Readonly {
				ctx.addErrorWithLoc(fmt.Sprintf("property '%s' in %s must be readonly. Use StatefulSmartContract for mutable state.", prop.Name, ctx.contract.ParentClass), &prop.SourceLocation)
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
	// A contract with no public methods has no spending entry points and
	// compiles to an empty script — never what the author meant (usually a
	// missing `public` modifier; methods default to private).
	hasPublic := false
	for _, method := range ctx.contract.Methods {
		if method.Visibility == "public" {
			hasPublic = true
			break
		}
	}
	if !hasPublic {
		ctx.addError(fmt.Sprintf("Contract '%s' has no public methods — no spending entry points; add 'public' to at least one method", ctx.contract.Name))
	}

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

	// Public methods must end with an assert() call (unless
	// StatefulSmartContract, where the compiler auto-injects the final
	// assert; or UnsafeSmartContract, where a terminal asm({..., out_arity:
	// 1}) provides the truthy stack value).
	if method.Visibility == "public" && ctx.contract.ParentClass == "SmartContract" {
		if !endsWithAssert(method.Body) {
			ctx.addErrorWithLoc(fmt.Sprintf("public method '%s' must end with an assert() call", method.Name), &method.SourceLocation)
		}
	}

	// UnsafeSmartContract public methods must end with either an assert()
	// call or a terminal asm({..., out_arity: 1}) — either way the script
	// has to leave a truthy value on the stack.
	if method.Visibility == "public" && ctx.contract.ParentClass == "UnsafeSmartContract" {
		if !endsWithAssert(method.Body) && !endsWithTerminalAsm(method.Body) {
			ctx.addErrorWithLoc(fmt.Sprintf("public method '%s' must end with an assert() call or a terminal asm({...}) with out_arity 1", method.Name), &method.SourceLocation)
		}
	}

	// Warn on manual preimage boilerplate in StatefulSmartContract public methods
	if ctx.contract.ParentClass == "StatefulSmartContract" && method.Visibility == "public" {
		ctx.warnManualPreimageUsage(method)
	}

	// #131: warn when a public method gates on extractLocktime but never asserts
	// the spending tx is non-final (extractSequence < 0xffffffff). Advisory only.
	if method.Visibility == "public" {
		ctx.warnLocktimeWithoutSequenceGuard(method)
	}

	// Gate asm({...}) calls on UnsafeSmartContract and check the structural args.
	ctx.validateAsmUsage(method)

	// readonly properties may only be assigned in the constructor.
	ctx.checkReadonlyWrites(method)

	// Validate statements
	for _, stmt := range method.Body {
		ctx.validateStatement(stmt)
	}
}

// checkReadonlyWrites reports every write to a readonly contract property in
// a method body.
//
// spec/semantics.md:
//
//	<this.p = e, env, sigma> ==> ERROR: cannot assign to readonly property
//
// The constructor is exempt — that is where every contract initialises its
// readonly properties — so this runs per METHOD only (validateConstructor
// never calls in here).
//
// Three AST shapes reach update_prop in ANF lowering and are all covered:
// `this.p = e`, `this.p++` / `this.p--`, and `this.arr[i] = e`.
func (ctx *validationContext) checkReadonlyWrites(method MethodNode) {
	readonly := make(map[string]bool)
	for _, prop := range ctx.contract.Properties {
		if prop.Readonly {
			readonly[prop.Name] = true
		}
	}
	if len(readonly) == 0 {
		return
	}

	report := func(name string, loc SourceLocation) {
		ctx.addErrorWithLoc(fmt.Sprintf(
			"cannot assign to readonly property '%s' in method '%s'. readonly properties may only be assigned in the constructor.",
			name, method.Name,
		), &loc)
	}

	var visitStatements func(stmts []Statement)
	visitExpr := func(expr Expression, loc SourceLocation) {
		if expr == nil {
			return
		}
		walkExpr(expr, func(e Expression) {
			var operand Expression
			switch v := e.(type) {
			case IncrementExpr:
				operand = v.Operand
			case DecrementExpr:
				operand = v.Operand
			default:
				return
			}
			if name, ok := writtenProperty(operand); ok && readonly[name] {
				report(name, loc)
			}
		})
	}

	visitStatements = func(stmts []Statement) {
		for _, stmt := range stmts {
			switch s := stmt.(type) {
			case AssignmentStmt:
				if name, ok := writtenProperty(s.Target); ok && readonly[name] {
					report(name, s.SourceLocation)
				}
				visitExpr(s.Target, s.SourceLocation)
				visitExpr(s.Value, s.SourceLocation)
			case VariableDeclStmt:
				visitExpr(s.Init, s.SourceLocation)
			case ExpressionStmt:
				visitExpr(s.Expr, s.SourceLocation)
			case ReturnStmt:
				visitExpr(s.Value, s.SourceLocation)
			case IfStmt:
				visitExpr(s.Condition, s.SourceLocation)
				visitStatements(s.Then)
				visitStatements(s.Else)
			case ForStmt:
				visitStatements([]Statement{s.Init, s.Update})
				visitExpr(s.Condition, s.SourceLocation)
				visitStatements(s.Body)
			}
		}
	}

	visitStatements(method.Body)
}

// writtenProperty resolves the contract property an assignment target writes
// to. Unwraps IndexAccessExpr chains so `this.grid[i][j] = v` resolves to
// `grid`.
func writtenProperty(target Expression) (string, bool) {
	node := target
	for {
		idx, ok := node.(IndexAccessExpr)
		if !ok {
			break
		}
		node = idx.Object
	}
	pa, ok := node.(PropertyAccessExpr)
	if !ok {
		return "", false
	}
	return pa.Property, true
}

// isAsmCall reports whether expr is a call to the asm compiler intrinsic.
func isAsmCall(expr Expression) bool {
	call, ok := expr.(CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Callee.(Identifier)
	return ok && id.Name == "asm"
}

// endsWithTerminalAsm reports whether the last statement of body is an
// asm({...}) call with the parser-normalised positional args
// (body, in_arity, out_arity) and an out_arity literal equal to 1.
//
// If/else branches that both terminate in a terminal asm (or assert) also
// count, mirroring the asserts-on-both-branches rule.
func endsWithTerminalAsm(body []Statement) bool {
	if len(body) == 0 {
		return false
	}
	last := body[len(body)-1]

	if es, ok := last.(ExpressionStmt); ok {
		if !isAsmCall(es.Expr) {
			return false
		}
		call := es.Expr.(CallExpr)
		// The parser always rewrites asm({...}) into positional
		// (body, in_arity, out_arity).
		if len(call.Args) == 3 {
			if outArity, ok := call.Args[2].(BigIntLiteral); ok &&
				outArity.Value != nil && outArity.Value.Cmp(big.NewInt(1)) == 0 {
				return true
			}
		}
		return false
	}

	if ifStmt, ok := last.(IfStmt); ok {
		thenEnds := endsWithTerminalAsm(ifStmt.Then) || endsWithAssert(ifStmt.Then)
		elseEnds := len(ifStmt.Else) > 0 &&
			(endsWithTerminalAsm(ifStmt.Else) || endsWithAssert(ifStmt.Else))
		return thenEnds && elseEnds
	}

	return false
}

// validateAsmUsage walks a method body and validates every asm({...}) call:
//
//   - Reject any asm() outside an UnsafeSmartContract.
//   - Confirm the parser-normalised arg shape: (body, in_arity, out_arity)
//     where body is a ByteString literal with even-length hex and the
//     arities are non-negative bigint literals.
//   - Expression-form asm<T>({...}) must have out_arity 1.
//
// The parser already pushes most hex diagnostics; this pass is the back-stop
// that runs even when the parser shape is well-formed and is the only layer
// that knows about the contract's parentClass.
func (ctx *validationContext) validateAsmUsage(method MethodNode) {
	walkExpressionsInBody(method.Body, func(expr Expression) {
		if !isAsmCall(expr) {
			return
		}
		call := expr.(CallExpr)

		if ctx.contract.ParentClass != "UnsafeSmartContract" {
			ctx.addError(fmt.Sprintf("'asm' is only available in contracts extending UnsafeSmartContract; got %s. Move the call into a class that extends UnsafeSmartContract (and import { UnsafeSmartContract } from 'runar-lang').", ctx.contract.ParentClass))
			return
		}

		if len(call.Args) != 3 {
			ctx.addError("asm() expects exactly one object-literal argument { body, in_arity?, out_arity? }")
			return
		}

		bodyArg, bodyOk := call.Args[0].(ByteStringLiteral)
		if !bodyOk {
			ctx.addError("asm() body must be a hex string literal")
			return
		}
		body := bodyArg.Value
		if len(body) == 0 {
			ctx.addError("asm() body must be a non-empty hex string literal")
		} else if len(body)%2 != 0 {
			ctx.addError(fmt.Sprintf("asm() body has odd hex length (%d); each opcode byte requires two hex characters", len(body)))
		} else if !isHexString(body) {
			ctx.addError("asm() body contains non-hex characters; only 0-9, a-f, A-F are allowed")
		}

		inArity, inOk := call.Args[1].(BigIntLiteral)
		if !inOk || inArity.Value == nil || inArity.Value.Sign() < 0 {
			ctx.addError("asm() in_arity must be a non-negative integer literal")
		}

		outArity, outOk := call.Args[2].(BigIntLiteral)
		if !outOk || outArity.Value == nil || outArity.Value.Sign() < 0 {
			ctx.addError("asm() out_arity must be a non-negative integer literal")
		}

		// Expression-form asm<T>({...}) returns a value that flows into a
		// let-binding — exactly ONE stack value, so out_arity must be 1.
		if call.AsmReturnType != "" && outOk && outArity.Value != nil &&
			outArity.Value.Cmp(big.NewInt(1)) != 0 {
			ctx.addError(fmt.Sprintf("Expression-form asm<%s>() must have out_arity 1 (got %s); only a single stack value can be bound to the result variable.", call.AsmReturnType, outArity.Value.String()))
		}
	})
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

	// Check constant bounds. Non-zero starts and countdown loops (`i--` with
	// `>`/`>=`) are supported: the ANF loop node carries an explicit start value
	// and step direction (issue #121), so lowering binds `iterVar = start +
	// i*step` on each unrolled iteration.
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

// isCompileTimeConstant reports whether a for-loop bound can be unrolled into
// fixed Bitcoin Script. Only integer literals (and their negation) qualify: a
// bare identifier bound (e.g. `const N`) or a runtime member access (`this.x`)
// is NOT resolvable and must be rejected here with a graceful diagnostic —
// anf-lower's extractLoopShape would otherwise panic. Mirrors the reference TS
// compiler's observable behavior: only literal loop bounds compile.
func isCompileTimeConstant(expr Expression) bool {
	switch e := expr.(type) {
	case BigIntLiteral:
		return true
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

// ---------------------------------------------------------------------------
// #131: locktime soundness — extractLocktime needs an extractSequence guard
// ---------------------------------------------------------------------------

// sequenceFinal is the sentinel maximum nSequence: a tx is FINAL (ignores
// locktime) at this value.
var sequenceFinal = new(big.Int).SetUint64(0xffffffff)

// isCallToNamed reports whether expr is a direct call to the named intrinsic,
// e.g. `f(...)`.
func isCallToNamed(expr Expression, name string) bool {
	call, ok := expr.(CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Callee.(Identifier)
	return ok && id.Name == name
}

// isLocktimeRead reports whether expr reads the transaction locktime. Both the
// raw intrinsic extractLocktime(preimage) and its ergonomic sugar
// currentBlockHeight() (which the ANF pass desugars to extractLocktime) count —
// either read is unsound without a sequence-finality guard.
func isLocktimeRead(expr Expression) bool {
	return isCallToNamed(expr, "extractLocktime") || isCallToNamed(expr, "currentBlockHeight")
}

// isSequenceFinalityGuard reports whether expr is an
// `extractSequence(...) < <final>`-style comparison (the guard that makes a
// locktime gate consensus-enforced). Accepts the two natural spellings:
// `extractSequence(pre) < N` / `<= N`, and the reversed `N > extractSequence(pre)`
// / `>= ...`. N must be a bigint literal no greater than the finality sentinel,
// so the guard genuinely forces non-finality.
func isSequenceFinalityGuard(expr Expression) bool {
	bin, ok := expr.(BinaryExpr)
	if !ok {
		return false
	}
	boundOk := func(e Expression) bool {
		lit, ok := e.(BigIntLiteral)
		return ok && lit.Value != nil && lit.Value.Cmp(sequenceFinal) <= 0
	}
	if (bin.Op == "<" || bin.Op == "<=") && isCallToNamed(bin.Left, "extractSequence") && boundOk(bin.Right) {
		return true
	}
	if (bin.Op == ">" || bin.Op == ">=") && isCallToNamed(bin.Right, "extractSequence") && boundOk(bin.Left) {
		return true
	}
	return false
}

// warnLocktimeWithoutSequenceGuard warns when method (transitively, through the
// private-helper call graph) reads the tx locktime but never asserts the tx is
// non-final. A locktime gate is not consensus-enforced unless
// extractSequence < 0xffffffff is also asserted — otherwise an all-final-sequence
// spend bypasses it. Advisory (warning) only — no effect on emitted bytecode.
func (ctx *validationContext) warnLocktimeWithoutSequenceGuard(method MethodNode) {
	privateMethods := make(map[string]MethodNode)
	for _, m := range ctx.contract.Methods {
		if m.Visibility == "private" {
			privateMethods[m.Name] = m
		}
	}

	readsLocktime := false
	hasSequenceGuard := false
	visited := map[string]bool{method.Name: true}
	queue := []MethodNode{method}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		walkExpressionsInBody(current.Body, func(expr Expression) {
			if isLocktimeRead(expr) {
				readsLocktime = true
			}
			if isSequenceFinalityGuard(expr) {
				hasSequenceGuard = true
			}
		})
		// Follow calls into private helpers so a guard (or locktime read) supplied
		// by an inlined helper is seen by the public entry point.
		calls := make(map[string]bool)
		collectMethodCalls(current.Body, calls)
		for callee := range calls {
			if visited[callee] {
				continue
			}
			if pm, ok := privateMethods[callee]; ok {
				visited[callee] = true
				queue = append(queue, pm)
			}
		}
	}

	if readsLocktime && !hasSequenceGuard {
		ctx.addWarningWithLoc(fmt.Sprintf(
			"method '%s' reads extractLocktime but does not assert extractSequence < 0xffffffff; "+
				"a locktime gate is not consensus-enforced unless the tx is non-final — add "+
				"assert(extractSequence(this.txPreimage) < 0xffffffffn)",
			method.Name), &method.SourceLocation)
	}
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
