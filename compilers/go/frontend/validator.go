package frontend

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/icellan/runar/compilers/go/ir"
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
	callDepthExceeded := ctx.checkNoRecursion()
	ctx.checkReservedNames()
	// N-180: the Rabin-provenance and sighash passes walk the private-method
	// call graph; past MaxCallDepth that walk is the very depth the limit
	// refuses, so stop here.
	if callDepthExceeded {
		return &ValidationResult{Errors: ctx.errors, Warnings: ctx.warnings}
	}
	ctx.checkRabinPubKeyProvenance()

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

	// See sp1_fri_soundness_warning.go: the SP1 FRI verifier is not
	// implemented for v1 (F-007). Always refuse; there is no override.
	if contractCallsSP1FriVerifier(contract) {
		ctx.addError(SP1FriNotImplementedError)
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

// checkReservedNames is N-065 / N-060: refuse a declared identifier spelled
// like a name a compiler pass mints (see ir/reserved_names.go). Checks
// properties, method names, constructor and method parameters, locals and loop
// variables. A stateful `txPreimage` PROPERTY keeps its older diagnostic.
// Runs before fixed-array expansion, which mints __idx_/__val_/<root>__<i>.
func (ctx *validationContext) checkReservedNames() {
	stateful := ctx.contract.ParentClass == "StatefulSmartContract"
	check := func(name string, loc SourceLocation) {
		if ir.IsReservedSourceName(name, stateful) {
			l := loc
			ctx.addErrorWithLoc(ir.ReservedNameMessage(name), &l)
		}
	}
	var walk func(stmts []Statement)
	walk = func(stmts []Statement) {
		for _, s := range stmts {
			switch st := s.(type) {
			case VariableDeclStmt:
				check(st.Name, st.SourceLocation)
			case *VariableDeclStmt:
				check(st.Name, st.SourceLocation)
			case IfStmt:
				walk(st.Then)
				walk(st.Else)
			case *IfStmt:
				walk(st.Then)
				walk(st.Else)
			case ForStmt:
				check(st.Init.Name, st.Init.SourceLocation)
				walk(st.Body)
			case *ForStmt:
				check(st.Init.Name, st.Init.SourceLocation)
				walk(st.Body)
			}
		}
	}

	for _, prop := range ctx.contract.Properties {
		if stateful && prop.Name == "txPreimage" {
			continue
		}
		check(prop.Name, prop.SourceLocation)
	}
	methods := append([]MethodNode{ctx.contract.Constructor}, ctx.contract.Methods...)
	for _, m := range methods {
		if m.Name != "constructor" {
			check(m.Name, m.SourceLocation)
		}
		for _, p := range m.Params {
			check(p.Name, m.SourceLocation)
		}
		walk(m.Body)
	}
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
	"bigint":          true,
	"boolean":         true,
	"ByteString":      true,
	"PubKey":          true,
	"Sig":             true,
	"Sha256":          true,
	"Ripemd160":       true,
	"Addr":            true,
	"SigHashPreimage": true,
	"RabinSig":        true,
	"RabinPubKey":     true,
	"Point":           true,
	"P256Point":       true,
	"P384Point":       true,
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
	case CallExpr:
		// `toByteString('<hex>')` IS the ByteStringLiteral production -- see
		// spec/grammar.md section 11:
		//
		//     ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
		//
		// 0e192af6 folded it in ANF lowering, which covers every EXPRESSION
		// position. This check runs on the AST, BEFORE ANF lowering, so an
		// initializer still arrives here as a call node and was refused -- in
		// the one position the `.runar.rs` surface needs it, since the Rust
		// DSL writes initializers as assignments inside `init()` that the
		// parser LIFTS into PropertyNode.Initializer, and a bare `"1976a914"`
		// is a `&str` that cannot be assigned to a `ByteString` (`Vec<u8>`).
		//
		// Accepting it here is only half the job: extractLiteralValue in
		// anf_lower.go must UNWRAP the same shape, or the property validates
		// and then loses its default entirely.
		//
		// Literal argument ONLY. `toByteString(x)` for a non-literal `x` is
		// not this production and stays a non-literal initializer.
		return isToByteStringLiteral(e)
	}
	return false
}

// isToByteStringLiteral reports whether e is the `toByteString(<literal>)`
// ByteStringLiteral production. Peer of the TS helper of the same name in
// 02-validate.ts.
func isToByteStringLiteral(e CallExpr) bool {
	id, ok := e.Callee.(Identifier)
	if !ok || id.Name != "toByteString" || len(e.Args) != 1 {
		return false
	}
	_, isLit := e.Args[0].(ByteStringLiteral)
	return isLit
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
			} else {
				// R-246: any other unrecognised primitive name used to fall
				// through in silence, while the identical name arriving as a
				// CustomType is refused below. No parser produces a
				// PrimitiveType with an unknown name today — they all map an
				// unrecognised name to CustomType — but Validate takes an AST,
				// and the frontend is not the only thing that builds one.
				ctx.addErrorWithLoc(fmt.Sprintf("unsupported type '%s' in property declaration at %s:%d", t.Name, loc.File, loc.Line), &loc)
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

// rejectUnknownParamType refuses a parameter whose type is a name that is not
// a Rúnar type (N-325). "unknown" is the missing-annotation case, already
// diagnosed by the parser; StatefulContext is the explicit context parameter of
// the Zig/Go/Move stateful surfaces, dropped by ANF lowering.
func (ctx *validationContext) rejectUnknownParamType(param ParamNode, where string, loc *SourceLocation) {
	ct, ok := param.Type.(CustomType)
	if !ok || ct.Name == "unknown" || ct.Name == "StatefulContext" {
		return
	}
	ctx.addErrorWithLoc(fmt.Sprintf("type '%s' of parameter '%s' in %s is not a Rúnar type", ct.Name, param.Name, where), loc)
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
		ctx.rejectUnknownParamType(param, "constructor", &ctor.SourceLocation)
	}

	// Validate constructor body
	for _, stmt := range ctor.Body {
		ctx.validateStatement(stmt)
	}

	ctx.validateConstructorSlotBijection()
}

// validateConstructorSlotBijection enforces the NEW-002 invariant: every
// constructor parameter initialises exactly one property that needs a
// deploy-time value, and the i-th parameter initialises the i-th such property.
//
// A property's deploy-time value comes from a constructor ARGUMENT, and the
// artifact addresses those arguments POSITIONALLY: the ABI constructor params
// come from the constructor SIGNATURE while a constructor slot's ParamIndex is
// an index into the properties with no InitialValue, and the SDK splices
// constructorArgs[slot.ParamIndex] into the slot's bytes. Two independently
// built lists, assumed to line up. Where they disagree a deploy argument lands
// in ANOTHER property's slot, silently — a deployed contract authorising a
// value the developer never passed for that property.
//
// "Needs a deploy-time value" mirrors constructorAssignedProperties in
// anf_lower.go exactly: a property carries a compile-time InitialValue iff it
// has an initializer the constructor does NOT override by assigning it a bare
// parameter.
func (ctx *validationContext) validateConstructorSlotBijection() {
	ctor := ctx.contract.Constructor
	paramIndex := map[string]int{}
	for i, p := range ctor.Params {
		paramIndex[p.Name] = i
	}

	// property -> distinct bare parameters assigned to it; a property with any
	// non-parameter assignment is recorded with an EMPTY set.
	propToParams := map[string]map[string]bool{}
	paramToProps := map[string]map[string]bool{}
	for _, stmt := range ctor.Body {
		assign, ok := stmt.(AssignmentStmt)
		if !ok {
			continue
		}
		target, ok := assign.Target.(PropertyAccessExpr)
		if !ok {
			continue
		}
		ident, identOK := assign.Value.(Identifier)
		_, isParam := paramIndex[ident.Name]
		if !identOK || !isParam {
			propToParams[target.Property] = map[string]bool{}
			continue
		}
		if propToParams[target.Property] == nil {
			propToParams[target.Property] = map[string]bool{}
		}
		propToParams[target.Property][ident.Name] = true
		if paramToProps[ident.Name] == nil {
			paramToProps[ident.Name] = map[string]bool{}
		}
		paramToProps[ident.Name][target.Property] = true
	}

	before := len(ctx.errors)

	// (a) One parameter feeding several properties: only one of them could own
	// the argument, so the rest keep a default or deploy undefined.
	for _, param := range ctor.Params {
		props := paramToProps[param.Name]
		if len(props) > 1 {
			ctx.addErrorWithLoc(fmt.Sprintf(
				"constructor parameter '%s' initialises more than one property (%s). "+
					"Each constructor parameter is spliced into exactly one property's "+
					"deploy-time slot, so only the first would receive the argument. "+
					"Declare one parameter per property.",
				param.Name, strings.Join(sortedKeys(props), ", ")), &ctor.SourceLocation)
		}
	}

	// (b) One property fed by several parameters — no single argument owns it.
	for _, prop := range ctx.contract.Properties {
		params := propToParams[prop.Name]
		if len(params) > 1 {
			ctx.addErrorWithLoc(fmt.Sprintf(
				"property '%s' is assigned more than one constructor parameter (%s). "+
					"Each property that needs a deploy-time value corresponds to exactly "+
					"one constructor parameter.",
				prop.Name, strings.Join(sortedKeys(params), ", ")), &ctor.SourceLocation)
		}
	}

	// (c) A property that needs a deploy-time value but whose constructor
	// assignment is not a parameter. A property assigned NOTHING is already
	// reported above, so it is skipped here rather than double-reported.
	for _, prop := range ctx.contract.Properties {
		if prop.Initializer != nil {
			continue
		}
		params, assigned := propToParams[prop.Name]
		if !assigned || len(params) >= 1 {
			continue
		}
		ctx.addErrorWithLoc(fmt.Sprintf(
			"property '%s' has no initializer and is not assigned a constructor "+
				"parameter, so it has no deploy-time value. The constructor body is not "+
				"compiled into the locking script — give the property a literal "+
				"initializer or assign it a constructor parameter (this.%s = %s).",
			prop.Name, prop.Name, prop.Name), &ctor.SourceLocation)
	}

	// (d) A parameter that initialises nothing: its argument is dropped and,
	// because slots are positional, every later argument lands in the wrong slot.
	for _, param := range ctor.Params {
		if _, ok := paramToProps[param.Name]; ok {
			continue
		}
		ctx.addErrorWithLoc(fmt.Sprintf(
			"constructor parameter '%s' does not initialise any property. Constructor "+
				"arguments are spliced into property slots positionally, so an unused "+
				"parameter drops its own argument and shifts every later one into the "+
				"wrong property's slot. Assign it (this.%s = %s) or remove the parameter.",
			param.Name, param.Name, param.Name), &ctor.SourceLocation)
	}

	// (e) Order. Only meaningful once (a)-(d) hold, otherwise the positions
	// being compared are themselves the thing that is broken.
	if len(ctx.errors) != before {
		return
	}
	slot := 0
	for _, prop := range ctx.contract.Properties {
		params := propToParams[prop.Name]
		if prop.Initializer != nil && len(params) != 1 {
			continue // initializer survives: not a deploy-time property
		}
		if len(params) == 1 {
			var param string
			for p := range params {
				param = p
			}
			if declared := paramIndex[param]; declared != slot {
				abiName := "?"
				if slot < len(ctor.Params) {
					abiName = ctor.Params[slot].Name
				}
				ctx.addErrorWithLoc(fmt.Sprintf(
					"property '%s' occupies deploy-time slot %d, but the constructor "+
						"parameter that initialises it ('%s') is declared at position %d. "+
						"Constructor arguments are spliced positionally, so the deployed "+
						"script would carry argument %d — advertised by the ABI as parameter "+
						"'%s' — in this property's slot. Declare the parameters in the same "+
						"order as the properties they initialise.",
					prop.Name, slot, param, declared, slot, abiName), &ctor.SourceLocation)
			}
		}
		slot++
	}
}

// sortedKeys returns a set's keys in a deterministic order so diagnostics do
// not depend on Go's randomised map iteration.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
		ctx.rejectUnknownParamType(param, fmt.Sprintf("method '%s'", method.Name), &method.SourceLocation)
	}

	// `return` is a PRIVATE-helper construct only (NEW-012).
	if method.Visibility == "public" {
		ctx.rejectReturnInPublicMethod(method)
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
	// the spending tx is non-final (extractSequence !== 0xffffffff). Advisory only.
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
	// R-136 / R-233: all nine diagnostics below used the locationless
	// ctx.addError while every other validator diagnostic in this file carries
	// a SourceLocation — including the "must end with an assert() call or a
	// terminal asm({...})" one a few dozen lines up, which uses
	// addErrorWithLoc. An asm() mistake is a hand-written opcode string, which
	// is exactly the diagnostic a reader most needs a line number for.
	walkExpressionsInBodyWithLoc(method.Body, func(expr Expression, loc *SourceLocation) {
		if !isAsmCall(expr) {
			return
		}
		call := expr.(CallExpr)

		if ctx.contract.ParentClass != "UnsafeSmartContract" {
			ctx.addErrorWithLoc(fmt.Sprintf("'asm' is only available in contracts extending UnsafeSmartContract; got %s. Move the call into a class that extends UnsafeSmartContract (and import { UnsafeSmartContract } from 'runar-lang').", ctx.contract.ParentClass), loc)
			return
		}

		if len(call.Args) != 3 {
			ctx.addErrorWithLoc("asm() expects exactly one object-literal argument { body, in_arity?, out_arity? }", loc)
			return
		}

		bodyArg, bodyOk := call.Args[0].(ByteStringLiteral)
		if !bodyOk {
			ctx.addErrorWithLoc("asm() body must be a hex string literal", loc)
			return
		}
		body := bodyArg.Value
		if len(body) == 0 {
			ctx.addErrorWithLoc("asm() body must be a non-empty hex string literal", loc)
		} else if len(body)%2 != 0 {
			ctx.addErrorWithLoc(fmt.Sprintf("asm() body has odd hex length (%d); each opcode byte requires two hex characters", len(body)), loc)
		} else if !isHexString(body) {
			ctx.addErrorWithLoc("asm() body contains non-hex characters; only 0-9, a-f, A-F are allowed", loc)
		}

		inArity, inOk := call.Args[1].(BigIntLiteral)
		if !inOk || inArity.Value == nil || inArity.Value.Sign() < 0 {
			ctx.addErrorWithLoc("asm() in_arity must be a non-negative integer literal", loc)
		}

		outArity, outOk := call.Args[2].(BigIntLiteral)
		if !outOk || outArity.Value == nil || outArity.Value.Sign() < 0 {
			ctx.addErrorWithLoc("asm() out_arity must be a non-negative integer literal", loc)
		}

		// Expression-form asm<T>({...}) returns a value that flows into a
		// let-binding — exactly ONE stack value, so out_arity must be 1.
		if call.AsmReturnType != "" && outOk && outArity.Value != nil &&
			outArity.Value.Cmp(big.NewInt(1)) != 0 {
			ctx.addErrorWithLoc(fmt.Sprintf("Expression-form asm<%s>() must have out_arity 1 (got %s); only a single stack value can be bound to the result variable.", call.AsmReturnType, outArity.Value.String()), loc)
		}
	})
}

// rejectReturnInPublicMethod enforces spec/grammar.md:161 ("Public methods MUST
// return `void`") and :162 ("Public methods MUST end with an `assert(...)` call
// as their final statement").
//
// spec/semantics.md gives `return` no early-exit meaning at all: §4.6 defines it
// ONLY as "the value of this method is v" (the private-helper inlining
// semantics), while §4.7 sequences statements UNCONDITIONALLY — there is no
// rule under which the statements after a `return` are skipped.
//
// Lowering it as if it were the tail of an inlined helper produced two
// different broken scripts (NEW-012):
//
//   - `return;`      the enclosing branch had no result to contribute, so its
//     arm yielded OP_0 and the whole script evaluated FALSE —
//     an unspendable UTXO from source that compiled clean. In
//     this tier it surfaced as an internal stack-lowering panic
//     ("index out of range [-1]") instead.
//   - `return expr;` the returned value became the branch result and hence the
//     script's final truthiness, so any truthy expr spent the
//     contract WITHOUT reaching the guarding assert. Fail-OPEN.
//
// The Java tier has always rejected the valued form; this brings the rule to
// every tier and covers the bare form too.
func (ctx *validationContext) rejectReturnInPublicMethod(method MethodNode) {
	for _, ret := range findReturnStatements(method.Body) {
		loc := ret.SourceLocation
		ctx.addErrorWithLoc(
			fmt.Sprintf(
				"public method '%s' must not use `return`: public methods are spending "+
					"entry points, they return void (spec/grammar.md:161) and must end with "+
					"an assert() that encodes the spending condition (spec/grammar.md:162). "+
					"Rúnar has no early exit — restructure the guard as an if/else, or move "+
					"the logic into a private helper, where `return` is allowed.",
				method.Name,
			),
			&loc,
		)
	}
}

// findReturnStatements collects every return in body, at any nesting depth
// (if/else arms, loop bodies).
func findReturnStatements(body []Statement) []ReturnStmt {
	var found []ReturnStmt
	var walk func(stmts []Statement)
	walk = func(stmts []Statement) {
		for _, stmt := range stmts {
			switch s := stmt.(type) {
			case ReturnStmt:
				found = append(found, s)
			case IfStmt:
				walk(s.Then)
				walk(s.Else)
			case ForStmt:
				walk(s.Body)
			}
		}
	}
	walk(body)
	return found
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
		ctx.validateIndexAssignmentTarget(s)
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

// validateIndexAssignmentTarget is N-002 (F-013's rule, shared verbatim by all
// seven tiers): only a FixedArray property is index-writable. Any other index
// target (a ByteString property, a local, a parameter, a member-chained root)
// is left alone by ExpandFixedArrays and ANF lowering lowers it as a READ,
// dropping the write -- a deployable script whose state never changes. Reject
// it here with a location instead.
func (ctx *validationContext) validateIndexAssignmentTarget(s AssignmentStmt) {
	idx, ok := s.Target.(IndexAccessExpr)
	if !ok {
		return
	}
	var root Expression = idx
	for {
		ia, isIdx := root.(IndexAccessExpr)
		if !isIdx {
			break
		}
		root = ia.Object
	}
	if pa, isProp := root.(PropertyAccessExpr); isProp {
		for _, p := range ctx.contract.Properties {
			if p.Name != pa.Property {
				continue
			}
			if _, isFixed := p.Type.(FixedArrayType); isFixed {
				return
			}
		}
	}
	loc := s.SourceLocation
	ctx.addErrorWithLoc(
		"index assignment is only supported on FixedArray contract properties; "+
			"the target here is not a FixedArray property",
		&loc,
	)
}

func (ctx *validationContext) validateForStatement(stmt ForStmt) {
	ctx.validateExpression(stmt.Condition)

	// Check constant bounds. Non-zero starts and countdown loops (`i--` with
	// `>`/`>=`) are supported: the ANF loop node carries an explicit start value
	// and step direction (issue #121), so lowering binds `iterVar = start +
	// i*step` on each unrolled iteration.
	if bin, ok := stmt.Condition.(BinaryExpr); ok {
		if !isCompileTimeConstant(bin.Right) {
			ctx.addError(forLoopBoundDiagnostic(bin.Right))
		}
	}

	ctx.validateForConditionTestsIterator(stmt)

	ctx.validateExpression(stmt.Init.Init)
	ctx.validateForUpdate(stmt)
	ctx.validateNoOutputIntrinsicInLoop(stmt)
	for _, s := range stmt.Body {
		ctx.validateStatement(s)
	}
}

// validateForConditionTestsIterator rejects any for-loop whose condition does
// not test the iterator itself (W4 / PhantomLap).
//
// The comment above this function's caller used to say the condition compares
// the iter var to a constant, and then the code read only `Condition.Right`.
// Nothing required `Condition.Left` to BE the iterator, and extractLoopShape
// ignores left entirely: it computes `count = bound - start`. So
//
//	for (let i = 0n; i + 1n < 2n; i++) { ... }
//
// runs ONCE in the source language and TWICE in the emitted script
// (count = 2 - 0). The extra lap executes the `else` arm the source can never
// reach. Measured on @bsv/sdk Spend.validate() with a vault whose signature
// check sits in the first lap and whose second lap sets `authorized = true`:
// the phantom-lap loop ACCEPTED an empty signature, while the semantically
// identical `i < 1n` rejected it.
//
// Refusal rather than lowering: evaluating a general condition per iteration
// means unrolling against a real interpreter at ANF time, a language extension
// with no golden behind it. The diagnostic text is shared verbatim with the
// other six tiers.
func (ctx *validationContext) validateForConditionTestsIterator(stmt ForStmt) {
	if bin, ok := stmt.Condition.(BinaryExpr); ok {
		if id, ok := bin.Left.(Identifier); ok && id.Name == stmt.Init.Name {
			return
		}
	}
	ctx.addErrorWithLoc(forConditionIteratorError(stmt.Init.Name), &stmt.SourceLocation)
}

func forConditionIteratorError(iter string) string {
	return "For loop condition must compare the loop variable '" + iter +
		"' to a compile-time constant (`" + iter + " < 10n`). The unrolled loop binds " +
		"the iterator as `start + k*step` and takes its trip count from the bound alone, " +
		"so a condition whose left-hand side is anything else -- a computed expression, " +
		"or a different variable -- is not the condition the loop actually evaluates"
}

// loopOutputIntrinsicMsg builds the R-127 rejection. Shared verbatim
// with the other six tiers (same mirror list as loopUpdateDiagnosticMsg).
func loopOutputIntrinsicMsg(intrinsic, via string) string {
	viaClause := ""
	if via != "" {
		viaClause = " (reached through private method '" + via + "')"
	}
	return "Output intrinsic '" + intrinsic + "'" + viaClause +
		" cannot be called inside a loop body. A loop body lowers into its own scope whose " +
		"declared outputs never reach the method's output list, so the continuation hash would " +
		"commit to fewer outputs than the transaction actually creates: the spend is rejected by " +
		"every shipped SDK and any successor it produces is unspendable. Move the call out of the loop."
}

// ternaryOutputIntrinsicMsg builds the N-049 rejection. Shared verbatim with
// the other six tiers (TS reference: ternaryOutputIntrinsicDiagnostic in
// packages/runar-compiler/src/passes/02-validate.ts).
func ternaryOutputIntrinsicMsg(intrinsic, via string) string {
	viaClause := ""
	if via != "" {
		viaClause = " (reached through private method '" + via + "')"
	}
	return "Output intrinsic '" + intrinsic + "'" + viaClause +
		" cannot be called inside a conditional (ternary) expression arm. A ternary arm lowers " +
		"into its own scope whose declared outputs never reach the method's output list, so the " +
		"continuation hash would commit to fewer outputs than the transaction actually creates: " +
		"a spender can drop the output and the honest spend is rejected. Use an if/else statement instead."
}

// validateNoOutputIntrinsicInTernaryArm rejects an output intrinsic in either
// arm of a ternary expression (N-049). lowerTernaryExpr lowers each arm into a
// sub-context whose output refs are dropped, unlike the if-statement lowering,
// which merges each arm's refs into the parent — so the continuation hash would
// omit the arm's output (EXT-2 TernaryToll: a spend dropping the payout was
// accepted on every tier). Private helpers are followed because they are
// inlined into the arm. A ternary that only selects values is untouched.
func (ctx *validationContext) validateNoOutputIntrinsicInTernaryArm(e TernaryExpr) {
	for _, arm := range []Expression{e.Consequent, e.Alternate} {
		if intrinsic, via, _, found := ctx.findOutputIntrinsicInExpr(arm, nil, map[string]bool{}); found {
			ctx.addError(ternaryOutputIntrinsicMsg(intrinsic, via))
			return
		}
	}
}

// outputIntrinsicNames are the three intrinsics that register an output ref.
var outputIntrinsicNames = map[string]bool{
	"addOutput": true, "addRawOutput": true, "addDataOutput": true,
}

// validateNoOutputIntrinsicInLoop rejects an output intrinsic called inside a
// loop body (R-127).
//
// anf_lower lowers a loop body into its own sub-context, which starts with a
// fresh empty add-output ref list, and nothing propagates that list back to the
// method context — unlike the if-statement lowering, which concatenates each
// arm's outputs into one ref precisely so the parent sees them. The
// continuation hash is then built from whatever addOutput calls sit at the
// method's TOP level while the loop's outputs are still emitted into the
// transaction. Measured on a two-iteration loop before this check existed:
//
//   - loop only: ts/go/rust/python blew up inside stack lowering ("method
//     parameter '_newAmount' is not on the stack at a post-consumption
//     reference"), zig/ruby emitted a covenant over the WRONG output set, java
//     emitted none.
//   - loop + one top-level call: compiled clean in every tier, and the ANF
//     continuation hashed exactly ONE leaf while three outputs were built.
//
// A continuation committing to fewer outputs than the transaction creates is
// spendable only by a hand-crafted transaction, is rejected by every shipped
// SDK, and the successor it produces is permanently unspendable (CL-BUG-164).
//
// Refusal rather than lowering: propagating the refs cannot work by name,
// because the loop is unrolled at stack-lowering time and one body binding name
// denotes N physical slots. A correct lowering means unrolling at ANF time, a
// language feature with no golden behind it; refusing removes nothing that
// works today — no fixture or example in the repo declares an output inside a
// loop.
func (ctx *validationContext) validateNoOutputIntrinsicInLoop(stmt ForStmt) {
	intrinsic, via, loc, found := ctx.findOutputIntrinsic(stmt.Body, map[string]bool{})
	if !found {
		return
	}
	if loc == nil {
		l := stmt.SourceLocation
		loc = &l
	}
	ctx.addErrorWithLoc(loopOutputIntrinsicMsg(intrinsic, via), loc)
}

// calleeProperty returns the property/function name a call names, if any.
func calleeProperty(expr Expression) string {
	call, ok := expr.(CallExpr)
	if !ok {
		return ""
	}
	switch c := call.Callee.(type) {
	case PropertyAccessExpr:
		return c.Property
	case MemberExpr:
		return c.Property
	case Identifier:
		return c.Name
	}
	return ""
}

// privateMethodNamed reports whether name is a private method on the contract.
func (ctx *validationContext) privateMethodNamed(name string) *MethodNode {
	if ctx.contract == nil {
		return nil
	}
	for i := range ctx.contract.Methods {
		m := &ctx.contract.Methods[i]
		if m.Name == name && m.Visibility == "private" {
			return m
		}
	}
	return nil
}

// findOutputIntrinsic returns the first output intrinsic reachable from stmts,
// following calls to private methods: a public method that delegates addOutput
// to a private helper has that helper INLINED at ANF time, so a helper called
// in a loop lands its outputs in the loop's sub-context exactly as a direct
// call would.
func (ctx *validationContext) findOutputIntrinsic(
	stmts []Statement, seen map[string]bool,
) (string, string, *SourceLocation, bool) {
	for _, stmt := range stmts {
		intrinsic, via, loc, found := ctx.findOutputIntrinsicInStatement(stmt, seen)
		if found {
			return intrinsic, via, loc, true
		}
	}
	return "", "", nil, false
}

func (ctx *validationContext) findOutputIntrinsicInStatement(
	stmt Statement, seen map[string]bool,
) (string, string, *SourceLocation, bool) {
	var loc SourceLocation
	var expr Expression
	switch s := stmt.(type) {
	case ExpressionStmt:
		loc, expr = s.SourceLocation, s.Expr
	case VariableDeclStmt:
		loc, expr = s.SourceLocation, s.Init
	case AssignmentStmt:
		loc, expr = s.SourceLocation, s.Value
	case ReturnStmt:
		if s.Value == nil {
			return "", "", nil, false
		}
		loc, expr = s.SourceLocation, s.Value
	case IfStmt:
		if intrinsic, via, l, found := ctx.findOutputIntrinsicInExpr(s.Condition, &s.SourceLocation, seen); found {
			return intrinsic, via, l, true
		}
		body := append(append([]Statement{}, s.Then...), s.Else...)
		return ctx.findOutputIntrinsic(body, seen)
	case ForStmt:
		return ctx.findOutputIntrinsic(s.Body, seen)
	default:
		return "", "", nil, false
	}
	return ctx.findOutputIntrinsicInExpr(expr, &loc, seen)
}

func (ctx *validationContext) findOutputIntrinsicInExpr(
	expr Expression, loc *SourceLocation, seen map[string]bool,
) (string, string, *SourceLocation, bool) {
	if expr == nil {
		return "", "", nil, false
	}
	if name := calleeProperty(expr); name != "" {
		if outputIntrinsicNames[name] {
			return name, "", loc, true
		}
		if m := ctx.privateMethodNamed(name); m != nil && !seen[name] {
			seen[name] = true
			if intrinsic, _, _, found := ctx.findOutputIntrinsic(m.Body, seen); found {
				return intrinsic, name, loc, true
			}
		}
	}
	for _, child := range subExpressions(expr) {
		if intrinsic, via, l, found := ctx.findOutputIntrinsicInExpr(child, loc, seen); found {
			return intrinsic, via, l, true
		}
	}
	return "", "", nil, false
}

// subExpressions returns the direct sub-expressions of expr, for the intrinsic
// search above. An intrinsic can sit inside an argument list or an operand, not
// only as a bare expression statement.
func subExpressions(expr Expression) []Expression {
	switch e := expr.(type) {
	case CallExpr:
		return e.Args
	case BinaryExpr:
		return []Expression{e.Left, e.Right}
	case UnaryExpr:
		return []Expression{e.Operand}
	case TernaryExpr:
		return []Expression{e.Condition, e.Consequent, e.Alternate}
	case IndexAccessExpr:
		return []Expression{e.Object, e.Index}
	case ArrayLiteralExpr:
		return e.Elements
	}
	return nil
}

// loopUpdateDiagnosticMsg is shared verbatim with the other six tiers. Per-tier
// diagnostic drift on the same rejection is a recurring defect in this repo, so
// the string is pinned here and mirrored, character for character, in
// packages/runar-compiler/src/passes/02-validate.ts,
// compilers/rust/src/frontend/validator.rs,
// compilers/python/runar_compiler/frontend/validator.py,
// compilers/zig/src/frontend/validator.zig,
// compilers/ruby/lib/frontend/validator.rb and
// compilers/java/src/main/java/runar/compiler/passes/Validate.java.
const loopUpdateDiagnosticMsg = "For loop update must advance the loop variable by one (`i++`, `i--`, " +
	"`i = i + 1n`, `i = i - 1n`). The unrolled loop carries only a start value and a " +
	"unit step, so any other update clause -- a function call, a state mutation, or a " +
	"non-unit step such as `i += 2` -- cannot be represented and would be discarded"

// validateForUpdate rejects any for-loop update clause the loop model cannot
// represent (R-065).
//
// The ANF `loop` node carries exactly `{count, iterVar, start, step, body}` and
// synthesizes the iterator on unrolled iteration k as `start + k*step`. There
// is no slot for an arbitrary update statement, and extractLoopStep only ever
// understood a unit step — everything else was silently coerced to `+1` (or
// `-1` from the comparison direction) and the clause itself was discarded. That
// made three distinct failures indistinguishable from a correct compile:
//
//   - `for (let i = 0n; i < 3n; undefinedFn())` produced byte-identical output.
//     A nonexistent function name raised nothing.
//   - `for (let i = 0n; i < 3n; this.count++)` dropped the state write.
//   - `for (let i = 0n; i < 5n; i += 2n)` unrolled 5 times over i = 0..4 instead
//     of 3 times over i = 0,2,4.
//
// spec/grammar.md's ForStatement production admits only
// `Identifier ('++' | '--')`, and its Statement Restrictions say "The loop
// variable MUST use simple increment (`++`) or decrement (`--`)". So rejecting
// is the fix rather than lowering: appending the update's lowering to the loop
// body would re-emit `i++` as a dead binding on every loop that already
// compiles correctly, moving bytes across the whole corpus to express nothing.
//
// The accepted set is every shape the nine frontends actually synthesize:
// `i++`/`i--`/`++i`/`--i`; the assignment spelling `i = i + 1` / `i = i - 1` /
// `i = 1 + i` that `i += 1` becomes in the Solidity, Zig and Java parsers; and
// the effect-free no-op sentinel (a literal or a bare identifier) that the
// while-shaped parsers synthesize when the source has no continue expression at
// all -- but only on a loop whose condition does not test its declared
// iterator (already refused by the condition rule). On a real iterator a no-op
// update never advances it: `var i = 3; while (i < 5) : (i)` compiled two laps
// over i = 3, 4 (N-116).
//
// The advanced variable must be the declared iterator or the identifier the
// condition tests. Both are needed: the Zig parser only folds
// `var i = 0; while (i < N) : (i += 1)` into a single ForStmt when the
// declaration is the immediately preceding statement, so an unfolded loop
// carries a placeholder init while the update advances the real `i` named in
// the condition.
func (ctx *validationContext) validateForUpdate(stmt ForStmt) {
	// Names the update is allowed to advance: the declared iterator, plus the
	// identifier the condition tests (see the doc comment's Zig case).
	allowed := []string{stmt.Init.Name}
	if bin, ok := stmt.Condition.(BinaryExpr); ok {
		if id, ok := bin.Left.(Identifier); ok {
			allowed = append(allowed, id.Name)
		}
	}

	// N-116: the no-op sentinel is tolerated only on a loop the condition rule
	// already refuses (placeholder iterator). On a real iterator it never
	// advances, yet the unrolled loop would still step by one.
	condTestsIter := false
	if bin, ok := stmt.Condition.(BinaryExpr); ok {
		if id, ok := bin.Left.(Identifier); ok && id.Name == stmt.Init.Name {
			condTestsIter = true
		}
	}

	if isRepresentableForUpdate(allowed, stmt.Update, !condTestsIter) {
		return
	}

	loc := stmt.SourceLocation
	ctx.addErrorWithLoc(loopUpdateDiagnosticMsg, &loc)
}

// isAllowedLoopVar reports whether expr names one of the identifiers the update
// is allowed to advance. A property access, an index access or anything else is
// never accepted: those are the side effects that used to be dropped.
func isAllowedLoopVar(allowed []string, expr Expression) bool {
	id, ok := expr.(Identifier)
	if !ok {
		return false
	}
	for _, a := range allowed {
		if a == id.Name {
			return true
		}
	}
	return false
}

func isLiteralOne(expr Expression) bool {
	lit, ok := expr.(BigIntLiteral)
	return ok && lit.Value != nil && lit.Value.IsInt64() && lit.Value.Int64() == 1
}

func isRepresentableForUpdate(allowed []string, update Statement, acceptNoOpSentinel bool) bool {
	switch u := update.(type) {
	case ExpressionStmt:
		switch e := u.Expr.(type) {
		case IncrementExpr:
			return isAllowedLoopVar(allowed, e.Operand)
		case DecrementExpr:
			return isAllowedLoopVar(allowed, e.Operand)
		case BigIntLiteral, BoolLiteral, Identifier:
			// The no-op sentinel a while-shaped frontend synthesizes when the
			// source carries no continue expression: zig's `while (c) {}`,
			// move's `while (c) {}`, go's `for c {}`. Reading a literal or a
			// bare identifier has no effect, so discarding it loses nothing --
			// on a loop the condition rule already refuses (N-116).
			return acceptNoOpSentinel
		}
		return false

	case AssignmentStmt:
		// `i += 1` / `i -= 1` arrive here as `i = i + 1` / `i = i - 1`.
		if !isAllowedLoopVar(allowed, u.Target) {
			return false
		}
		bin, ok := u.Value.(BinaryExpr)
		if !ok {
			return false
		}
		switch bin.Op {
		case "+":
			return (isAllowedLoopVar(allowed, bin.Left) && isLiteralOne(bin.Right)) ||
				(isLiteralOne(bin.Left) && isAllowedLoopVar(allowed, bin.Right))
		case "-":
			return isAllowedLoopVar(allowed, bin.Left) && isLiteralOne(bin.Right)
		}
		return false
	}

	return false
}

// isCompileTimeConstant reports whether a for-loop bound can be unrolled into
// fixed Bitcoin Script. Only integer literals (and their negation) qualify: a
// bare identifier bound (e.g. `const N`) or a runtime member access (`this.x`)
// is NOT resolvable and must be rejected here with a graceful diagnostic —
// anf-lower's extractLoopShape would otherwise panic. Mirrors the reference TS
// compiler's observable behavior: only literal loop bounds compile.
// forLoopBoundDiagnostic returns the reference (TypeScript) tier's sentence for
// a for-loop bound that is not an integer literal. The reference's validator
// trusts a bare identifier (or boolean literal, or a negation of one) as "could
// be a const" and lets ANF lowering refuse it with the "Cannot determine"
// sentence; every other non-literal shape (`this.x`, an expression) is refused
// by its validator with the "must be a compile-time constant" sentence. Both
// sentences are shared verbatim by all seven tiers (N-026).
func forLoopBoundDiagnostic(bound Expression) string {
	for {
		u, ok := bound.(UnaryExpr)
		if !ok || u.Op != "-" {
			break
		}
		bound = u.Operand
	}
	switch bound.(type) {
	case Identifier, BoolLiteral:
		return "Cannot determine loop bound at compile time. For-loop bounds must be integer literals."
	}
	return "For loop bound must be a compile-time constant (literal or const variable)"
}

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
		ctx.validateNoOutputIntrinsicInTernaryArm(e)
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
	case ArrayLiteralExpr:
		for _, el := range e.Elements {
			ctx.validateExpression(el)
		}
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

// isSequenceFinalityGuard reports whether expr is a comparison on
// extractSequence(...) that genuinely EXCLUDES the finality sentinel
// 0xffffffff, reading the field as the unsigned 32-bit wire value it is
// (see emitUnsignedBin2Num in codegen/stack.go).
//
// Accepted:
//
//	extractSequence(pre) !== 0xffffffff   and the reversed spelling
//	extractSequence(pre) <  N, 0 < N <= 0xffffffff   (reversed: N > ...)
//	extractSequence(pre) <= N, N <  0xffffffff   (reversed: N >= ...)
//
// Deliberately NOT accepted: <= 0xffffffff and >= 0xffffffff. nSequence cannot
// exceed 0xffffffff, so those are true for every transaction including the
// final one — a tautology that used to silence this warning on a contract with
// no guard at all (W1 / FinalCountdown).
//
// Also NOT accepted: extractSequence(pre) < 0. Unsigned nSequence is never
// negative, so that comparison is vacuous.
func isSequenceFinalityGuard(expr Expression) bool {
	bin, ok := expr.(BinaryExpr)
	if !ok {
		return false
	}
	isFinalSentinel := func(e Expression) bool {
		lit, ok := e.(BigIntLiteral)
		return ok && lit.Value != nil && lit.Value.Cmp(sequenceFinal) == 0
	}
	strictBoundOk := func(e Expression) bool {
		lit, ok := e.(BigIntLiteral)
		return ok && lit.Value != nil && lit.Value.Sign() > 0 && lit.Value.Cmp(sequenceFinal) <= 0
	}
	nonStrictBoundOk := func(e Expression) bool {
		lit, ok := e.(BigIntLiteral)
		return ok && lit.Value != nil && lit.Value.Cmp(sequenceFinal) < 0
	}
	switch bin.Op {
	case "!==":
		return (isCallToNamed(bin.Left, "extractSequence") && isFinalSentinel(bin.Right)) ||
			(isCallToNamed(bin.Right, "extractSequence") && isFinalSentinel(bin.Left))
	case "<":
		return isCallToNamed(bin.Left, "extractSequence") && strictBoundOk(bin.Right)
	case "<=":
		return isCallToNamed(bin.Left, "extractSequence") && nonStrictBoundOk(bin.Right)
	case ">":
		return isCallToNamed(bin.Right, "extractSequence") && strictBoundOk(bin.Left)
	case ">=":
		return isCallToNamed(bin.Right, "extractSequence") && nonStrictBoundOk(bin.Left)
	}
	return false
}

// assertionImpliesSequenceGuard reports whether asserting expr logically
// implies a sequence-finality guard. A matching comparison nested under
// `!` (or `||`) does not count: assert(!(extractSequence !== 0xffffffff))
// requires a FINAL sequence. `&&` implies each conjunct.
func assertionImpliesSequenceGuard(expr Expression) bool {
	if isSequenceFinalityGuard(expr) {
		return true
	}
	bin, ok := expr.(BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op == "&&" {
		return assertionImpliesSequenceGuard(bin.Left) || assertionImpliesSequenceGuard(bin.Right)
	}
	return false
}

// warnLocktimeWithoutSequenceGuard warns when method (transitively, through the
// private-helper call graph) reads the tx locktime but never asserts the tx is
// non-final. A locktime gate is not consensus-enforced unless
// extractSequence !== 0xffffffff is also asserted — otherwise an all-final-sequence
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
			if isAssertCall(expr) {
				call := expr.(CallExpr)
				for _, arg := range call.Args {
					if assertionImpliesSequenceGuard(arg) {
						hasSequenceGuard = true
					}
				}
			}
		})
		// Follow calls into private helpers so a guard (or locktime read) supplied
		// by an inlined helper is seen by the public entry point.
		calls := make(map[string]bool)
		collectMethodCalls(current.Body, calls, false)
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
			"method '%s' reads extractLocktime but does not assert extractSequence is not 0xffffffff; "+
				"a locktime gate is not consensus-enforced unless the tx is non-final — add "+
				"assert(extractSequence(this.txPreimage) !== 0xffffffffn)",
			method.Name), &method.SourceLocation)
	}
}

func walkExpressionsInBody(stmts []Statement, visitor func(Expression)) {
	for _, stmt := range stmts {
		walkExpressionsInStatement(stmt, visitor)
	}
}

// walkExpressionsInBodyWithLoc is walkExpressionsInBody plus the location of the
// STATEMENT each expression came from (R-136 / R-233).
//
// Expressions in this AST carry no SourceLocation of their own — CallExpr has
// Callee, Args and AsmReturnType and nothing else — so a diagnostic about an
// expression has nowhere to point unless the walker hands down the enclosing
// statement's position. Statements all carry one.
func walkExpressionsInBodyWithLoc(stmts []Statement, visitor func(Expression, *SourceLocation)) {
	for _, stmt := range stmts {
		walkExpressionsInStatementWithLoc(stmt, visitor)
	}
}

func walkExpressionsInStatementWithLoc(stmt Statement, visitor func(Expression, *SourceLocation)) {
	switch s := stmt.(type) {
	case ExpressionStmt:
		loc := s.SourceLocation
		walkExprWithLoc(s.Expr, &loc, visitor)
	case VariableDeclStmt:
		loc := s.SourceLocation
		walkExprWithLoc(s.Init, &loc, visitor)
	case AssignmentStmt:
		loc := s.SourceLocation
		walkExprWithLoc(s.Target, &loc, visitor)
		walkExprWithLoc(s.Value, &loc, visitor)
	case IfStmt:
		loc := s.SourceLocation
		walkExprWithLoc(s.Condition, &loc, visitor)
		walkExpressionsInBodyWithLoc(s.Then, visitor)
		walkExpressionsInBodyWithLoc(s.Else, visitor)
	case ForStmt:
		loc := s.SourceLocation
		walkExprWithLoc(s.Condition, &loc, visitor)
		walkExpressionsInBodyWithLoc(s.Body, visitor)
	case ReturnStmt:
		if s.Value != nil {
			loc := s.SourceLocation
			walkExprWithLoc(s.Value, &loc, visitor)
		}
	}
}

func walkExprWithLoc(expr Expression, loc *SourceLocation, visitor func(Expression, *SourceLocation)) {
	walkExpr(expr, func(e Expression) { visitor(e, loc) })
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
	case ArrayLiteralExpr:
		for _, el := range e.Elements {
			walkExpr(el, visitor)
		}
	}
}

// ---------------------------------------------------------------------------
// F-286: verifyRabinSig's public key must not be chosen by the spender
// ---------------------------------------------------------------------------

// RabinPubKeyProvenanceMessage is the one diagnostic every tier emits for
// F-286 (user decision R78).
const RabinPubKeyProvenanceMessage = "verifyRabinSig public key (4th argument) must be a contract property or a literal; " +
	"a spender-supplied Rabin modulus lets anyone forge a signature"

type rabinScope struct {
	method    *MethodNode
	isPrivate bool
	params    map[string]int
	bindings  map[string][]Expression
	mutated   map[string]bool
	// N-205: names declared as locals (a bare property write also lands in
	// bindings).
	declared map[string]bool
}

type rabinCallSite struct {
	args  []Expression
	scope *rabinScope
}

// checkRabinPubKeyProvenance ports packages/runar-compiler/src/passes/
// 02-validate.ts checkRabinPubKeyProvenance. verifyRabinSig(msg, sig,
// padding, n) checks (sig^2 + padding) mod n == SHA256(msg) mod n; a spender
// who chooses n forges any message, so n must be fixed by the deployer.
//
// Trusted 4th arguments: a property read (this.x, or a bare identifier naming
// a property no parameter or local shadows); a bigint literal; a local whose
// initialiser and every assignment are trusted; a parameter of a PRIVATE
// method that every call site (at least one) binds to a trusted value (least
// fixed point). Everything else is refused.
func (ctx *validationContext) checkRabinPubKeyProvenance() {
	contract := ctx.contract
	props := map[string]bool{}
	for _, p := range contract.Properties {
		props[p.Name] = true
	}
	private := map[string]*MethodNode{}
	for i := range contract.Methods {
		if contract.Methods[i].Visibility == "private" {
			private[contract.Methods[i].Name] = &contract.Methods[i]
		}
	}

	newScope := func(m *MethodNode, isPrivate bool) *rabinScope {
		sc := &rabinScope{method: m, isPrivate: isPrivate, params: map[string]int{},
			bindings: map[string][]Expression{}, mutated: map[string]bool{}, declared: map[string]bool{}}
		for i, p := range m.Params {
			sc.params[p.Name] = i
		}
		visitExpr := func(e Expression) {
			walkExpr(e, func(x Expression) {
				switch v := x.(type) {
				case IncrementExpr:
					if id, ok := v.Operand.(Identifier); ok {
						sc.mutated[id.Name] = true
					}
				case DecrementExpr:
					if id, ok := v.Operand.(Identifier); ok {
						sc.mutated[id.Name] = true
					}
				}
			})
		}
		var visit func(stmts []Statement)
		visit = func(stmts []Statement) {
			for _, stmt := range stmts {
				switch st := stmt.(type) {
				case VariableDeclStmt:
					sc.declared[st.Name] = true
					sc.bindings[st.Name] = append(sc.bindings[st.Name], st.Init)
					visitExpr(st.Init)
				case AssignmentStmt:
					if id, ok := st.Target.(Identifier); ok {
						sc.bindings[id.Name] = append(sc.bindings[id.Name], st.Value)
					}
					visitExpr(st.Target)
					visitExpr(st.Value)
				case ExpressionStmt:
					visitExpr(st.Expr)
				case IfStmt:
					visitExpr(st.Condition)
					visit(st.Then)
					visit(st.Else)
				case ForStmt:
					visit([]Statement{st.Init})
					visitExpr(st.Condition)
					if st.Update != nil {
						visit([]Statement{st.Update})
					}
					visit(st.Body)
				case ReturnStmt:
					if st.Value != nil {
						visitExpr(st.Value)
					}
				}
			}
		}
		visit(m.Body)
		return sc
	}

	scopes := []*rabinScope{newScope(&contract.Constructor, false)}
	for i := range contract.Methods {
		scopes = append(scopes, newScope(&contract.Methods[i], contract.Methods[i].Visibility == "private"))
	}

	trusted := map[string]map[int]bool{}
	for name := range private {
		trusted[name] = map[int]bool{}
	}

	var isTrusted func(e Expression, sc *rabinScope, visiting map[string]bool) bool
	isTrusted = func(e Expression, sc *rabinScope, visiting map[string]bool) bool {
		switch v := e.(type) {
		case PropertyAccessExpr:
			return true
		case MemberExpr:
			id, ok := v.Object.(Identifier)
			return ok && id.Name == "this"
		case BigIntLiteral:
			return true
		case Identifier:
			name := v.Name
			idx, isParam := sc.params[name]
			locals, isLocal := sc.bindings[name]
			if !isParam && !isLocal {
				return props[name]
			}
			if sc.mutated[name] {
				return false
			}
			if isParam {
				if !sc.isPrivate || !trusted[sc.method.Name][idx] {
					return false
				}
			}
			if isLocal {
				if visiting[name] {
					return false
				}
				visiting[name] = true
				defer delete(visiting, name)
				for _, b := range locals {
					if !isTrusted(b, sc, visiting) {
						return false
					}
				}
			}
			return true
		default:
			return false
		}
	}

	privateCallee := func(e Expression) (string, []Expression, bool) {
		call, ok := e.(CallExpr)
		if !ok {
			return "", nil, false
		}
		name := ""
		switch c := call.Callee.(type) {
		case PropertyAccessExpr:
			name = c.Property
		case MemberExpr:
			if id, ok := c.Object.(Identifier); ok && id.Name == "this" {
				name = c.Property
			}
		}
		if _, ok := private[name]; name == "" || !ok {
			return "", nil, false
		}
		return name, call.Args, true
	}

	sites := map[string][]rabinCallSite{}
	for _, sc := range scopes {
		sc := sc
		walkRabinBodyDeep(sc.method.Body, sc.method.SourceLocation, func(e Expression, _ SourceLocation) {
			if name, args, ok := privateCallee(e); ok {
				sites[name] = append(sites[name], rabinCallSite{args: args, scope: sc})
			}
		})
	}

	// Least fixed point; monotone, so it terminates.
	for changed := true; changed; {
		changed = false
		for name, m := range private {
			ss := sites[name]
			if len(ss) == 0 {
				continue
			}
			for i := range m.Params {
				if trusted[name][i] {
					continue
				}
				all := true
				for _, site := range ss {
					if i >= len(site.args) || !isTrusted(site.args[i], site.scope, map[string]bool{}) {
						all = false
						break
					}
				}
				if all {
					trusted[name][i] = true
					changed = true
				}
			}
		}
	}

	for _, sc := range scopes {
		sc := sc
		walkRabinBodyDeep(sc.method.Body, sc.method.SourceLocation, func(e Expression, loc SourceLocation) {
			call, ok := e.(CallExpr)
			if !ok {
				return
			}
			id, ok := call.Callee.(Identifier)
			if !ok || id.Name != "verifyRabinSig" || len(call.Args) < 4 {
				return
			}
			if !isTrusted(call.Args[3], sc, map[string]bool{}) {
				l := loc
				ctx.addErrorWithLoc(RabinPubKeyProvenanceMessage, &l)
			}
		})
	}

	// N-205 (a): a MUTABLE property used as the key is state the previous
	// spend chose, so outside the constructor it may only be written with a
	// value isTrusted accepts. KEY properties: those whose value reaches a 4th
	// argument, closed under "is written into a key property".
	var sourcesOf func(e Expression, sc *rabinScope, out map[string]bool, visiting map[string]bool)
	sourcesOf = func(e Expression, sc *rabinScope, out map[string]bool, visiting map[string]bool) {
		switch v := e.(type) {
		case PropertyAccessExpr:
			out[v.Property] = true
		case MemberExpr:
			if id, ok := v.Object.(Identifier); ok && id.Name == "this" {
				out[v.Property] = true
			}
		case Identifier:
			name := v.Name
			idx, isParam := sc.params[name]
			locals, isLocal := sc.bindings[name]
			if !isParam && !isLocal {
				if props[name] {
					out[name] = true
				}
				return
			}
			key := sc.method.Name + "\x00" + name
			if visiting[key] {
				return
			}
			visiting[key] = true
			for _, b := range locals {
				sourcesOf(b, sc, out, visiting)
			}
			if isParam && sc.isPrivate {
				for _, site := range sites[sc.method.Name] {
					if idx < len(site.args) {
						sourcesOf(site.args[idx], site.scope, out, visiting)
					}
				}
			}
		}
	}

	keyProps := map[string]bool{}
	for _, sc := range scopes {
		sc := sc
		walkRabinBodyDeep(sc.method.Body, sc.method.SourceLocation, func(e Expression, _ SourceLocation) {
			call, ok := e.(CallExpr)
			if !ok {
				return
			}
			if id, ok := call.Callee.(Identifier); ok && id.Name == "verifyRabinSig" && len(call.Args) >= 4 {
				sourcesOf(call.Args[3], sc, keyProps, map[string]bool{})
			}
		})
	}

	// Every write to a property outside the constructor; value is nil for
	// ++/--, which no value makes trusted.
	type propWrite struct {
		prop  string
		value Expression
		scope *rabinScope
		loc   SourceLocation
	}
	var writes []propWrite
	var mutableProps []string
	mutable := map[string]bool{}
	for _, p := range contract.Properties {
		if !p.Readonly {
			mutableProps = append(mutableProps, p.Name)
			mutable[p.Name] = true
		}
	}
	writtenProp := func(target Expression, sc *rabinScope) (string, bool) {
		switch v := target.(type) {
		case PropertyAccessExpr:
			return v.Property, true
		case MemberExpr:
			if id, ok := v.Object.(Identifier); ok && id.Name == "this" {
				return v.Property, true
			}
		case Identifier:
			_, isParam := sc.params[v.Name]
			if props[v.Name] && !isParam && !sc.declared[v.Name] {
				return v.Name, true
			}
		}
		return "", false
	}
	var collectAssignments func(stmts []Statement, sc *rabinScope)
	collectAssignments = func(stmts []Statement, sc *rabinScope) {
		for _, stmt := range stmts {
			switch st := stmt.(type) {
			case AssignmentStmt:
				if prop, ok := writtenProp(st.Target, sc); ok {
					writes = append(writes, propWrite{prop, st.Value, sc, st.SourceLocation})
				}
			case IfStmt:
				collectAssignments(st.Then, sc)
				collectAssignments(st.Else, sc)
			case ForStmt:
				collectAssignments([]Statement{st.Init}, sc)
				if st.Update != nil {
					collectAssignments([]Statement{st.Update}, sc)
				}
				collectAssignments(st.Body, sc)
			}
		}
	}
	for _, sc := range scopes {
		sc := sc
		if sc.method == &contract.Constructor {
			continue
		}
		collectAssignments(sc.method.Body, sc)
		walkRabinBodyDeep(sc.method.Body, sc.method.SourceLocation, func(e Expression, loc SourceLocation) {
			switch v := e.(type) {
			case IncrementExpr:
				if prop, ok := writtenProp(v.Operand, sc); ok {
					writes = append(writes, propWrite{prop, nil, sc, loc})
				}
			case DecrementExpr:
				if prop, ok := writtenProp(v.Operand, sc); ok {
					writes = append(writes, propWrite{prop, nil, sc, loc})
				}
			case CallExpr:
				name := ""
				switch c := v.Callee.(type) {
				case PropertyAccessExpr:
					name = c.Property
				case MemberExpr:
					name = c.Property
				}
				if name != "addOutput" {
					return
				}
				// addOutput(satoshis, ...values): values are positional over
				// the mutable properties in declaration order. A single
				// array-literal value list (the Zig tuple form) is unpacked,
				// as ANF lowering's flattenAddOutputArgs does.
				args := flattenAddOutputArgs(v.Args)
				for i := 1; i < len(args); i++ {
					if i-1 < len(mutableProps) {
						writes = append(writes, propWrite{mutableProps[i-1], args[i], sc, loc})
					}
				}
			}
		})
	}

	for grew := true; grew; {
		before := len(keyProps)
		for _, w := range writes {
			if keyProps[w.prop] && w.value != nil && isTrusted(w.value, w.scope, map[string]bool{}) {
				sourcesOf(w.value, w.scope, keyProps, map[string]bool{})
			}
		}
		grew = len(keyProps) != before
	}

	for _, w := range writes {
		if !keyProps[w.prop] || !mutable[w.prop] {
			continue
		}
		if w.value != nil && isTrusted(w.value, w.scope, map[string]bool{}) {
			continue
		}
		l := w.loc
		ctx.addErrorWithLoc(RabinKeyWriteMessage(w.prop), &l)
	}
}

// RabinKeyWriteMessage is the N-205 (a) diagnostic every tier emits when a
// mutable key property is written, outside the constructor, with a value the
// F-286 rule does not trust.
func RabinKeyWriteMessage(prop string) string {
	return "verifyRabinSig public key property '" + prop + "' may only be assigned a contract property or a literal " +
		"outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature"
}

// walkRabinBodyDeep visits every expression in stmts, including every for
// loop's init and update at any depth, with the enclosing statement's location.
func walkRabinBodyDeep(stmts []Statement, fallback SourceLocation, visitor func(Expression, SourceLocation)) {
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case ExpressionStmt:
			walkExpr(s.Expr, func(e Expression) { visitor(e, s.SourceLocation) })
		case VariableDeclStmt:
			walkExpr(s.Init, func(e Expression) { visitor(e, s.SourceLocation) })
		case AssignmentStmt:
			walkExpr(s.Target, func(e Expression) { visitor(e, s.SourceLocation) })
			walkExpr(s.Value, func(e Expression) { visitor(e, s.SourceLocation) })
		case IfStmt:
			walkExpr(s.Condition, func(e Expression) { visitor(e, s.SourceLocation) })
			walkRabinBodyDeep(s.Then, fallback, visitor)
			walkRabinBodyDeep(s.Else, fallback, visitor)
		case ForStmt:
			walkRabinBodyDeep([]Statement{s.Init}, fallback, visitor)
			walkExpr(s.Condition, func(e Expression) { visitor(e, s.SourceLocation) })
			if s.Update != nil {
				walkRabinBodyDeep([]Statement{s.Update}, fallback, visitor)
			}
			walkRabinBodyDeep(s.Body, fallback, visitor)
		case ReturnStmt:
			if s.Value != nil {
				walkExpr(s.Value, func(e Expression) { visitor(e, s.SourceLocation) })
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Recursion detection
// ---------------------------------------------------------------------------

// checkNoRecursion reports recursion and the N-180 call depth; it returns true
// iff MaxCallDepth was exceeded.
func (ctx *validationContext) checkNoRecursion() bool {
	callGraph := make(map[string]map[string]bool)
	methodNames := make(map[string]bool)

	for _, method := range ctx.contract.Methods {
		methodNames[method.Name] = true
		calls := make(map[string]bool)
		collectMethodCalls(method.Body, calls, true)
		callGraph[method.Name] = calls
	}

	// N-180: one iterative pass answers, for every method, whether it reaches
	// a cycle and how deep its call chain is, in O(methods + calls). The old
	// per-method DFS restarted for each method (quadratic on a chain).
	reachesCycle, depth := analyzeCallGraph(ctx.contract.Methods, callGraph, methodNames)

	for _, method := range ctx.contract.Methods {
		if reachesCycle[method.Name] {
			ctx.addErrorWithLoc(fmt.Sprintf("recursion detected: method '%s' calls itself directly or indirectly", method.Name), &method.SourceLocation)
		}
	}

	// N-180: private methods are inlined at every call site, so the call depth
	// is the inlining depth. Report the first method (declaration order) past it.
	for _, method := range ctx.contract.Methods {
		if !reachesCycle[method.Name] && depth[method.Name] > MaxCallDepth {
			ctx.addErrorWithLoc(CallDepthMessage(method.Name), &method.SourceLocation)
			return true
		}
	}
	return false
}

// analyzeCallGraph (N-180) returns, for every method, whether it reaches a
// call cycle, and (when it does not) its call depth: 0 if it calls no contract
// method, else 1 + the largest call depth among the contract methods it calls.
// Iterative three-colour DFS with memoisation: O(methods + calls), no
// recursion. reachesCycle matches what a fresh DFS from each method reports.
func analyzeCallGraph(methods []MethodNode, callGraph map[string]map[string]bool, methodNames map[string]bool) (map[string]bool, map[string]int) {
	type frame struct {
		name    string
		callees []string
		next    int
		cyc     bool
		depth   int
	}
	reachesCycle := make(map[string]bool, len(methodNames))
	depth := make(map[string]int, len(methodNames))
	done := make(map[string]bool, len(methodNames))
	onStack := make(map[string]bool)

	for _, root := range methods {
		if done[root.Name] {
			continue
		}
		var stack []*frame
		push := func(name string) {
			onStack[name] = true
			callees := make([]string, 0, len(callGraph[name]))
			for c := range callGraph[name] {
				callees = append(callees, c)
			}
			stack = append(stack, &frame{name: name, callees: callees})
		}
		push(root.Name)
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			if top.next < len(top.callees) {
				callee := top.callees[top.next]
				top.next++
				switch {
				case !methodNames[callee]:
				case onStack[callee]:
					top.cyc = true
				case done[callee]:
					if reachesCycle[callee] {
						top.cyc = true
					} else if d := 1 + depth[callee]; d > top.depth {
						top.depth = d
					}
				default:
					push(callee)
				}
				continue
			}
			stack = stack[:len(stack)-1]
			delete(onStack, top.name)
			done[top.name] = true
			reachesCycle[top.name] = top.cyc
			depth[top.name] = top.depth
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				if top.cyc {
					parent.cyc = true
				} else if d := 1 + top.depth; d > parent.depth {
					parent.depth = d
				}
			}
		}
	}
	return reachesCycle, depth
}

func collectMethodCalls(stmts []Statement, calls map[string]bool, bare bool) {
	for _, stmt := range stmts {
		collectMethodCallsInStmt(stmt, calls, bare)
	}
}

func collectMethodCallsInStmt(stmt Statement, calls map[string]bool, bare bool) {
	switch s := stmt.(type) {
	case ExpressionStmt:
		collectMethodCallsInExpr(s.Expr, calls, bare)
	case VariableDeclStmt:
		collectMethodCallsInExpr(s.Init, calls, bare)
	case AssignmentStmt:
		collectMethodCallsInExpr(s.Target, calls, bare)
		collectMethodCallsInExpr(s.Value, calls, bare)
	case IfStmt:
		collectMethodCallsInExpr(s.Condition, calls, bare)
		collectMethodCalls(s.Then, calls, bare)
		collectMethodCalls(s.Else, calls, bare)
	case ForStmt:
		collectMethodCallsInExpr(s.Condition, calls, bare)
		collectMethodCalls(s.Body, calls, bare)
	case ReturnStmt:
		if s.Value != nil {
			collectMethodCallsInExpr(s.Value, calls, bare)
		}
	}
}

func collectMethodCallsInExpr(expr Expression, calls map[string]bool, bare bool) {
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
		// N-180: the Solidity, Move and Java surfaces may call a helper as a
		// bare `m(...)`. Counted only for the recursion / call-depth graph
		// (bare), and only names of contract methods count there
		// (analyzeCallGraph filters by methodNames), so builtins are unaffected.
		if id, ok := e.Callee.(Identifier); ok && bare {
			calls[id.Name] = true
		}
		collectMethodCallsInExpr(e.Callee, calls, bare)
		for _, arg := range e.Args {
			collectMethodCallsInExpr(arg, calls, bare)
		}
	case BinaryExpr:
		collectMethodCallsInExpr(e.Left, calls, bare)
		collectMethodCallsInExpr(e.Right, calls, bare)
	case UnaryExpr:
		collectMethodCallsInExpr(e.Operand, calls, bare)
	case MemberExpr:
		collectMethodCallsInExpr(e.Object, calls, bare)
	case TernaryExpr:
		collectMethodCallsInExpr(e.Condition, calls, bare)
		collectMethodCallsInExpr(e.Consequent, calls, bare)
		collectMethodCallsInExpr(e.Alternate, calls, bare)
	case IndexAccessExpr:
		collectMethodCallsInExpr(e.Object, calls, bare)
		collectMethodCallsInExpr(e.Index, calls, bare)
	case IncrementExpr:
		collectMethodCallsInExpr(e.Operand, calls, bare)
	case DecrementExpr:
		collectMethodCallsInExpr(e.Operand, calls, bare)
	case ArrayLiteralExpr:
		for _, el := range e.Elements {
			collectMethodCallsInExpr(el, calls, bare)
		}
	}
}
