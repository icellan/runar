package frontend

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// LowerToANF lowers a type-checked Rúnar AST to the ANF IR.
// This matches the TypeScript reference compiler's 04-anf-lower.ts exactly.
func LowerToANF(contract *ContractNode) *ir.ANFProgram {
	properties := lowerProperties(contract)
	methods := lowerMethods(contract)

	// Post-pass: lift update_prop from if-else branches into flat conditionals.
	// This prevents phantom stack entries in stack lowering for patterns like
	// position dispatch (different properties updated in different branches).
	// Mirrors the TS reference compiler's liftBranchUpdateProps (04-anf-lower.ts line 50).
	for i := range methods {
		methods[i].Body = liftBranchUpdateProps(methods[i].Body)
	}

	return &ir.ANFProgram{
		ContractName: contract.Name,
		Properties:   properties,
		Methods:      methods,
	}
}

var byteTypes = map[string]bool{
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
}

var byteReturningFunctions = map[string]bool{
	"sha256":       true,
	"ripemd160":    true,
	"hash160":      true,
	"hash256":      true,
	"cat":          true,
	"substr":       true,
	"num2bin":      true,
	"reverseBytes": true,
	"left":         true,
	"right":        true,
	"int2str":      true,
	"toByteString":       true,
	"pack":               true,
	"ecAdd":              true,
	"ecMul":              true,
	"ecMulGen":           true,
	"ecNegate":           true,
	"ecMakePoint":        true,
	"ecEncodeCompressed": true,
	"sha256Compress":     true,
	"sha256Finalize":     true,
	"blake3Compress":     true,
	"blake3Hash":         true,
}

func isByteTypedExpr(expr Expression, ctx *lowerCtx) bool {
	switch e := expr.(type) {
	case ByteStringLiteral:
		return true

	case Identifier:
		if t, ok := ctx.getParamType(e.Name); ok && byteTypes[t] {
			return true
		}
		if t, ok := ctx.getPropertyType(e.Name); ok && byteTypes[t] {
			return true
		}
		if ctx.localByteVars[e.Name] {
			return true
		}
		return false

	case PropertyAccessExpr:
		if t, ok := ctx.getPropertyType(e.Property); ok && byteTypes[t] {
			return true
		}
		return false

	case MemberExpr:
		if id, ok := e.Object.(Identifier); ok && id.Name == "this" {
			if t, found := ctx.getPropertyType(e.Property); found && byteTypes[t] {
				return true
			}
		}
		return false

	case CallExpr:
		if id, ok := e.Callee.(Identifier); ok {
			if byteReturningFunctions[id.Name] {
				return true
			}
			if len(id.Name) >= 7 && id.Name[:7] == "extract" {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

func lowerProperties(contract *ContractNode) []ir.ANFProperty {
	props := make([]ir.ANFProperty, len(contract.Properties))
	for i, prop := range contract.Properties {
		props[i] = ir.ANFProperty{
			Name:     prop.Name,
			Type:     typeNodeToString(prop.Type),
			Readonly: prop.Readonly,
		}
		if prop.Initializer != nil {
			props[i].InitialValue = extractLiteralValue(prop.Initializer)
		}
		if len(prop.SyntheticArrayChain) > 0 {
			chain := make([]ir.ANFSyntheticArrayLevel, len(prop.SyntheticArrayChain))
			for k, lvl := range prop.SyntheticArrayChain {
				chain[k] = ir.ANFSyntheticArrayLevel{
					Base:   lvl.Base,
					Index:  lvl.Index,
					Length: lvl.Length,
				}
			}
			props[i].SyntheticArrayChain = chain
		}
	}
	return props
}

func extractLiteralValue(expr Expression) interface{} {
	switch e := expr.(type) {
	case BigIntLiteral:
		return e.Value
	case BoolLiteral:
		return e.Value
	case ByteStringLiteral:
		return e.Value
	case UnaryExpr:
		if e.Op == "-" {
			if lit, ok := e.Operand.(BigIntLiteral); ok {
				return new(big.Int).Neg(lit.Value)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

func lowerMethods(contract *ContractNode) []ir.ANFMethod {
	var result []ir.ANFMethod

	// Lower constructor (the TS reference includes the constructor in output)
	ctorCtx := newLowerCtx(contract)
	ctorCtx.lowerStatements(contract.Constructor.Body)
	result = append(result, ir.ANFMethod{
		Name:     "constructor",
		Params:   lowerParams(contract.Constructor.Params),
		Body:     ctorCtx.bindings,
		IsPublic: false,
	})

	// Lower each method (including private methods as separate entries)
	for _, method := range contract.Methods {
		methodCtx := newLowerCtx(contract)

		if contract.ParentClass == "StatefulSmartContract" && method.Visibility == "public" {
			// Determine if this method verifies hashOutputs (needs change output support).
			// Methods that use addOutput or mutate state need hashOutputs verification.
			// Non-mutating methods (like close/destroy) don't verify outputs.
			needsChangeOutput := methodMutatesState(method, contract) || methodHasAddOutput(method)

			// Single-output continuation needs _newAmount to allow changing the UTXO satoshis.
			// Multi-output (addOutput) methods already specify amounts explicitly per output.
			needsNewAmount := methodMutatesState(method, contract) && !methodHasAddOutput(method)

			// Register implicit parameters
			if needsChangeOutput {
				methodCtx.addParam("_changePKH")
				methodCtx.addParam("_changeAmount")
			}
			if needsNewAmount {
				methodCtx.addParam("_newAmount")
			}
			methodCtx.addParam("txPreimage")

			// Inject checkPreimage(txPreimage) at the start
			preimageRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			checkResult := methodCtx.emit(ir.ANFValue{Kind: "check_preimage", Preimage: preimageRef})
			methodCtx.emit(makeAssert(checkResult))

			// Deserialize mutable state from the preimage's scriptCode.
			// On subsequent spends, the state is embedded in the script (after OP_RETURN),
			// so we extract it from the scriptCode field rather than using hardcoded initial values.
			hasStateProp := false
			for _, p := range contract.Properties {
				if !p.Readonly {
					hasStateProp = true
					break
				}
			}
			if hasStateProp {
				preimageRef3 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
				methodCtx.emit(ir.ANFValue{Kind: "deserialize_state", Preimage: preimageRef3})
			}

			// Lower the developer's method body
			methodCtx.lowerStatements(method.Body)

			// Determine state continuation type
			addOutputRefs := methodCtx.getAddOutputRefs()
			if len(addOutputRefs) > 0 || methodMutatesState(method, contract) {
				// Build the P2PKH change output for hashOutputs verification
				changePKHRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "_changePKH"})
				changeAmountRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "_changeAmount"})
				changeOutputRef := methodCtx.emit(makeCall("buildChangeOutput", []string{changePKHRef, changeAmountRef}))

				if len(addOutputRefs) > 0 {
					// Multi-output continuation: concat all outputs + change output, hash
					accumulated := addOutputRefs[0]
					for i := 1; i < len(addOutputRefs); i++ {
						accumulated = methodCtx.emit(makeCall("cat", []string{accumulated, addOutputRefs[i]}))
					}
					accumulated = methodCtx.emit(makeCall("cat", []string{accumulated, changeOutputRef}))
					hashRef := methodCtx.emit(makeCall("hash256", []string{accumulated}))
					preimageRef2 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
					outputHashRef := methodCtx.emit(makeCall("extractOutputHash", []string{preimageRef2}))
					eqRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: hashRef, Right: outputHashRef, ResultType: "bytes"})
					methodCtx.emit(makeAssert(eqRef))
				} else {
					// Single-output continuation: build raw output bytes, concat with change, hash
					stateScriptRef := methodCtx.emit(ir.ANFValue{Kind: "get_state_script"})
					preimageRef2 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
					newAmountRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "_newAmount"})
					contractOutputRef := methodCtx.emit(makeCall("computeStateOutput", []string{preimageRef2, stateScriptRef, newAmountRef}))
					allOutputs := methodCtx.emit(makeCall("cat", []string{contractOutputRef, changeOutputRef}))
					hashRef := methodCtx.emit(makeCall("hash256", []string{allOutputs}))
					preimageRef4 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
					outputHashRef := methodCtx.emit(makeCall("extractOutputHash", []string{preimageRef4}))
					eqRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: hashRef, Right: outputHashRef, ResultType: "bytes"})
					methodCtx.emit(makeAssert(eqRef))
				}
			}

			// Build augmented params list for ABI
			augmentedParams := lowerParams(method.Params)
			if needsChangeOutput {
				augmentedParams = append(augmentedParams,
					ir.ANFParam{Name: "_changePKH", Type: "Ripemd160"},
					ir.ANFParam{Name: "_changeAmount", Type: "bigint"},
				)
			}
			if needsNewAmount {
				augmentedParams = append(augmentedParams, ir.ANFParam{Name: "_newAmount", Type: "bigint"})
			}
			augmentedParams = append(augmentedParams, ir.ANFParam{
				Name: "txPreimage",
				Type: "SigHashPreimage",
			})

			result = append(result, ir.ANFMethod{
				Name:     method.Name,
				Params:   augmentedParams,
				Body:     methodCtx.bindings,
				IsPublic: true,
			})
		} else {
			methodCtx.lowerStatements(method.Body)
			result = append(result, ir.ANFMethod{
				Name:     method.Name,
				Params:   lowerParams(method.Params),
				Body:     methodCtx.bindings,
				IsPublic: method.Visibility == "public",
			})
		}
	}

	return result
}

func lowerParams(params []ParamNode) []ir.ANFParam {
	result := make([]ir.ANFParam, len(params))
	for i, p := range params {
		result[i] = ir.ANFParam{
			Name: p.Name,
			Type: typeNodeToString(p.Type),
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Lowering context: manages temp variable generation
//
// Mirrors the TypeScript LoweringContext class exactly:
// - No parameter pre-loading (params are loaded lazily on first reference)
// - addParam is never called (matching TS where addParam exists but is unused)
// - Local variables are tracked via localNames set
// - Properties are checked against the contract
// ---------------------------------------------------------------------------

type lowerCtx struct {
	bindings         []ir.ANFBinding
	counter          int
	contract         *ContractNode
	localNames       map[string]bool   // tracks variable names registered via addLocal
	paramNames       map[string]bool   // tracks parameter names registered via addParam
	addOutputRefs    []string          // tracks addOutput binding refs for multi-output continuation
	localAliases     map[string]string // maps local variable names to their current ANF binding name (updated after if-statements that reassign locals in both branches)
	localByteVars    map[string]bool   // tracks local variables known to be byte-typed
	currentSourceLoc *ir.SourceLocation // Debug: source location to attach to emitted ANF bindings
}

func newLowerCtx(contract *ContractNode) *lowerCtx {
	return &lowerCtx{
		contract:      contract,
		localNames:    make(map[string]bool),
		paramNames:    make(map[string]bool),
		localAliases:  make(map[string]string),
		localByteVars: make(map[string]bool),
	}
}

// freshTemp generates a fresh temporary variable name.
func (ctx *lowerCtx) freshTemp() string {
	name := fmt.Sprintf("t%d", ctx.counter)
	ctx.counter++
	return name
}

// emit appends a binding and returns the name of the temp variable.
func (ctx *lowerCtx) emit(value ir.ANFValue) string {
	name := ctx.freshTemp()
	binding := ir.ANFBinding{Name: name, Value: value}
	if ctx.currentSourceLoc != nil {
		binding.SourceLoc = ctx.currentSourceLoc
	}
	ctx.bindings = append(ctx.bindings, binding)
	return name
}

// emitNamed appends a binding with a specific name (for named variables).
func (ctx *lowerCtx) emitNamed(name string, value ir.ANFValue) {
	binding := ir.ANFBinding{Name: name, Value: value}
	if ctx.currentSourceLoc != nil {
		binding.SourceLoc = ctx.currentSourceLoc
	}
	ctx.bindings = append(ctx.bindings, binding)
}

// addLocal records a local variable name.
func (ctx *lowerCtx) addLocal(name string) {
	ctx.localNames[name] = true
}

// isLocal checks if a name is a registered local variable.
func (ctx *lowerCtx) isLocal(name string) bool {
	return ctx.localNames[name]
}

// addParam records a parameter name so we know to use load_param for it.
func (ctx *lowerCtx) addParam(name string) {
	ctx.paramNames[name] = true
}

// isParam checks if a name is a registered parameter.
func (ctx *lowerCtx) isParam(name string) bool {
	return ctx.paramNames[name]
}

// setLocalAlias sets the current ANF binding for a local variable (after if-statement reassignment).
func (ctx *lowerCtx) setLocalAlias(localName, bindingName string) {
	ctx.localAliases[localName] = bindingName
}

// getLocalAlias returns the current ANF binding for a local variable, or "" if not aliased.
func (ctx *lowerCtx) getLocalAlias(localName string) string {
	return ctx.localAliases[localName]
}

// addOutputRef tracks an addOutput binding ref for multi-output continuation.
func (ctx *lowerCtx) addOutputRef(ref string) {
	ctx.addOutputRefs = append(ctx.addOutputRefs, ref)
}

// getAddOutputRefs returns all addOutput refs collected during lowering.
func (ctx *lowerCtx) getAddOutputRefs() []string {
	return ctx.addOutputRefs
}

// isProperty checks if a name is a contract property.
// isPrivateMethod reports whether `name` is a private (non-public) method
// on the contract — matching the TypeScript compiler's check used for
// routing bare-identifier calls through the method_call inlining path.
func (ctx *lowerCtx) isPrivateMethod(name string) bool {
	for _, m := range ctx.contract.Methods {
		if m.Name == name && m.Visibility != "public" && m.Name != "constructor" {
			return true
		}
	}
	return false
}

func (ctx *lowerCtx) isProperty(name string) bool {
	for _, p := range ctx.contract.Properties {
		if p.Name == name {
			return true
		}
	}
	return false
}

func (ctx *lowerCtx) getParamType(name string) (string, bool) {
	for _, p := range ctx.contract.Constructor.Params {
		if p.Name == name {
			return typeNodeToString(p.Type), true
		}
	}
	for _, method := range ctx.contract.Methods {
		for _, p := range method.Params {
			if p.Name == name {
				return typeNodeToString(p.Type), true
			}
		}
	}
	return "", false
}

func (ctx *lowerCtx) getPropertyType(name string) (string, bool) {
	for _, p := range ctx.contract.Properties {
		if p.Name == name {
			return typeNodeToString(p.Type), true
		}
	}
	return "", false
}

// subContext creates a sub-context for nested blocks (if/else, loops).
// The counter continues from the parent. Local names and param names are shared.
func (ctx *lowerCtx) subContext() *lowerCtx {
	sub := &lowerCtx{
		contract:      ctx.contract,
		counter:       ctx.counter,
		localNames:    make(map[string]bool),
		paramNames:    make(map[string]bool),
		localAliases:  make(map[string]string),
		localByteVars: make(map[string]bool),
	}
	// Share local name set
	for k := range ctx.localNames {
		sub.localNames[k] = true
	}
	// Share param name set
	for k := range ctx.paramNames {
		sub.paramNames[k] = true
	}
	// Share local byte var set
	for k := range ctx.localByteVars {
		sub.localByteVars[k] = true
	}
	// Share local aliases
	for k, v := range ctx.localAliases {
		sub.localAliases[k] = v
	}
	return sub
}

// syncCounter brings the parent's counter up to the sub's counter value.
func (ctx *lowerCtx) syncCounter(sub *lowerCtx) {
	if sub.counter > ctx.counter {
		ctx.counter = sub.counter
	}
}

// ---------------------------------------------------------------------------
// Statement lowering
// ---------------------------------------------------------------------------

func (ctx *lowerCtx) lowerStatements(stmts []Statement) {
	for i, stmt := range stmts {
		// Early-return nesting: when an if-statement's then-block ends with a
		// return and there is no else-branch, the remaining statements after the
		// if are unreachable from the then-branch. Nest them into the else-branch
		// so that only one value ends up on the stack (the return value from
		// whichever branch executes). Without this, both branches produce values
		// and the stack becomes misaligned.
		if ifStmt, ok := stmt.(IfStmt); ok &&
			len(ifStmt.Else) == 0 &&
			i+1 < len(stmts) &&
			branchEndsWithReturn(ifStmt.Then) {
			remaining := stmts[i+1:]
			modifiedIf := IfStmt{
				Condition:      ifStmt.Condition,
				Then:           ifStmt.Then,
				Else:           remaining,
				SourceLocation: ifStmt.SourceLocation,
			}
			ctx.lowerStatement(modifiedIf)
			return // remaining stmts are now inside the else branch
		}

		ctx.lowerStatement(stmt)
	}
}

// branchEndsWithReturn checks whether a statement list always terminates with a return.
func branchEndsWithReturn(stmts []Statement) bool {
	if len(stmts) == 0 {
		return false
	}
	last := stmts[len(stmts)-1]
	if _, ok := last.(ReturnStmt); ok {
		return true
	}
	// Also handle if-else where both branches return
	if ifStmt, ok := last.(IfStmt); ok && len(ifStmt.Else) > 0 {
		return branchEndsWithReturn(ifStmt.Then) && branchEndsWithReturn(ifStmt.Else)
	}
	return false
}

func (ctx *lowerCtx) lowerStatement(stmt Statement) {
	// Propagate source location to emitted ANF bindings
	ctx.currentSourceLoc = stmtSourceLoc(stmt)
	defer func() { ctx.currentSourceLoc = nil }()

	switch s := stmt.(type) {
	case VariableDeclStmt:
		ctx.lowerVariableDecl(s)
	case AssignmentStmt:
		ctx.lowerAssignment(s)
	case IfStmt:
		ctx.lowerIfStatement(s)
	case ForStmt:
		ctx.lowerForStatement(s)
	case ExpressionStmt:
		ctx.lowerExprToRef(s.Expr)
	case ReturnStmt:
		if s.Value != nil {
			ref := ctx.lowerExprToRef(s.Value)
			// If the returned ref is not the name of the last emitted binding, emit
			// an explicit load so the return value is the last (top-of-stack) binding.
			// This matters when a local variable is returned after control flow (e.g.,
			// `let count = 0n; if (...) { count += 1n; } return count;`). Without
			// this, the last binding is the if, not `count`, so inlineMethodCall in
			// stack lowering can't find the return value.
			if len(ctx.bindings) > 0 && ctx.bindings[len(ctx.bindings)-1].Name != ref {
				ctx.emit(makeLoadConstString("@ref:" + ref))
			}
		}
	}
}

// stmtSourceLoc extracts the SourceLocation from a concrete statement type
// and converts it to an ir.SourceLocation pointer (nil if the location is empty).
func stmtSourceLoc(stmt Statement) *ir.SourceLocation {
	var loc SourceLocation
	switch s := stmt.(type) {
	case VariableDeclStmt:
		loc = s.SourceLocation
	case AssignmentStmt:
		loc = s.SourceLocation
	case IfStmt:
		loc = s.SourceLocation
	case ForStmt:
		loc = s.SourceLocation
	case ReturnStmt:
		loc = s.SourceLocation
	case ExpressionStmt:
		loc = s.SourceLocation
	default:
		return nil
	}
	if loc.File == "" && loc.Line == 0 && loc.Column == 0 {
		return nil
	}
	return &ir.SourceLocation{File: loc.File, Line: loc.Line, Column: loc.Column}
}

// lowerVariableDecl matches the TS reference:
// Lower the init expression, register the variable as local, then emit
// a named binding that aliases the variable to the computed value via @ref.
func (ctx *lowerCtx) lowerVariableDecl(stmt VariableDeclStmt) {
	valueRef := ctx.lowerExprToRef(stmt.Init)
	ctx.addLocal(stmt.Name)
	if isByteTypedExpr(stmt.Init, ctx) {
		ctx.localByteVars[stmt.Name] = true
	}
	ctx.emitNamed(stmt.Name, makeLoadConstString("@ref:"+valueRef))
}

// lowerAssignment matches the TS reference:
// For this.x = expr -> emit update_prop
// For local = expr -> emit named binding with @ref alias
func (ctx *lowerCtx) lowerAssignment(stmt AssignmentStmt) {
	valueRef := ctx.lowerExprToRef(stmt.Value)

	// this.x = expr -> update_prop
	if pa, ok := stmt.Target.(PropertyAccessExpr); ok {
		ctx.emit(makeUpdateProp(pa.Property, valueRef))
		return
	}

	// local = expr -> re-bind (emit a new named binding with @ref)
	if id, ok := stmt.Target.(Identifier); ok {
		ctx.emitNamed(id.Name, makeLoadConstString("@ref:"+valueRef))
		return
	}

	// For other targets, lower the target expression
	ctx.lowerExprToRef(stmt.Target)
}

func (ctx *lowerCtx) lowerIfStatement(stmt IfStmt) {
	condRef := ctx.lowerExprToRef(stmt.Condition)

	// Lower then-block into sub-context
	thenCtx := ctx.subContext()
	thenCtx.lowerStatements(stmt.Then)
	ctx.syncCounter(thenCtx)

	// Lower else-block into sub-context
	elseCtx := ctx.subContext()
	if len(stmt.Else) > 0 {
		elseCtx.lowerStatements(stmt.Else)
	}
	ctx.syncCounter(elseCtx)

	elseBindings := elseCtx.bindings
	if elseBindings == nil {
		elseBindings = []ir.ANFBinding{}
	}
	ifName := ctx.emit(ir.ANFValue{
		Kind: "if",
		Cond: condRef,
		Then: thenCtx.bindings,
		Else: elseBindings,
	})

	// Propagate addOutput refs from sub-contexts: when either branch produces
	// addOutput calls, the if-expression result represents each addOutput
	// (only one branch executes at runtime).
	thenOutputRefs := thenCtx.getAddOutputRefs()
	elseOutputRefs := elseCtx.getAddOutputRefs()
	if len(thenOutputRefs) > 0 || len(elseOutputRefs) > 0 {
		ctx.addOutputRef(ifName)
	}

	// If both branches end by reassigning the same local variable,
	// alias that variable to the if-expression result so that subsequent
	// references resolve to the branch output, not the dead initial value.
	if len(thenCtx.bindings) > 0 && len(elseCtx.bindings) > 0 {
		thenLast := thenCtx.bindings[len(thenCtx.bindings)-1]
		elseLast := elseCtx.bindings[len(elseCtx.bindings)-1]
		if thenLast.Name == elseLast.Name && ctx.isLocal(thenLast.Name) {
			ctx.setLocalAlias(thenLast.Name, ifName)
		}
	}
}

func (ctx *lowerCtx) lowerForStatement(stmt ForStmt) {
	count := extractLoopCount(stmt)

	// Lower body into sub-context
	bodyCtx := ctx.subContext()
	bodyCtx.lowerStatements(stmt.Body)
	ctx.syncCounter(bodyCtx)

	ctx.emit(ir.ANFValue{
		Kind:    "loop",
		Count:   count,
		Body:    bodyCtx.bindings,
		IterVar: stmt.Init.Name,
	})
}

func extractLoopCount(stmt ForStmt) int {
	startVal := extractBigIntValue(stmt.Init.Init)

	if bin, ok := stmt.Condition.(BinaryExpr); ok {
		boundVal := extractBigIntValue(bin.Right)

		if startVal != nil && boundVal != nil {
			start := startVal.Int64()
			bound := boundVal.Int64()
			switch bin.Op {
			case "<":
				v := int(bound - start)
				if v < 0 {
					v = 0
				}
				return v
			case "<=":
				v := int(bound - start + 1)
				if v < 0 {
					v = 0
				}
				return v
			case ">":
				v := int(start - bound)
				if v < 0 {
					v = 0
				}
				return v
			case ">=":
				v := int(start - bound + 1)
				if v < 0 {
					v = 0
				}
				return v
			}
		}

		if boundVal != nil {
			bound := boundVal.Int64()
			switch bin.Op {
			case "<":
				return int(bound)
			case "<=":
				return int(bound) + 1
			}
		}
	}

	return 0
}

func extractBigIntValue(expr Expression) *big.Int {
	switch e := expr.(type) {
	case BigIntLiteral:
		return new(big.Int).Set(e.Value)
	case UnaryExpr:
		if e.Op == "-" {
			inner := extractBigIntValue(e.Operand)
			if inner != nil {
				return new(big.Int).Neg(inner)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Expression lowering (the core ANF conversion)
//
// Matches the TypeScript lowerExprToRef exactly.
// ---------------------------------------------------------------------------

func (ctx *lowerCtx) lowerExprToRef(expr Expression) string {
	switch e := expr.(type) {
	case BigIntLiteral:
		return ctx.emit(makeLoadConstInt(e.Value))

	case BoolLiteral:
		return ctx.emit(makeLoadConstBool(e.Value))

	case ByteStringLiteral:
		return ctx.emit(makeLoadConstString(e.Value))

	case Identifier:
		return ctx.lowerIdentifier(e)

	case PropertyAccessExpr:
		// this.txPreimage in StatefulSmartContract -> load_param (it's an implicit param, not a stored property)
		if ctx.isParam(e.Property) {
			return ctx.emit(ir.ANFValue{Kind: "load_param", Name: e.Property})
		}
		// this.x -> load_prop
		return ctx.emit(ir.ANFValue{Kind: "load_prop", Name: e.Property})

	case MemberExpr:
		return ctx.lowerMemberExpr(e)

	case BinaryExpr:
		leftRef := ctx.lowerExprToRef(e.Left)
		rightRef := ctx.lowerExprToRef(e.Right)

		resultType := ""
		if (e.Op == "===" || e.Op == "!==") && (isByteTypedExpr(e.Left, ctx) || isByteTypedExpr(e.Right, ctx)) {
			resultType = "bytes"
		}
		// For +, annotate byte-typed operands so stack lowering can emit OP_CAT.
		if e.Op == "+" && (isByteTypedExpr(e.Left, ctx) || isByteTypedExpr(e.Right, ctx)) {
			resultType = "bytes"
		}
		// For bitwise &, |, ^, annotate byte-typed operands.
		if (e.Op == "&" || e.Op == "|" || e.Op == "^") && (isByteTypedExpr(e.Left, ctx) || isByteTypedExpr(e.Right, ctx)) {
			resultType = "bytes"
		}

		return ctx.emit(ir.ANFValue{Kind: "bin_op", Op: e.Op, Left: leftRef, Right: rightRef, ResultType: resultType})

	case UnaryExpr:
		operandRef := ctx.lowerExprToRef(e.Operand)
		unaryValue := ir.ANFValue{Kind: "unary_op", Op: e.Op, Operand: operandRef}
		// For ~, annotate byte-typed operands so downstream passes know the result is bytes.
		if e.Op == "~" && isByteTypedExpr(e.Operand, ctx) {
			unaryValue.ResultType = "bytes"
		}
		return ctx.emit(unaryValue)

	case CallExpr:
		return ctx.lowerCallExpr(e)

	case TernaryExpr:
		return ctx.lowerTernaryExpr(e)

	case IndexAccessExpr:
		objRef := ctx.lowerExprToRef(e.Object)
		indexRef := ctx.lowerExprToRef(e.Index)
		return ctx.emit(makeCall("__array_access", []string{objRef, indexRef}))

	case IncrementExpr:
		return ctx.lowerIncrementExpr(e)

	case DecrementExpr:
		return ctx.lowerDecrementExpr(e)

	case ArrayLiteralExpr:
		elementRefs := make([]string, len(e.Elements))
		for i, elem := range e.Elements {
			elementRefs[i] = ctx.lowerExprToRef(elem)
		}
		return ctx.emit(ir.ANFValue{Kind: "array_literal", Elements: elementRefs})
	}

	return ctx.emit(makeLoadConstInt(big.NewInt(0)))
}

// lowerIdentifier matches the TS reference's lowerIdentifier exactly:
// 1. 'this' -> load_const "@this"
// 2. isParam(name) -> load_param (but isParam always false since addParam never called)
// 3. isLocal(name) -> return name directly (reference the local variable)
// 4. isProperty(name) -> load_prop
// 5. default -> load_param
func (ctx *lowerCtx) lowerIdentifier(id Identifier) string {
	name := id.Name

	// 'this' is not a value in ANF
	if name == "this" {
		return ctx.emit(makeLoadConstString("@this"))
	}

	// Check if it's a registered parameter (e.g. txPreimage in StatefulSmartContract)
	if ctx.isParam(name) {
		return ctx.emit(ir.ANFValue{Kind: "load_param", Name: name})
	}

	// Check if it's a local variable -- reference it directly
	// (or use its alias if reassigned by an if-statement)
	if ctx.isLocal(name) {
		if alias := ctx.getLocalAlias(name); alias != "" {
			return alias
		}
		return name
	}

	// Check if it's a contract property
	if ctx.isProperty(name) {
		return ctx.emit(ir.ANFValue{Kind: "load_prop", Name: name})
	}

	// Default: treat as parameter (this is how params get loaded lazily)
	return ctx.emit(ir.ANFValue{Kind: "load_param", Name: name})
}

func (ctx *lowerCtx) lowerMemberExpr(e MemberExpr) string {
	// this.x -> load_prop
	if id, ok := e.Object.(Identifier); ok && id.Name == "this" {
		return ctx.emit(ir.ANFValue{Kind: "load_prop", Name: e.Property})
	}

	// SigHash.ALL etc. -> load constant
	if id, ok := e.Object.(Identifier); ok && id.Name == "SigHash" {
		sigHashValues := map[string]int64{
			"ALL":          0x01,
			"NONE":         0x02,
			"SINGLE":       0x03,
			"FORKID":       0x40,
			"ANYONECANPAY": 0x80,
		}
		if val, ok := sigHashValues[e.Property]; ok {
			return ctx.emit(makeLoadConstInt(big.NewInt(val)))
		}
	}

	// General member access
	objRef := ctx.lowerExprToRef(e.Object)
	return ctx.emit(ir.ANFValue{Kind: "method_call", Object: objRef, Method: e.Property})
}

func (ctx *lowerCtx) lowerCallExpr(e CallExpr) string {
	callee := e.Callee

	// super(...) call
	if id, ok := callee.(Identifier); ok && id.Name == "super" {
		argRefs := ctx.lowerArgs(e.Args)
		return ctx.emit(makeCall("super", argRefs))
	}

	// assert(expr)
	if id, ok := callee.(Identifier); ok && id.Name == "assert" {
		if len(e.Args) >= 1 {
			valueRef := ctx.lowerExprToRef(e.Args[0])
			return ctx.emit(makeAssert(valueRef))
		}
		falseRef := ctx.emit(makeLoadConstBool(false))
		return ctx.emit(makeAssert(falseRef))
	}

	// checkPreimage(preimage)
	if id, ok := callee.(Identifier); ok && id.Name == "checkPreimage" {
		if len(e.Args) >= 1 {
			preimageRef := ctx.lowerExprToRef(e.Args[0])
			return ctx.emit(ir.ANFValue{Kind: "check_preimage", Preimage: preimageRef})
		}
	}

	// this.addOutput(satoshis, val1, val2, ...) -> special node
	if pa, ok := callee.(PropertyAccessExpr); ok && pa.Property == "addOutput" {
		argRefs := ctx.lowerArgs(e.Args)
		satoshis := argRefs[0]
		stateValues := argRefs[1:]
		ref := ctx.emit(ir.ANFValue{Kind: "add_output", Satoshis: satoshis, StateValues: stateValues, Preimage: ""})
		ctx.addOutputRef(ref)
		return ref
	}
	if me, ok := callee.(MemberExpr); ok {
		if id, ok := me.Object.(Identifier); ok && id.Name == "this" && me.Property == "addOutput" {
			argRefs := ctx.lowerArgs(e.Args)
			satoshis := argRefs[0]
			stateValues := argRefs[1:]
			ref := ctx.emit(ir.ANFValue{Kind: "add_output", Satoshis: satoshis, StateValues: stateValues, Preimage: ""})
			ctx.addOutputRef(ref)
			return ref
		}
	}

	// this.addRawOutput(satoshis, scriptBytes) -> special node
	if pa, ok := callee.(PropertyAccessExpr); ok && pa.Property == "addRawOutput" {
		argRefs := ctx.lowerArgs(e.Args)
		satoshis := argRefs[0]
		scriptBytes := argRefs[1]
		ref := ctx.emit(ir.ANFValue{Kind: "add_raw_output", Satoshis: satoshis, ScriptBytes: scriptBytes})
		ctx.addOutputRef(ref)
		return ref
	}
	if me, ok := callee.(MemberExpr); ok {
		if id, ok := me.Object.(Identifier); ok && id.Name == "this" && me.Property == "addRawOutput" {
			argRefs := ctx.lowerArgs(e.Args)
			satoshis := argRefs[0]
			scriptBytes := argRefs[1]
			ref := ctx.emit(ir.ANFValue{Kind: "add_raw_output", Satoshis: satoshis, ScriptBytes: scriptBytes})
			ctx.addOutputRef(ref)
			return ref
		}
	}

	// this.getStateScript()
	if pa, ok := callee.(PropertyAccessExpr); ok && pa.Property == "getStateScript" {
		return ctx.emit(ir.ANFValue{Kind: "get_state_script"})
	}
	if me, ok := callee.(MemberExpr); ok {
		if id, ok := me.Object.(Identifier); ok && id.Name == "this" && me.Property == "getStateScript" {
			return ctx.emit(ir.ANFValue{Kind: "get_state_script"})
		}
	}

	// this.method(...) via PropertyAccessExpr
	if pa, ok := callee.(PropertyAccessExpr); ok {
		argRefs := ctx.lowerArgs(e.Args)
		thisRef := ctx.emit(makeLoadConstString("@this"))
		return ctx.emit(ir.ANFValue{Kind: "method_call", Object: thisRef, Method: pa.Property, Args: argRefs})
	}

	// this.method(...) via MemberExpr
	if me, ok := callee.(MemberExpr); ok {
		if id, ok := me.Object.(Identifier); ok && id.Name == "this" {
			argRefs := ctx.lowerArgs(e.Args)
			thisRef := ctx.emit(makeLoadConstString("@this"))
			return ctx.emit(ir.ANFValue{Kind: "method_call", Object: thisRef, Method: me.Property, Args: argRefs})
		}
	}

	// Direct function call: sha256(x), checkSig(sig, pk), etc.
	if id, ok := callee.(Identifier); ok {
		argRefs := ctx.lowerArgs(e.Args)
		// Bare identifier calls that match a private method on the contract
		// (e.g. Move's `require_owner(contract, sig)` which the parser strips
		// to `requireOwner(sig)`) must be routed through the same inlining
		// path as `this.requireOwner(sig)` so downstream stack lowering can
		// inline the body. This keeps .runar.move, .runar.go, and .runar.ts
		// lowering in sync.
		if ctx.isPrivateMethod(id.Name) {
			thisRef := ctx.emit(makeLoadConstString("@this"))
			return ctx.emit(ir.ANFValue{Kind: "method_call", Object: thisRef, Method: id.Name, Args: argRefs})
		}
		return ctx.emit(makeCall(id.Name, argRefs))
	}

	// General call
	calleeRef := ctx.lowerExprToRef(callee)
	argRefs := ctx.lowerArgs(e.Args)
	return ctx.emit(ir.ANFValue{Kind: "method_call", Object: calleeRef, Method: "call", Args: argRefs})
}

func (ctx *lowerCtx) lowerArgs(args []Expression) []string {
	refs := make([]string, len(args))
	for i, arg := range args {
		refs[i] = ctx.lowerExprToRef(arg)
	}
	return refs
}

func (ctx *lowerCtx) lowerTernaryExpr(e TernaryExpr) string {
	condRef := ctx.lowerExprToRef(e.Condition)

	thenCtx := ctx.subContext()
	thenCtx.lowerExprToRef(e.Consequent)
	ctx.syncCounter(thenCtx)

	elseCtx := ctx.subContext()
	elseCtx.lowerExprToRef(e.Alternate)
	ctx.syncCounter(elseCtx)

	elseBindings2 := elseCtx.bindings
	if elseBindings2 == nil {
		elseBindings2 = []ir.ANFBinding{}
	}
	return ctx.emit(ir.ANFValue{
		Kind: "if",
		Cond: condRef,
		Then: thenCtx.bindings,
		Else: elseBindings2,
	})
}

func (ctx *lowerCtx) lowerIncrementExpr(e IncrementExpr) string {
	operandRef := ctx.lowerExprToRef(e.Operand)
	oneRef := ctx.emit(makeLoadConstInt(big.NewInt(1)))
	result := ctx.emit(ir.ANFValue{Kind: "bin_op", Op: "+", Left: operandRef, Right: oneRef})

	// If the operand is a named variable, update it
	if id, ok := e.Operand.(Identifier); ok {
		ctx.emitNamed(id.Name, makeLoadConstString("@ref:"+result))
	}
	if pa, ok := e.Operand.(PropertyAccessExpr); ok {
		ctx.emit(makeUpdateProp(pa.Property, result))
	}

	if e.Prefix {
		return result
	}
	return operandRef
}

func (ctx *lowerCtx) lowerDecrementExpr(e DecrementExpr) string {
	operandRef := ctx.lowerExprToRef(e.Operand)
	oneRef := ctx.emit(makeLoadConstInt(big.NewInt(1)))
	result := ctx.emit(ir.ANFValue{Kind: "bin_op", Op: "-", Left: operandRef, Right: oneRef})

	// If the operand is a named variable, update it
	if id, ok := e.Operand.(Identifier); ok {
		ctx.emitNamed(id.Name, makeLoadConstString("@ref:"+result))
	}
	if pa, ok := e.Operand.(PropertyAccessExpr); ok {
		ctx.emit(makeUpdateProp(pa.Property, result))
	}

	if e.Prefix {
		return result
	}
	return operandRef
}

// ---------------------------------------------------------------------------
// ANFValue constructors — build properly serializable values
// ---------------------------------------------------------------------------

func makeLoadConstInt(val *big.Int) ir.ANFValue {
	raw, _ := json.Marshal(val)
	v := ir.ANFValue{
		Kind:        "load_const",
		RawValue:    raw,
		ConstBigInt: new(big.Int).Set(val),
	}
	if val.IsInt64() {
		i := val.Int64()
		v.ConstInt = &i
	}
	return v
}

func makeLoadConstBool(val bool) ir.ANFValue {
	raw, _ := json.Marshal(val)
	b := val
	return ir.ANFValue{
		Kind:      "load_const",
		RawValue:  raw,
		ConstBool: &b,
	}
}

func makeLoadConstString(val string) ir.ANFValue {
	raw, _ := json.Marshal(val)
	s := val
	return ir.ANFValue{
		Kind:        "load_const",
		RawValue:    raw,
		ConstString: &s,
	}
}

func makeCall(funcName string, args []string) ir.ANFValue {
	return ir.ANFValue{
		Kind: "call",
		Func: funcName,
		Args: args,
	}
}

func makeAssert(valueRef string) ir.ANFValue {
	raw, _ := json.Marshal(valueRef)
	return ir.ANFValue{
		Kind:     "assert",
		RawValue: raw,
		ValueRef: valueRef,
	}
}

func makeUpdateProp(name, valueRef string) ir.ANFValue {
	raw, _ := json.Marshal(valueRef)
	return ir.ANFValue{
		Kind:     "update_prop",
		Name:     name,
		RawValue: raw,
		ValueRef: valueRef,
	}
}

// ---------------------------------------------------------------------------
// State mutation analysis for StatefulSmartContract
// ---------------------------------------------------------------------------

// methodMutatesState determines whether a method mutates any mutable
// (non-readonly) property. Conservative: if ANY code path can mutate state,
// returns true.
func methodMutatesState(method MethodNode, contract *ContractNode) bool {
	mutableProps := make(map[string]bool)
	for _, p := range contract.Properties {
		if !p.Readonly {
			mutableProps[p.Name] = true
		}
	}
	if len(mutableProps) == 0 {
		return false
	}
	return bodyMutatesState(method.Body, mutableProps)
}

func bodyMutatesState(stmts []Statement, mutableProps map[string]bool) bool {
	for _, stmt := range stmts {
		if stmtMutatesState(stmt, mutableProps) {
			return true
		}
	}
	return false
}

func stmtMutatesState(stmt Statement, mutableProps map[string]bool) bool {
	switch s := stmt.(type) {
	case AssignmentStmt:
		if pa, ok := s.Target.(PropertyAccessExpr); ok && mutableProps[pa.Property] {
			return true
		}
		return false
	case ExpressionStmt:
		return exprMutatesState(s.Expr, mutableProps)
	case IfStmt:
		if bodyMutatesState(s.Then, mutableProps) {
			return true
		}
		if len(s.Else) > 0 && bodyMutatesState(s.Else, mutableProps) {
			return true
		}
		return false
	case ForStmt:
		if stmtMutatesState(s.Update, mutableProps) {
			return true
		}
		return bodyMutatesState(s.Body, mutableProps)
	default:
		return false
	}
}

func exprMutatesState(expr Expression, mutableProps map[string]bool) bool {
	switch e := expr.(type) {
	case IncrementExpr:
		if pa, ok := e.Operand.(PropertyAccessExpr); ok && mutableProps[pa.Property] {
			return true
		}
	case DecrementExpr:
		if pa, ok := e.Operand.(PropertyAccessExpr); ok && mutableProps[pa.Property] {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// addOutput detection for determining change output necessity
// ---------------------------------------------------------------------------

// methodHasAddOutput checks if a method body contains any this.addOutput() calls.
func methodHasAddOutput(method MethodNode) bool {
	return bodyHasAddOutput(method.Body)
}

func bodyHasAddOutput(stmts []Statement) bool {
	for _, stmt := range stmts {
		if stmtHasAddOutput(stmt) {
			return true
		}
	}
	return false
}

func stmtHasAddOutput(stmt Statement) bool {
	switch s := stmt.(type) {
	case ExpressionStmt:
		return exprHasAddOutput(s.Expr)
	case IfStmt:
		if bodyHasAddOutput(s.Then) {
			return true
		}
		if len(s.Else) > 0 && bodyHasAddOutput(s.Else) {
			return true
		}
		return false
	case ForStmt:
		return bodyHasAddOutput(s.Body)
	default:
		return false
	}
}

func exprHasAddOutput(expr Expression) bool {
	if ce, ok := expr.(CallExpr); ok {
		if pa, ok := ce.Callee.(PropertyAccessExpr); ok && (pa.Property == "addOutput" || pa.Property == "addRawOutput") {
			return true
		}
		if me, ok := ce.Callee.(MemberExpr); ok {
			if id, ok := me.Object.(Identifier); ok && id.Name == "this" && (me.Property == "addOutput" || me.Property == "addRawOutput") {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Post-ANF pass: lift update_prop from if-else branches
// ---------------------------------------------------------------------------
//
// Mirrors the TypeScript reference compiler's liftBranchUpdateProps function.
// Transforms if-else chains where each branch ends with update_prop into
// flat conditional assignments. This prevents phantom stack entries in
// stack lowering.
//
// Before:
//   if (pos === 0) { this.c0 = turn; }
//   else if (pos === 1) { this.c1 = turn; }
//   else { this.c4 = turn; }
//
// After:
//   this.c0 = (pos === 0) ? turn : this.c0;
//   this.c1 = (!cond0 && pos === 1) ? turn : this.c1;
//   this.c4 = (!cond0 && !cond1) ? turn : this.c4;

type updateBranch struct {
	condSetupBindings []ir.ANFBinding
	condRef           *string // nil for final else
	propName          string
	valueBindings     []ir.ANFBinding
	valueRef          string
}

// maxTempIndex finds the max temp index (e.g. t47 → 47) in a binding tree.
func maxTempIndex(bindings []ir.ANFBinding) int {
	max := -1
	for _, b := range bindings {
		if len(b.Name) > 1 && b.Name[0] == 't' {
			n := 0
			valid := true
			for _, ch := range b.Name[1:] {
				if ch >= '0' && ch <= '9' {
					n = n*10 + int(ch-'0')
				} else {
					valid = false
					break
				}
			}
			if valid && n > max {
				max = n
			}
		}
		if b.Value.Kind == "if" {
			if t := maxTempIndex(b.Value.Then); t > max {
				max = t
			}
			if e := maxTempIndex(b.Value.Else); e > max {
				max = e
			}
		}
		if b.Value.Kind == "loop" {
			if l := maxTempIndex(b.Value.Body); l > max {
				max = l
			}
		}
	}
	return max
}

// isSideEffectFree checks if an ANF value kind is side-effect-free.
func isSideEffectFree(v *ir.ANFValue) bool {
	switch v.Kind {
	case "load_prop", "load_param", "load_const", "bin_op", "unary_op":
		return true
	}
	return false
}

func allBindingsSideEffectFree(bindings []ir.ANFBinding) bool {
	for i := range bindings {
		if !isSideEffectFree(&bindings[i].Value) {
			return false
		}
	}
	return true
}

// extractBranchUpdate checks if a branch's bindings end with update_prop.
// Returns (propName, valueBindings, valueRef, ok).
func extractBranchUpdate(bindings []ir.ANFBinding) (string, []ir.ANFBinding, string, bool) {
	if len(bindings) == 0 {
		return "", nil, "", false
	}
	last := &bindings[len(bindings)-1]
	if last.Value.Kind != "update_prop" {
		return "", nil, "", false
	}
	valueBindings := make([]ir.ANFBinding, len(bindings)-1)
	copy(valueBindings, bindings[:len(bindings)-1])
	if !allBindingsSideEffectFree(valueBindings) {
		return "", nil, "", false
	}
	return last.Value.Name, valueBindings, last.Value.ValueRef, true
}

// isAssertFalseElse checks if an else branch is just assert(false).
func isAssertFalseElse(bindings []ir.ANFBinding) bool {
	if len(bindings) == 0 {
		return false
	}
	last := &bindings[len(bindings)-1]
	if last.Value.Kind != "assert" {
		return false
	}
	assertRef := last.Value.ValueRef
	for _, b := range bindings {
		if b.Name == assertRef && b.Value.Kind == "load_const" && b.Value.ConstBool != nil && !*b.Value.ConstBool {
			return true
		}
	}
	return false
}

// collectUpdateBranches recursively collects update branches from a nested if-else chain.
func collectUpdateBranches(ifCond string, thenBindings, elseBindings []ir.ANFBinding) []updateBranch {
	propName, valBindings, valRef, ok := extractBranchUpdate(thenBindings)
	if !ok {
		return nil
	}

	branches := []updateBranch{{
		condRef:      &ifCond,
		propName:     propName,
		valueBindings: valBindings,
		valueRef:     valRef,
	}}

	if len(elseBindings) == 0 {
		return nil
	}

	// Check if else is another if (else-if chain)
	lastElse := &elseBindings[len(elseBindings)-1]
	if lastElse.Value.Kind == "if" {
		condSetup := make([]ir.ANFBinding, len(elseBindings)-1)
		copy(condSetup, elseBindings[:len(elseBindings)-1])
		if !allBindingsSideEffectFree(condSetup) {
			return nil
		}

		innerBranches := collectUpdateBranches(lastElse.Value.Cond, lastElse.Value.Then, lastElse.Value.Else)
		if innerBranches == nil {
			return nil
		}

		// Prepend condition setup to first inner branch
		newSetup := make([]ir.ANFBinding, 0, len(condSetup)+len(innerBranches[0].condSetupBindings))
		newSetup = append(newSetup, condSetup...)
		newSetup = append(newSetup, innerBranches[0].condSetupBindings...)
		innerBranches[0].condSetupBindings = newSetup

		branches = append(branches, innerBranches...)
		return branches
	}

	// Otherwise, else branch should end with update_prop (final else)
	if ePropName, eValBindings, eValRef, eOk := extractBranchUpdate(elseBindings); eOk {
		branches = append(branches, updateBranch{
			condRef:       nil,
			propName:      ePropName,
			valueBindings: eValBindings,
			valueRef:      eValRef,
		})
		return branches
	}

	// Handle unreachable else: assert(false)
	if isAssertFalseElse(elseBindings) {
		return branches
	}

	return nil
}

// remapValueRefs remaps temp references in an ANF value according to a name mapping.
func remapValueRefs(v ir.ANFValue, nameMap map[string]string) ir.ANFValue {
	r := func(s string) string {
		if mapped, ok := nameMap[s]; ok {
			return mapped
		}
		return s
	}

	switch v.Kind {
	case "load_param", "load_prop", "get_state_script":
		return v
	case "load_const":
		if v.ConstString != nil {
			s := *v.ConstString
			if len(s) > 5 && s[:5] == "@ref:" {
				target := s[5:]
				if mapped, ok := nameMap[target]; ok {
					newRef := "@ref:" + mapped
					raw, _ := json.Marshal(newRef)
					return ir.ANFValue{
						Kind:        "load_const",
						RawValue:    raw,
						ConstString: &newRef,
					}
				}
			}
		}
		return v
	case "bin_op":
		v.Left = r(v.Left)
		v.Right = r(v.Right)
		return v
	case "unary_op":
		v.Operand = r(v.Operand)
		return v
	case "call":
		args := make([]string, len(v.Args))
		for i, a := range v.Args {
			args[i] = r(a)
		}
		v.Args = args
		return v
	case "method_call":
		v.Object = r(v.Object)
		args := make([]string, len(v.Args))
		for i, a := range v.Args {
			args[i] = r(a)
		}
		v.Args = args
		return v
	case "assert":
		v.ValueRef = r(v.ValueRef)
		return v
	case "update_prop":
		v.ValueRef = r(v.ValueRef)
		return v
	case "check_preimage":
		v.Preimage = r(v.Preimage)
		return v
	case "deserialize_state":
		v.Preimage = r(v.Preimage)
		return v
	case "add_output":
		v.Satoshis = r(v.Satoshis)
		sv := make([]string, len(v.StateValues))
		for i, s := range v.StateValues {
			sv[i] = r(s)
		}
		v.StateValues = sv
		return v
	case "add_raw_output":
		v.Satoshis = r(v.Satoshis)
		v.ScriptBytes = r(v.ScriptBytes)
		return v
	case "if":
		v.Cond = r(v.Cond)
		return v
	case "loop":
		return v
	}
	return v
}

// liftBranchUpdateProps transforms if-bindings whose branches all end
// with update_prop into flat conditional assignments.
func liftBranchUpdateProps(bindings []ir.ANFBinding) []ir.ANFBinding {
	nextIdx := maxTempIndex(bindings) + 1
	fresh := func() string {
		name := fmt.Sprintf("t%d", nextIdx)
		nextIdx++
		return name
	}

	result := make([]ir.ANFBinding, 0, len(bindings))

	for _, binding := range bindings {
		if binding.Value.Kind != "if" {
			result = append(result, binding)
			continue
		}

		branches := collectUpdateBranches(binding.Value.Cond, binding.Value.Then, binding.Value.Else)

		if branches == nil || len(branches) < 2 {
			result = append(result, binding)
			continue
		}

		// --- Transform: flatten into conditional assignments ---

		// 1. Hoist condition setup bindings with fresh names
		nameMap := map[string]string{}
		condRefs := make([]*string, len(branches))

		for bi, branch := range branches {
			for _, csb := range branch.condSetupBindings {
				newName := fresh()
				nameMap[csb.Name] = newName
				result = append(result, ir.ANFBinding{
					Name:  newName,
					Value: remapValueRefs(csb.Value, nameMap),
				})
			}
			if branch.condRef != nil {
				cr := *branch.condRef
				if mapped, ok := nameMap[cr]; ok {
					cr = mapped
				}
				condRefs[bi] = &cr
			}
		}

		// 2. Compute effective condition for each branch
		effectiveConds := make([]string, 0, len(branches))
		negatedConds := make([]string, 0)

		for i := range branches {
			if i == 0 {
				effectiveConds = append(effectiveConds, *condRefs[0])
				continue
			}

			// Negate any prior conditions not yet negated
			for j := len(negatedConds); j < i; j++ {
				if condRefs[j] == nil {
					continue
				}
				negName := fresh()
				result = append(result, ir.ANFBinding{
					Name: negName,
					Value: ir.ANFValue{
						Kind:    "unary_op",
						Op:      "!",
						Operand: *condRefs[j],
					},
				})
				negatedConds = append(negatedConds, negName)
			}

			// AND all negated conditions together
			andRef := negatedConds[0]
			limit := i
			if len(negatedConds) < limit {
				limit = len(negatedConds)
			}
			for j := 1; j < limit; j++ {
				andName := fresh()
				result = append(result, ir.ANFBinding{
					Name: andName,
					Value: ir.ANFValue{
						Kind:  "bin_op",
						Op:    "&&",
						Left:  andRef,
						Right: negatedConds[j],
					},
				})
				andRef = andName
			}

			if condRefs[i] != nil {
				// Middle branch: AND with own condition
				finalName := fresh()
				result = append(result, ir.ANFBinding{
					Name: finalName,
					Value: ir.ANFValue{
						Kind:  "bin_op",
						Op:    "&&",
						Left:  andRef,
						Right: *condRefs[i],
					},
				})
				effectiveConds = append(effectiveConds, finalName)
			} else {
				// Final else: just the AND of negations
				effectiveConds = append(effectiveConds, andRef)
			}
		}

		// 3. For each branch, emit: load_old, conditional if-expression, update_prop
		for i, branch := range branches {
			// Load old property value
			oldPropRef := fresh()
			result = append(result, ir.ANFBinding{
				Name: oldPropRef,
				Value: ir.ANFValue{
					Kind: "load_prop",
					Name: branch.propName,
				},
			})

			// Remap value bindings for the then-branch
			branchMap := make(map[string]string)
			for k, v := range nameMap {
				branchMap[k] = v
			}
			thenBindings := make([]ir.ANFBinding, 0, len(branch.valueBindings))
			for _, vb := range branch.valueBindings {
				newName := fresh()
				branchMap[vb.Name] = newName
				thenBindings = append(thenBindings, ir.ANFBinding{
					Name:  newName,
					Value: remapValueRefs(vb.Value, branchMap),
				})
			}

			// Else branch: keep old property value
			keepName := fresh()
			refStr := "@ref:" + oldPropRef
			raw, _ := json.Marshal(refStr)
			elseBindings := []ir.ANFBinding{
				{
					Name: keepName,
					Value: ir.ANFValue{
						Kind:        "load_const",
						RawValue:    raw,
						ConstString: &refStr,
					},
				},
			}

			// Emit conditional if-expression
			condIfRef := fresh()
			result = append(result, ir.ANFBinding{
				Name: condIfRef,
				Value: ir.ANFValue{
					Kind: "if",
					Cond: effectiveConds[i],
					Then: thenBindings,
					Else: elseBindings,
				},
			})

			// Emit update_prop
			updateName := fresh()
			valRefJSON, _ := json.Marshal(condIfRef)
			result = append(result, ir.ANFBinding{
				Name: updateName,
				Value: ir.ANFValue{
					Kind:     "update_prop",
					Name:     branch.propName,
					RawValue: valRefJSON,
					ValueRef: condIfRef,
				},
			})
		}
	}

	return result
}
