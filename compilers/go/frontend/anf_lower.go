package frontend

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

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
	"toByteString": true,
	"pack":         true,
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
	}
	return props
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

		if contract.ParentClass == "InductiveSmartContract" && method.Visibility == "public" {
			// ---------------------------------------------------------------
			// InductiveSmartContract public method lowering
			// ---------------------------------------------------------------

			// Register implicit parameters: parentTx + txPreimage
			methodCtx.addParam("parentTx")
			methodCtx.addParam("txPreimage")

			// 1. Inject checkPreimage(txPreimage) at the start
			preimageRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			checkResult := methodCtx.emit(ir.ANFValue{Kind: "check_preimage", Preimage: preimageRef})
			methodCtx.emit(makeAssert(checkResult))

			// 2. Verify parent tx authenticity:
			//    assert(hash256(parentTx) === left(extractOutpoint(txPreimage), 32))
			parentTxRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "parentTx"})
			parentTxHash := methodCtx.emit(makeCall("hash256", []string{parentTxRef}))
			preimageRef2 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			outpointRef := methodCtx.emit(makeCall("extractOutpoint", []string{preimageRef2}))
			thirtyTwo := methodCtx.emit(makeLoadConstInt(32))
			parentTxIdFromPreimage := methodCtx.emit(makeCall("left", []string{outpointRef, thirtyTwo}))
			parentHashEq := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: parentTxHash, Right: parentTxIdFromPreimage, ResultType: "bytes"})
			methodCtx.emit(makeAssert(parentHashEq))

			// 3. Genesis detection: if (_genesisOutpoint === 0x00..00_36)
			genesisRef := methodCtx.emit(ir.ANFValue{Kind: "load_prop", Name: "_genesisOutpoint"})
			zeroSentinel := methodCtx.emit(makeLoadConstString(strings.Repeat("0", 72))) // 36 bytes = 72 hex chars
			isGenesis := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: genesisRef, Right: zeroSentinel, ResultType: "bytes"})

			// Genesis branch: set _genesisOutpoint = extractOutpoint(txPreimage)
			genesisCtx := methodCtx.subContext()
			gpRef := genesisCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			currentOutpoint := genesisCtx.emit(makeCall("extractOutpoint", []string{gpRef}))
			genesisCtx.emit(makeUpdateProp("_genesisOutpoint", currentOutpoint))
			methodCtx.syncCounter(genesisCtx)

			// Non-genesis branch: verify chain consistency
			nonGenesisCtx := methodCtx.subContext()
			// Extract parent output script via extract_parent_output
			ptxRef := nonGenesisCtx.emit(ir.ANFValue{Kind: "load_param", Name: "parentTx"})
			// Derive output index dynamically from the current transaction's outpoint.
			// The outpoint is 36 bytes: 32-byte txid + 4-byte vout (little-endian).
			// We extract the last 4 bytes (vout) and convert to a number via OP_BIN2NUM.
			preimageForIdx := nonGenesisCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			outpointForIdx := nonGenesisCtx.emit(makeCall("extractOutpoint", []string{preimageForIdx}))
			fourC := nonGenesisCtx.emit(makeLoadConstInt(4))
			outputIdxBytes := nonGenesisCtx.emit(makeCall("right", []string{outpointForIdx, fourC}))
			outputIdx := nonGenesisCtx.emit(ir.ANFValue{Kind: "unary_op", Op: "unpack", Operand: outputIdxBytes})
			parentScript := nonGenesisCtx.emit(ir.ANFValue{Kind: "extract_parent_output", RawTx: ptxRef, OutputIndex: outputIdx})

			// Extract internal fields from the END of parent script
			// Internal fields are the last 111 bytes (3 * 37 bytes: 1 push opcode + 36 data bytes each)
			parentScriptLen := nonGenesisCtx.emit(makeCall("len", []string{parentScript}))
			oneEleven := nonGenesisCtx.emit(makeLoadConstInt(111))
			prefixLen := nonGenesisCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "-", Left: parentScriptLen, Right: oneEleven})
			_ = prefixLen
			internalFieldsWithPrefixes := nonGenesisCtx.emit(makeCall("right", []string{parentScript, oneEleven}))

			// Now extract each 37-byte field (1 push opcode + 36 data bytes)
			thirtySevenC := nonGenesisCtx.emit(makeLoadConstInt(37))
			thirtySixC := nonGenesisCtx.emit(makeLoadConstInt(36))
			_ = thirtySixC

			// parentGenesis: left(internalFieldsWithPrefixes, 37), then right(_, 36) to skip push opcode
			parentGenesisRaw := nonGenesisCtx.emit(makeCall("left", []string{internalFieldsWithPrefixes, thirtySevenC}))
			thirtySixC2 := nonGenesisCtx.emit(makeLoadConstInt(36))
			parentGenesis := nonGenesisCtx.emit(makeCall("right", []string{parentGenesisRaw, thirtySixC2}))

			// parentParentOutpoint: left(internalFieldsWithPrefixes, 74), then right(_, 37), then right(_, 36)
			seventyFourC := nonGenesisCtx.emit(makeLoadConstInt(74))
			parentParentOutpointRaw := nonGenesisCtx.emit(makeCall("left", []string{internalFieldsWithPrefixes, seventyFourC}))
			thirtySevenC2 := nonGenesisCtx.emit(makeLoadConstInt(37))
			parentParentOutpointWithPrefix := nonGenesisCtx.emit(makeCall("right", []string{parentParentOutpointRaw, thirtySevenC2}))
			thirtySixC3 := nonGenesisCtx.emit(makeLoadConstInt(36))
			parentParentOutpoint := nonGenesisCtx.emit(makeCall("right", []string{parentParentOutpointWithPrefix, thirtySixC3}))

			// Assert: parentGenesis === _genesisOutpoint (same lineage)
			myGenesis := nonGenesisCtx.emit(ir.ANFValue{Kind: "load_prop", Name: "_genesisOutpoint"})
			genesisEq := nonGenesisCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: parentGenesis, Right: myGenesis, ResultType: "bytes"})
			nonGenesisCtx.emit(makeAssert(genesisEq))

			// Assert: parentParentOutpoint === _grandparentOutpoint (chain links match)
			myGrandparent := nonGenesisCtx.emit(ir.ANFValue{Kind: "load_prop", Name: "_grandparentOutpoint"})
			chainEq := nonGenesisCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: parentParentOutpoint, Right: myGrandparent, ResultType: "bytes"})
			nonGenesisCtx.emit(makeAssert(chainEq))
			methodCtx.syncCounter(nonGenesisCtx)

			// Emit the if/else
			methodCtx.emit(ir.ANFValue{
				Kind: "if",
				Cond: isGenesis,
				Then: genesisCtx.bindings,
				Else: nonGenesisCtx.bindings,
			})

			// 4. Inject internal field updates BEFORE the developer body, so that
			//    addOutput calls in the developer's code pick up the updated values
			//    via auto-appended load_prop references.
			//    _grandparentOutpoint = _parentOutpoint
			oldParent := methodCtx.emit(ir.ANFValue{Kind: "load_prop", Name: "_parentOutpoint"})
			methodCtx.emit(makeUpdateProp("_grandparentOutpoint", oldParent))
			//    _parentOutpoint = extractOutpoint(txPreimage)
			preimageRef3 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			currentOutpoint2 := methodCtx.emit(makeCall("extractOutpoint", []string{preimageRef3}))
			methodCtx.emit(makeUpdateProp("_parentOutpoint", currentOutpoint2))

			// 5. Lower the developer's method body
			methodCtx.lowerStatements(method.Body)

			// 6. State continuation (same as StatefulSmartContract)
			addOutputRefs := methodCtx.getAddOutputRefs()
			if len(addOutputRefs) > 0 {
				// Multi-output continuation
				accumulated := addOutputRefs[0]
				for i := 1; i < len(addOutputRefs); i++ {
					accumulated = methodCtx.emit(makeCall("cat", []string{accumulated, addOutputRefs[i]}))
				}
				hashRef := methodCtx.emit(makeCall("hash256", []string{accumulated}))
				preimageRef4 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
				outputHashRef := methodCtx.emit(makeCall("extractOutputHash", []string{preimageRef4}))
				eqRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: hashRef, Right: outputHashRef, ResultType: "bytes"})
				methodCtx.emit(makeAssert(eqRef))
			} else {
				// InductiveSmartContract always mutates state (internal fields)
				stateScriptRef := methodCtx.emit(ir.ANFValue{Kind: "get_state_script"})
				hashRef := methodCtx.emit(makeCall("hash256", []string{stateScriptRef}))
				preimageRef4 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
				outputHashRef := methodCtx.emit(makeCall("extractOutputHash", []string{preimageRef4}))
				eqRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: hashRef, Right: outputHashRef, ResultType: "bytes"})
				methodCtx.emit(makeAssert(eqRef))
			}

			// Append implicit params: parentTx + txPreimage
			augmentedParams := append(lowerParams(method.Params),
				ir.ANFParam{Name: "parentTx", Type: "ByteString"},
				ir.ANFParam{Name: "txPreimage", Type: "SigHashPreimage"},
			)

			result = append(result, ir.ANFMethod{
				Name:     method.Name,
				Params:   augmentedParams,
				Body:     methodCtx.bindings,
				IsPublic: true,
			})
		} else if contract.ParentClass == "StatefulSmartContract" && method.Visibility == "public" {
			// Register txPreimage as an implicit parameter
			methodCtx.addParam("txPreimage")

			// Inject checkPreimage(txPreimage) at the start
			preimageRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			checkResult := methodCtx.emit(ir.ANFValue{Kind: "check_preimage", Preimage: preimageRef})
			methodCtx.emit(makeAssert(checkResult))

			// Lower the developer's method body
			methodCtx.lowerStatements(method.Body)

			// Determine state continuation type
			addOutputRefs := methodCtx.getAddOutputRefs()
			if len(addOutputRefs) > 0 {
				// Multi-output continuation: concat all outputs, hash, compare to extractOutputHash
				accumulated := addOutputRefs[0]
				for i := 1; i < len(addOutputRefs); i++ {
					accumulated = methodCtx.emit(makeCall("cat", []string{accumulated, addOutputRefs[i]}))
				}
				hashRef := methodCtx.emit(makeCall("hash256", []string{accumulated}))
				preimageRef2 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
				outputHashRef := methodCtx.emit(makeCall("extractOutputHash", []string{preimageRef2}))
				eqRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: hashRef, Right: outputHashRef, ResultType: "bytes"})
				methodCtx.emit(makeAssert(eqRef))
			} else if methodMutatesState(method, contract) {
				// Single-output continuation (existing behavior)
				stateScriptRef := methodCtx.emit(ir.ANFValue{Kind: "get_state_script"})
				hashRef := methodCtx.emit(makeCall("hash256", []string{stateScriptRef}))
				preimageRef2 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
				outputHashRef := methodCtx.emit(makeCall("extractOutputHash", []string{preimageRef2}))
				eqRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: hashRef, Right: outputHashRef, ResultType: "bytes"})
				methodCtx.emit(makeAssert(eqRef))
			}

			// Append implicit txPreimage param to the method's param list
			augmentedParams := append(lowerParams(method.Params), ir.ANFParam{
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
	bindings      []ir.ANFBinding
	counter       int
	contract      *ContractNode
	localNames    map[string]bool // tracks variable names registered via addLocal
	paramNames    map[string]bool // tracks parameter names registered via addParam
	addOutputRefs []string        // tracks addOutput binding refs for multi-output continuation
}

func newLowerCtx(contract *ContractNode) *lowerCtx {
	return &lowerCtx{
		contract:   contract,
		localNames: make(map[string]bool),
		paramNames: make(map[string]bool),
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
	ctx.bindings = append(ctx.bindings, ir.ANFBinding{Name: name, Value: value})
	return name
}

// emitNamed appends a binding with a specific name (for named variables).
func (ctx *lowerCtx) emitNamed(name string, value ir.ANFValue) {
	ctx.bindings = append(ctx.bindings, ir.ANFBinding{Name: name, Value: value})
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

// addOutputRef tracks an addOutput binding ref for multi-output continuation.
func (ctx *lowerCtx) addOutputRef(ref string) {
	ctx.addOutputRefs = append(ctx.addOutputRefs, ref)
}

// getAddOutputRefs returns all addOutput refs collected during lowering.
func (ctx *lowerCtx) getAddOutputRefs() []string {
	return ctx.addOutputRefs
}

// isProperty checks if a name is a contract property.
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
		contract:   ctx.contract,
		counter:    ctx.counter,
		localNames: make(map[string]bool),
		paramNames: make(map[string]bool),
	}
	// Share local name set
	for k := range ctx.localNames {
		sub.localNames[k] = true
	}
	// Share param name set
	for k := range ctx.paramNames {
		sub.paramNames[k] = true
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
	for _, stmt := range stmts {
		ctx.lowerStatement(stmt)
	}
}

func (ctx *lowerCtx) lowerStatement(stmt Statement) {
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
			ctx.lowerExprToRef(s.Value)
		}
	}
}

// lowerVariableDecl matches the TS reference:
// Lower the init expression, register the variable as local, then emit
// a named binding that aliases the variable to the computed value via @ref.
func (ctx *lowerCtx) lowerVariableDecl(stmt VariableDeclStmt) {
	valueRef := ctx.lowerExprToRef(stmt.Init)
	ctx.addLocal(stmt.Name)
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

	ctx.emit(ir.ANFValue{
		Kind: "if",
		Cond: condRef,
		Then: thenCtx.bindings,
		Else: elseCtx.bindings,
	})
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
		return big.NewInt(e.Value)
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

		return ctx.emit(ir.ANFValue{Kind: "bin_op", Op: e.Op, Left: leftRef, Right: rightRef, ResultType: resultType})

	case UnaryExpr:
		operandRef := ctx.lowerExprToRef(e.Operand)
		return ctx.emit(ir.ANFValue{Kind: "unary_op", Op: e.Op, Operand: operandRef})

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
	}

	return ctx.emit(makeLoadConstInt(0))
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
	if ctx.isLocal(name) {
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
			return ctx.emit(makeLoadConstInt(val))
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
		// For InductiveSmartContract, auto-append internal field values.
		// The internal fields have already been updated (update_prop) before the
		// developer's body, so load_prop returns the correct new-generation values.
		if ctx.contract.ParentClass == "InductiveSmartContract" {
			genesisRef := ctx.emit(ir.ANFValue{Kind: "load_prop", Name: "_genesisOutpoint"})
			parentRef := ctx.emit(ir.ANFValue{Kind: "load_prop", Name: "_parentOutpoint"})
			grandparentRef := ctx.emit(ir.ANFValue{Kind: "load_prop", Name: "_grandparentOutpoint"})
			stateValues = append(stateValues, genesisRef, parentRef, grandparentRef)
		}
		ref := ctx.emit(ir.ANFValue{Kind: "add_output", Satoshis: satoshis, StateValues: stateValues})
		ctx.addOutputRef(ref)
		return ref
	}
	if me, ok := callee.(MemberExpr); ok {
		if id, ok := me.Object.(Identifier); ok && id.Name == "this" && me.Property == "addOutput" {
			argRefs := ctx.lowerArgs(e.Args)
			satoshis := argRefs[0]
			stateValues := argRefs[1:]
			// For InductiveSmartContract, auto-append internal field values.
			if ctx.contract.ParentClass == "InductiveSmartContract" {
				genesisRef := ctx.emit(ir.ANFValue{Kind: "load_prop", Name: "_genesisOutpoint"})
				parentRef := ctx.emit(ir.ANFValue{Kind: "load_prop", Name: "_parentOutpoint"})
				grandparentRef := ctx.emit(ir.ANFValue{Kind: "load_prop", Name: "_grandparentOutpoint"})
				stateValues = append(stateValues, genesisRef, parentRef, grandparentRef)
			}
			ref := ctx.emit(ir.ANFValue{Kind: "add_output", Satoshis: satoshis, StateValues: stateValues})
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

	return ctx.emit(ir.ANFValue{
		Kind: "if",
		Cond: condRef,
		Then: thenCtx.bindings,
		Else: elseCtx.bindings,
	})
}

func (ctx *lowerCtx) lowerIncrementExpr(e IncrementExpr) string {
	operandRef := ctx.lowerExprToRef(e.Operand)
	oneRef := ctx.emit(makeLoadConstInt(1))
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
	oneRef := ctx.emit(makeLoadConstInt(1))
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

func makeLoadConstInt(val int64) ir.ANFValue {
	raw, _ := json.Marshal(val)
	bi := big.NewInt(val)
	i := val
	return ir.ANFValue{
		Kind:        "load_const",
		RawValue:    raw,
		ConstBigInt: bi,
		ConstInt:    &i,
	}
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
