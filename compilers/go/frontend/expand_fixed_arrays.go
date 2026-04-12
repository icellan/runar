// Pass 3b: Expand fixed-size array properties into scalar sibling fields.
//
// This file is a direct Go port of the TypeScript reference implementation
// `packages/runar-compiler/src/passes/03b-expand-fixed-arrays.ts`. Any change
// in one must be mirrored in the other — cross-compiler conformance requires
// byte-identical output from identical input, which in turn requires
// identical synthetic names, identical traversal order, and identical
// dispatch shape for literal-index and runtime-index reads / writes.
//
// Runs between typecheck and ANF lowering. Takes a ContractNode whose
// properties may contain `FixedArrayType` declarations like
// `board: FixedArray<bigint, 9>` and rewrites the AST so that every
// downstream pass sees an equivalent contract with 9 scalar siblings
// `board__0 .. board__8` and all `this.board[i]` reads/writes replaced by
// direct member access (literal index) or if/else dispatch (runtime index).
//
// See the TS reference for the precise semantics of runtime reads (ternary
// fallback vs statement-form if/else chains), writes (if/else chain ending
// in `assert(false)`), nested literal chains (single-hop resolve), and
// initializer distribution / length-mismatch rules.

package frontend

import (
	"fmt"
	"math/big"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ExpandFixedArraysResult carries the rewritten contract and any
// diagnostics produced during expansion. On errors the original contract
// is returned unchanged so the caller can still report the issues.
type ExpandFixedArraysResult struct {
	Contract *ContractNode
	Errors   []Diagnostic
}

// ExpandFixedArrays expands fixed-array properties into scalar sibling
// fields and rewrites every `index_access` on such properties into
// direct-access or dispatch form. Pure AST→AST.
func ExpandFixedArrays(contract *ContractNode) ExpandFixedArraysResult {
	ctx := newExpandContext(contract)
	if !ctx.collectArrays() {
		return ExpandFixedArraysResult{Contract: contract, Errors: ctx.errors}
	}
	if len(ctx.errors) > 0 {
		return ExpandFixedArraysResult{Contract: contract, Errors: ctx.errors}
	}
	if len(ctx.arrayMap) == 0 {
		// No fixed-array properties — return the contract unchanged.
		return ExpandFixedArraysResult{Contract: contract, Errors: nil}
	}

	newProps := ctx.rewriteProperties()
	if len(ctx.errors) > 0 {
		return ExpandFixedArraysResult{Contract: contract, Errors: ctx.errors}
	}

	newCtor := ctx.rewriteMethod(contract.Constructor)
	newMethods := make([]MethodNode, len(contract.Methods))
	for i, m := range contract.Methods {
		newMethods[i] = ctx.rewriteMethod(m)
	}
	if len(ctx.errors) > 0 {
		return ExpandFixedArraysResult{Contract: contract, Errors: ctx.errors}
	}

	rewritten := *contract
	rewritten.Properties = newProps
	rewritten.Constructor = newCtor
	rewritten.Methods = newMethods
	return ExpandFixedArraysResult{Contract: &rewritten, Errors: nil}
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

// arrayMeta mirrors TS `ArrayMeta`. It holds the expansion metadata for a
// top-level (or nested intermediate) FixedArray property: its per-slot
// synthetic names, whether each slot is itself another array, the element
// type of the outer slot, and the recursive meta for any nested slots.
type arrayMeta struct {
	rootName    string
	typ         FixedArrayType
	slotNames   []string
	slotIsArray bool
	elementType TypeNode
	// nested is populated only when slotIsArray is true. Keyed by slot name.
	nested map[string]*arrayMeta
}

type expandContext struct {
	contract *ContractNode
	errors   []Diagnostic

	// arrayMap holds the top-level array properties, keyed by original name.
	arrayMap map[string]*arrayMeta

	// syntheticArrays holds every intermediate-level array meta (the
	// `grid__0` of a nested grid), keyed by synthetic name.
	syntheticArrays map[string]*arrayMeta

	// tempCounter is a monotonic counter used to mint fresh hoisted temp
	// names (`__idx_0`, `__val_0`, …). Matches the TS pass exactly.
	tempCounter int
}

func newExpandContext(contract *ContractNode) *expandContext {
	return &expandContext{
		contract:        contract,
		arrayMap:        map[string]*arrayMeta{},
		syntheticArrays: map[string]*arrayMeta{},
	}
}

func (ctx *expandContext) pushError(msg string, loc SourceLocation) {
	l := loc
	ctx.errors = append(ctx.errors, MakeDiagnostic(msg, SeverityError, &l))
}

func (ctx *expandContext) freshIdxName() string {
	n := ctx.tempCounter
	ctx.tempCounter++
	return fmt.Sprintf("__idx_%d", n)
}

func (ctx *expandContext) freshValName() string {
	n := ctx.tempCounter
	ctx.tempCounter++
	return fmt.Sprintf("__val_%d", n)
}

// collectArrays scans the top-level properties, building the per-property
// expansion metadata. Returns false on fatal errors (invalid element type
// or non-positive length).
func (ctx *expandContext) collectArrays() bool {
	for _, prop := range ctx.contract.Properties {
		farr, ok := prop.Type.(FixedArrayType)
		if !ok {
			continue
		}
		meta := ctx.buildArrayMeta(prop.Name, farr, prop.SourceLocation)
		if meta == nil {
			return false
		}
		ctx.arrayMap[prop.Name] = meta
	}
	return true
}

func (ctx *expandContext) buildArrayMeta(rootName string, typ FixedArrayType, loc SourceLocation) *arrayMeta {
	if prim, ok := typ.Element.(PrimitiveType); ok && prim.Name == "void" {
		ctx.pushError(fmt.Sprintf("FixedArray element type cannot be 'void' (property '%s')", rootName), loc)
		return nil
	}
	if typ.Length <= 0 {
		ctx.pushError(fmt.Sprintf("FixedArray length must be a positive integer (property '%s')", rootName), loc)
		return nil
	}

	slotNames := make([]string, typ.Length)
	for i := 0; i < typ.Length; i++ {
		slotNames[i] = fmt.Sprintf("%s__%d", rootName, i)
	}

	_, elemIsArray := typ.Element.(FixedArrayType)
	meta := &arrayMeta{
		rootName:    rootName,
		typ:         typ,
		slotNames:   slotNames,
		slotIsArray: elemIsArray,
		elementType: typ.Element,
	}
	if elemIsArray {
		meta.nested = map[string]*arrayMeta{}
		inner := typ.Element.(FixedArrayType)
		for _, slot := range slotNames {
			sub := ctx.buildArrayMeta(slot, inner, loc)
			if sub == nil {
				return nil
			}
			meta.nested[slot] = sub
			ctx.syntheticArrays[slot] = sub
		}
	}
	return meta
}

// ---------------------------------------------------------------------------
// Property rewriting (initializer distribution)
// ---------------------------------------------------------------------------

func (ctx *expandContext) rewriteProperties() []PropertyNode {
	var out []PropertyNode
	for _, prop := range ctx.contract.Properties {
		if _, ok := prop.Type.(FixedArrayType); !ok {
			out = append(out, prop)
			continue
		}
		meta := ctx.arrayMap[prop.Name]
		if meta == nil {
			continue
		}
		expanded := ctx.expandPropertyRoot(prop, meta)
		out = append(out, expanded...)
	}
	return out
}

func (ctx *expandContext) expandPropertyRoot(prop PropertyNode, meta *arrayMeta) []PropertyNode {
	elements, status := ctx.extractArrayLiteralElements(prop, meta)
	if status == extractErr {
		return nil
	}
	return ctx.expandArrayMeta(meta, prop.Readonly, prop.SourceLocation, elements, nil)
}

type extractStatus int

const (
	extractOK  extractStatus = 0
	extractNil extractStatus = 1
	extractErr extractStatus = 2
)

func (ctx *expandContext) extractArrayLiteralElements(prop PropertyNode, meta *arrayMeta) ([]Expression, extractStatus) {
	if prop.Initializer == nil {
		return nil, extractNil
	}
	arrLit, ok := prop.Initializer.(ArrayLiteralExpr)
	if !ok {
		ctx.pushError(
			fmt.Sprintf("Property '%s' of type FixedArray must use an array literal initializer", prop.Name),
			prop.SourceLocation,
		)
		return nil, extractErr
	}
	if len(arrLit.Elements) != meta.typ.Length {
		ctx.pushError(
			fmt.Sprintf(
				"Initializer length %d does not match FixedArray length %d for property '%s'",
				len(arrLit.Elements), meta.typ.Length, prop.Name,
			),
			prop.SourceLocation,
		)
		return nil, extractErr
	}
	return arrLit.Elements, extractOK
}

// expandArrayMeta recursively emits scalar leaf properties for the given
// array meta. Initializer elements are distributed pairwise; for nested
// arrays a non-array-literal element is a compile error.
//
// `parentChain` is the accumulated chain of outer FixedArray levels
// already consumed above this call. Each leaf scalar receives a
// SyntheticArrayChain equal to parentChain plus this level's entry, so by
// the time we mint `grid__0__1` its chain is
// `[{base:"grid",index:0,length:2},{base:"grid__0",index:1,length:2}]`.
func (ctx *expandContext) expandArrayMeta(
	meta *arrayMeta,
	readonly bool,
	loc SourceLocation,
	initializer []Expression,
	parentChain []SyntheticArrayLevel,
) []PropertyNode {
	var out []PropertyNode
	for i := 0; i < len(meta.slotNames); i++ {
		slot := meta.slotNames[i]
		var slotInit Expression
		if i < len(initializer) {
			slotInit = initializer[i]
		}

		chainEntry := SyntheticArrayLevel{
			Base:   meta.rootName,
			Index:  i,
			Length: len(meta.slotNames),
		}
		chainHere := make([]SyntheticArrayLevel, 0, len(parentChain)+1)
		chainHere = append(chainHere, parentChain...)
		chainHere = append(chainHere, chainEntry)

		if meta.slotIsArray {
			nestedMeta := meta.nested[slot]
			var nestedInit []Expression
			if slotInit != nil {
				nested, ok := slotInit.(ArrayLiteralExpr)
				if !ok {
					ctx.pushError("Nested FixedArray element must be an array literal", loc)
					continue
				}
				if len(nested.Elements) != nestedMeta.typ.Length {
					ctx.pushError(
						fmt.Sprintf(
							"Nested FixedArray initializer length %d does not match expected length %d",
							len(nested.Elements), nestedMeta.typ.Length,
						),
						loc,
					)
					continue
				}
				nestedInit = nested.Elements
			}
			out = append(out, ctx.expandArrayMeta(nestedMeta, readonly, loc, nestedInit, chainHere)...)
		} else {
			out = append(out, PropertyNode{
				Name:                slot,
				Type:                meta.elementType,
				Readonly:            readonly,
				Initializer:         slotInit,
				SourceLocation:      loc,
				SyntheticArrayChain: append([]SyntheticArrayLevel(nil), chainHere...),
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Method rewriting
// ---------------------------------------------------------------------------

func (ctx *expandContext) rewriteMethod(method MethodNode) MethodNode {
	newBody := ctx.rewriteStatements(method.Body)
	m := method
	m.Body = newBody
	return m
}

func (ctx *expandContext) rewriteStatements(stmts []Statement) []Statement {
	var out []Statement
	for _, s := range stmts {
		produced := ctx.rewriteStatement(s)
		out = append(out, produced...)
	}
	return out
}

// rewriteStatement dispatches on statement kind and returns the
// (possibly multi-statement) replacement. Each branch may produce a
// prelude of hoisted `const __idx_K = ...` variable_decls ahead of the
// rewritten statement.
func (ctx *expandContext) rewriteStatement(stmt Statement) []Statement {
	switch s := stmt.(type) {
	case VariableDeclStmt:
		return ctx.rewriteVariableDecl(s)
	case AssignmentStmt:
		return ctx.rewriteAssignment(s)
	case IfStmt:
		return ctx.rewriteIfStmt(s)
	case ForStmt:
		return ctx.rewriteForStmt(s)
	case ReturnStmt:
		return ctx.rewriteReturnStmt(s)
	case ExpressionStmt:
		return ctx.rewriteExpressionStmt(s)
	}
	return []Statement{stmt}
}

func (ctx *expandContext) rewriteVariableDecl(stmt VariableDeclStmt) []Statement {
	// Statement-form dispatch for `const v = this.board[idx]`.
	stmtForm := ctx.tryRewriteReadAsStatements(
		stmt.Init,
		Identifier{Name: stmt.Name},
		stmt.SourceLocation,
	)
	if stmtForm != nil {
		// Replace the original const with a (let v = fallback) and an
		// if-chain that reassigns v for each in-range index.
		decl := stmt
		decl.Mutable = true
		decl.Init = stmtForm.fallbackInit
		out := append([]Statement{}, stmtForm.prelude...)
		out = append(out, decl)
		out = append(out, stmtForm.dispatch...)
		return out
	}

	var prelude []Statement
	newInit := ctx.rewriteExpression(stmt.Init, &prelude)
	s := stmt
	s.Init = newInit
	return append(prelude, s)
}

func (ctx *expandContext) rewriteAssignment(stmt AssignmentStmt) []Statement {
	var prelude []Statement

	// Writes to `this.board[...]`.
	if idx, ok := stmt.Target.(IndexAccessExpr); ok {
		// Try to resolve a nested literal-index chain `this.grid[0][1] = v`
		// into a single synthetic leaf `this.grid__0__1 = v`.
		resolved, status := ctx.tryResolveLiteralIndexChain(idx)
		switch status {
		case resolveErr:
			// Diagnostic already pushed.
			return prelude
		case resolveOK:
			rv := ctx.rewriteExpression(stmt.Value, &prelude)
			return append(prelude, AssignmentStmt{
				Target:         PropertyAccessExpr{Property: resolved},
				Value:          rv,
				SourceLocation: stmt.SourceLocation,
			})
		}

		// Top-level runtime-index or literal-index write on a known array.
		if obj, ok := idx.Object.(PropertyAccessExpr); ok {
			if _, known := ctx.arrayMap[obj.Property]; known {
				return ctx.rewriteArrayWrite(stmt, &prelude)
			}
		}
		// Non-fixed-array index targets — rewrite sub-expressions only.
		newIndex := ctx.rewriteExpression(idx.Index, &prelude)
		newObj := ctx.rewriteExpression(idx.Object, &prelude)
		newValue := ctx.rewriteExpression(stmt.Value, &prelude)
		newIdx := idx
		newIdx.Index = newIndex
		newIdx.Object = newObj
		s := stmt
		s.Target = newIdx
		s.Value = newValue
		return append(prelude, s)
	}

	// Statement-form dispatch for `target = this.board[i]` (target must be
	// an identifier or property_access).
	if _, isID := stmt.Target.(Identifier); isID {
		if sf := ctx.tryRewriteReadAsStatements(stmt.Value, stmt.Target, stmt.SourceLocation); sf != nil {
			fallbackAssign := AssignmentStmt{
				Target:         stmt.Target,
				Value:          sf.fallbackInit,
				SourceLocation: stmt.SourceLocation,
			}
			out := append([]Statement{}, sf.prelude...)
			out = append(out, fallbackAssign)
			out = append(out, sf.dispatch...)
			return out
		}
	}
	if _, isProp := stmt.Target.(PropertyAccessExpr); isProp {
		if sf := ctx.tryRewriteReadAsStatements(stmt.Value, stmt.Target, stmt.SourceLocation); sf != nil {
			fallbackAssign := AssignmentStmt{
				Target:         stmt.Target,
				Value:          sf.fallbackInit,
				SourceLocation: stmt.SourceLocation,
			}
			out := append([]Statement{}, sf.prelude...)
			out = append(out, fallbackAssign)
			out = append(out, sf.dispatch...)
			return out
		}
	}

	newTarget := ctx.rewriteExpression(stmt.Target, &prelude)
	newValue := ctx.rewriteExpression(stmt.Value, &prelude)
	s := stmt
	s.Target = newTarget
	s.Value = newValue
	return append(prelude, s)
}

func (ctx *expandContext) rewriteIfStmt(stmt IfStmt) []Statement {
	var prelude []Statement
	newCond := ctx.rewriteExpression(stmt.Condition, &prelude)
	newThen := ctx.rewriteStatements(stmt.Then)
	var newElse []Statement
	if stmt.Else != nil {
		newElse = ctx.rewriteStatements(stmt.Else)
	}
	s := stmt
	s.Condition = newCond
	s.Then = newThen
	s.Else = newElse
	return append(prelude, s)
}

func (ctx *expandContext) rewriteForStmt(stmt ForStmt) []Statement {
	var prelude []Statement
	newCond := ctx.rewriteExpression(stmt.Condition, &prelude)

	var initPrelude []Statement
	newInitInit := ctx.rewriteExpression(stmt.Init.Init, &initPrelude)
	if len(initPrelude) > 0 {
		prelude = append(prelude, initPrelude...)
	}

	newUpdateList := ctx.rewriteStatement(stmt.Update)
	newBody := ctx.rewriteStatements(stmt.Body)
	var newUpdate Statement
	if len(newUpdateList) == 1 {
		newUpdate = newUpdateList[0]
	} else if len(newUpdateList) > 0 {
		newUpdate = newUpdateList[len(newUpdateList)-1]
		newBody = append(newBody, newUpdateList[:len(newUpdateList)-1]...)
	}

	newInit := stmt.Init
	newInit.Init = newInitInit

	s := stmt
	s.Init = newInit
	s.Condition = newCond
	s.Update = newUpdate
	s.Body = newBody
	return append(prelude, s)
}

func (ctx *expandContext) rewriteReturnStmt(stmt ReturnStmt) []Statement {
	if stmt.Value == nil {
		return []Statement{stmt}
	}
	var prelude []Statement
	newValue := ctx.rewriteExpression(stmt.Value, &prelude)
	s := stmt
	s.Value = newValue
	return append(prelude, s)
}

func (ctx *expandContext) rewriteExpressionStmt(stmt ExpressionStmt) []Statement {
	var prelude []Statement
	newExpr := ctx.rewriteExpression(stmt.Expr, &prelude)
	s := stmt
	s.Expr = newExpr
	return append(prelude, s)
}

// ---------------------------------------------------------------------------
// Expression rewriting
// ---------------------------------------------------------------------------

// rewriteExpression rewrites an expression, appending any hoisted prelude
// statements to `prelude` and returning the replacement expression.
func (ctx *expandContext) rewriteExpression(expr Expression, prelude *[]Statement) Expression {
	switch e := expr.(type) {
	case IndexAccessExpr:
		return ctx.rewriteIndexAccess(e, prelude)
	case BinaryExpr:
		left := ctx.rewriteExpression(e.Left, prelude)
		right := ctx.rewriteExpression(e.Right, prelude)
		e.Left = left
		e.Right = right
		return e
	case UnaryExpr:
		operand := ctx.rewriteExpression(e.Operand, prelude)
		e.Operand = operand
		return e
	case CallExpr:
		callee := ctx.rewriteExpression(e.Callee, prelude)
		args := make([]Expression, len(e.Args))
		for i, a := range e.Args {
			args[i] = ctx.rewriteExpression(a, prelude)
		}
		e.Callee = callee
		e.Args = args
		return e
	case MemberExpr:
		obj := ctx.rewriteExpression(e.Object, prelude)
		e.Object = obj
		return e
	case TernaryExpr:
		cond := ctx.rewriteExpression(e.Condition, prelude)
		cons := ctx.rewriteExpression(e.Consequent, prelude)
		alt := ctx.rewriteExpression(e.Alternate, prelude)
		e.Condition = cond
		e.Consequent = cons
		e.Alternate = alt
		return e
	case IncrementExpr:
		operand := ctx.rewriteExpression(e.Operand, prelude)
		e.Operand = operand
		return e
	case DecrementExpr:
		operand := ctx.rewriteExpression(e.Operand, prelude)
		e.Operand = operand
		return e
	case ArrayLiteralExpr:
		elems := make([]Expression, len(e.Elements))
		for i, el := range e.Elements {
			elems[i] = ctx.rewriteExpression(el, prelude)
		}
		e.Elements = elems
		return e
	}
	return expr
}

// rewriteIndexAccess rewrites `this.board[idx]` (as a read).
func (ctx *expandContext) rewriteIndexAccess(expr IndexAccessExpr, prelude *[]Statement) Expression {
	// Nested fully-literal chains resolve in a single hop.
	nested, status := ctx.tryResolveLiteralIndexChain(expr)
	if status == resolveErr {
		return BigIntLiteral{Value: big.NewInt(0)}
	}
	if status == resolveOK {
		return PropertyAccessExpr{Property: nested}
	}

	baseName := ctx.tryResolveArrayBase(expr.Object)
	if baseName == "" {
		// Not a fixed-array property — recurse into sub-expressions.
		obj := ctx.rewriteExpression(expr.Object, prelude)
		idx := ctx.rewriteExpression(expr.Index, prelude)
		e := expr
		e.Object = obj
		e.Index = idx
		return e
	}

	meta := ctx.arrayMap[baseName]
	if meta == nil {
		meta = ctx.syntheticArrays[baseName]
	}
	if meta == nil {
		obj := ctx.rewriteExpression(expr.Object, prelude)
		idx := ctx.rewriteExpression(expr.Index, prelude)
		e := expr
		e.Object = obj
		e.Index = idx
		return e
	}

	loc := SourceLocation{}
	literal, hasLiteral := ctx.asLiteralIndex(expr.Index)
	if hasLiteral {
		if literal.Sign() < 0 || literal.Cmp(big.NewInt(int64(meta.typ.Length))) >= 0 {
			ctx.pushError(
				fmt.Sprintf("Index %s is out of range for FixedArray of length %d", literal.String(), meta.typ.Length),
				loc,
			)
			return BigIntLiteral{Value: big.NewInt(0)}
		}
		slot := meta.slotNames[int(literal.Int64())]
		return PropertyAccessExpr{Property: slot}
	}

	// Runtime index — hoist if impure, build the ternary dispatch chain.
	rewrittenIndex := ctx.rewriteExpression(expr.Index, prelude)
	indexRef := ctx.hoistIfImpure(rewrittenIndex, prelude, loc, "idx")

	if meta.slotIsArray {
		ctx.pushError("Runtime index access on a nested FixedArray is not supported in the v1 spike", loc)
		return BigIntLiteral{Value: big.NewInt(0)}
	}
	return ctx.buildReadDispatchTernary(meta, indexRef)
}

// ---------------------------------------------------------------------------
// Statement-form runtime read
// ---------------------------------------------------------------------------

type readAsStatements struct {
	prelude      []Statement
	fallbackInit Expression
	dispatch     []Statement
}

// tryRewriteReadAsStatements emits the shorter statement-form dispatch
// (fallback assignment + if/else-if chain) for a runtime-index read. See
// the TS reference for the detailed semantics, including the deliberate
// lack of bounds checking (matches ternary-form fallback behaviour).
func (ctx *expandContext) tryRewriteReadAsStatements(
	initExpr Expression,
	target Expression,
	loc SourceLocation,
) *readAsStatements {
	idxAccess, ok := initExpr.(IndexAccessExpr)
	if !ok {
		return nil
	}
	baseName := ctx.tryResolveArrayBase(idxAccess.Object)
	if baseName == "" {
		return nil
	}
	meta := ctx.arrayMap[baseName]
	if meta == nil {
		meta = ctx.syntheticArrays[baseName]
	}
	if meta == nil {
		return nil
	}
	// Literal indices are handled by the expression rewriter.
	if _, hasLit := ctx.asLiteralIndex(idxAccess.Index); hasLit {
		return nil
	}
	// Nested runtime indices not supported.
	if meta.slotIsArray {
		return nil
	}

	var prelude []Statement
	rewrittenIndex := ctx.rewriteExpression(idxAccess.Index, &prelude)
	indexRef := ctx.hoistIfImpure(rewrittenIndex, &prelude, loc, "idx")

	N := len(meta.slotNames)
	if N < 2 {
		return &readAsStatements{
			prelude:      prelude,
			fallbackInit: PropertyAccessExpr{Property: meta.slotNames[0]},
			dispatch:     nil,
		}
	}

	fallbackInit := PropertyAccessExpr{Property: meta.slotNames[N-1]}

	// Build `if (idx === 0) target = board__0; else if (idx === 1) ...`
	// from the tail toward the head so the chain is left-leaning. The
	// (N-1)th branch is the implicit else — the fallback already holds
	// `board__{N-1}`.
	var tailElse []Statement
	for i := N - 2; i >= 0; i-- {
		slot := meta.slotNames[i]
		cond := BinaryExpr{
			Op:    "===",
			Left:  cloneExpression(indexRef),
			Right: BigIntLiteral{Value: big.NewInt(int64(i))},
		}
		assign := AssignmentStmt{
			Target:         cloneExpression(target),
			Value:          PropertyAccessExpr{Property: slot},
			SourceLocation: loc,
		}
		ifStmt := IfStmt{
			Condition:      cond,
			Then:           []Statement{assign},
			Else:           tailElse,
			SourceLocation: loc,
		}
		tailElse = []Statement{ifStmt}
	}

	var dispatch []Statement
	if tailElse != nil {
		dispatch = append(dispatch, tailElse...)
	}
	return &readAsStatements{
		prelude:      prelude,
		fallbackInit: fallbackInit,
		dispatch:     dispatch,
	}
}

// buildReadDispatchTernary builds
// `(idx===0)?s0:((idx===1)?s1:...:sN-1)` — matches TicTacToe's
// getCellOrOverride semantics. Out-of-range indices fall through to the
// last slot (no bounds check). See TS reference for rationale.
func (ctx *expandContext) buildReadDispatchTernary(meta *arrayMeta, indexRef Expression) Expression {
	var chain Expression = PropertyAccessExpr{Property: meta.slotNames[len(meta.slotNames)-1]}
	for i := len(meta.slotNames) - 2; i >= 0; i-- {
		slot := meta.slotNames[i]
		cond := BinaryExpr{
			Op:    "===",
			Left:  cloneExpression(indexRef),
			Right: BigIntLiteral{Value: big.NewInt(int64(i))},
		}
		branch := PropertyAccessExpr{Property: slot}
		chain = TernaryExpr{
			Condition:  cond,
			Consequent: branch,
			Alternate:  chain,
		}
	}
	return chain
}

// rewriteArrayWrite rewrites `this.board[idx] = v` into either a direct
// property assignment (literal index) or an if/else statement chain
// (runtime index), with side-effectful expressions hoisted.
func (ctx *expandContext) rewriteArrayWrite(stmt AssignmentStmt, prelude *[]Statement) []Statement {
	idxAccess := stmt.Target.(IndexAccessExpr)
	obj := idxAccess.Object.(PropertyAccessExpr)
	meta := ctx.arrayMap[obj.Property]
	if meta == nil {
		return []Statement{stmt}
	}

	rewrittenValue := ctx.rewriteExpression(stmt.Value, prelude)
	rewrittenIndex := ctx.rewriteExpression(idxAccess.Index, prelude)
	loc := stmt.SourceLocation

	if literal, hasLit := ctx.asLiteralIndex(rewrittenIndex); hasLit {
		if literal.Sign() < 0 || literal.Cmp(big.NewInt(int64(meta.typ.Length))) >= 0 {
			ctx.pushError(
				fmt.Sprintf("Index %s is out of range for FixedArray of length %d", literal.String(), meta.typ.Length),
				loc,
			)
			return *prelude
		}
		if meta.slotIsArray {
			ctx.pushError("Cannot assign to a nested FixedArray sub-array as a whole", loc)
			return *prelude
		}
		slot := meta.slotNames[int(literal.Int64())]
		out := append([]Statement{}, *prelude...)
		out = append(out, AssignmentStmt{
			Target:         PropertyAccessExpr{Property: slot},
			Value:          rewrittenValue,
			SourceLocation: loc,
		})
		return out
	}

	if meta.slotIsArray {
		ctx.pushError("Runtime index assignment on a nested FixedArray is not supported in the v1 spike", loc)
		return *prelude
	}

	indexRef := ctx.hoistIfImpure(rewrittenIndex, prelude, loc, "idx")
	valueRef := ctx.hoistIfImpure(rewrittenValue, prelude, loc, "val")

	branches := ctx.buildWriteDispatchIf(meta, indexRef, valueRef, loc)
	out := append([]Statement{}, *prelude...)
	out = append(out, branches)
	return out
}

func (ctx *expandContext) buildWriteDispatchIf(
	meta *arrayMeta,
	indexRef, valueRef Expression,
	loc SourceLocation,
) IfStmt {
	assertFalse := ExpressionStmt{
		Expr: CallExpr{
			Callee: Identifier{Name: "assert"},
			Args:   []Expression{BoolLiteral{Value: false}},
		},
		SourceLocation: loc,
	}
	var tail []Statement = []Statement{assertFalse}
	for i := len(meta.slotNames) - 1; i >= 0; i-- {
		slot := meta.slotNames[i]
		cond := BinaryExpr{
			Op:    "===",
			Left:  cloneExpression(indexRef),
			Right: BigIntLiteral{Value: big.NewInt(int64(i))},
		}
		branchAssign := AssignmentStmt{
			Target:         PropertyAccessExpr{Property: slot},
			Value:          cloneExpression(valueRef),
			SourceLocation: loc,
		}
		ifStmt := IfStmt{
			Condition:      cond,
			Then:           []Statement{branchAssign},
			Else:           tail,
			SourceLocation: loc,
		}
		tail = []Statement{ifStmt}
	}
	return tail[0].(IfStmt)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type resolveStatus int

const (
	resolveNone resolveStatus = 0
	resolveOK   resolveStatus = 1
	resolveErr  resolveStatus = 2
)

// tryResolveLiteralIndexChain mirrors the TS helper: flatten a
// fully-literal-indexed chain like `this.grid[0][1]` into the single
// synthetic leaf name `grid__0__1`. Returns resolveOK with the leaf name
// on success, resolveErr if a literal index is out of range (a diagnostic
// is pushed), and resolveNone otherwise (caller falls back to generic
// rewriting).
func (ctx *expandContext) tryResolveLiteralIndexChain(expr IndexAccessExpr) (string, resolveStatus) {
	// Collect literal indices from innermost to outermost.
	var literalIndices []int
	var cursor Expression = expr
	for {
		idxExpr, ok := cursor.(IndexAccessExpr)
		if !ok {
			break
		}
		lit, ok := ctx.asLiteralIndex(idxExpr.Index)
		if !ok {
			return "", resolveNone
		}
		// We only support non-negative literal indices for chains; the
		// bounds check below catches negatives.
		if !lit.IsInt64() {
			return "", resolveNone
		}
		literalIndices = append(literalIndices, int(lit.Int64()))
		cursor = idxExpr.Object
	}
	// After peeling, cursor must be a property_access on a known array.
	pa, ok := cursor.(PropertyAccessExpr)
	if !ok {
		return "", resolveNone
	}
	rootMeta := ctx.arrayMap[pa.Property]
	if rootMeta == nil {
		return "", resolveNone
	}

	// Reverse to outermost-first order.
	for i, j := 0, len(literalIndices)-1; i < j; i, j = i+1, j-1 {
		literalIndices[i], literalIndices[j] = literalIndices[j], literalIndices[i]
	}

	meta := rootMeta
	for level := 0; level < len(literalIndices); level++ {
		idx := literalIndices[level]
		if idx < 0 || idx >= meta.typ.Length {
			ctx.pushError(
				fmt.Sprintf("Index %d is out of range for FixedArray of length %d", idx, meta.typ.Length),
				SourceLocation{},
			)
			return "", resolveErr
		}
		slot := meta.slotNames[idx]
		if level == len(literalIndices)-1 {
			if meta.slotIsArray {
				return "", resolveNone
			}
			return slot, resolveOK
		}
		if !meta.slotIsArray {
			return "", resolveNone
		}
		meta = meta.nested[slot]
	}
	return "", resolveNone
}

// tryResolveArrayBase returns the base name if `obj` is a property_access
// referring to a known top-level or intermediate synthetic FixedArray.
func (ctx *expandContext) tryResolveArrayBase(obj Expression) string {
	pa, ok := obj.(PropertyAccessExpr)
	if !ok {
		return ""
	}
	if _, known := ctx.arrayMap[pa.Property]; known {
		return pa.Property
	}
	if _, known := ctx.syntheticArrays[pa.Property]; known {
		return pa.Property
	}
	return ""
}

// asLiteralIndex returns the literal bigint value of an index expression,
// or false if the expression is not a literal.
func (ctx *expandContext) asLiteralIndex(expr Expression) (*big.Int, bool) {
	if lit, ok := expr.(BigIntLiteral); ok {
		return lit.Value, true
	}
	if un, ok := expr.(UnaryExpr); ok && un.Op == "-" {
		if lit, ok := un.Operand.(BigIntLiteral); ok {
			neg := new(big.Int).Neg(lit.Value)
			return neg, true
		}
	}
	return nil, false
}

// hoistIfImpure hoists an impure expression to a fresh `const __idx_K = ...`
// variable_decl in `prelude` and returns an identifier reference. Pure
// expressions (identifier, literal, property_access, negative literal)
// are returned unchanged.
func (ctx *expandContext) hoistIfImpure(
	expr Expression,
	prelude *[]Statement,
	loc SourceLocation,
	tag string,
) Expression {
	if isPureReference(expr) {
		return expr
	}
	var name string
	if tag == "idx" {
		name = ctx.freshIdxName()
	} else {
		name = ctx.freshValName()
	}
	decl := VariableDeclStmt{
		Name:           name,
		Mutable:        false,
		Init:           expr,
		SourceLocation: loc,
	}
	*prelude = append(*prelude, decl)
	return Identifier{Name: name}
}

func isPureReference(expr Expression) bool {
	switch e := expr.(type) {
	case Identifier, BigIntLiteral, BoolLiteral, ByteStringLiteral, PropertyAccessExpr:
		return true
	case UnaryExpr:
		if e.Op == "-" {
			if _, ok := e.Operand.(BigIntLiteral); ok {
				return true
			}
		}
		return false
	}
	return false
}

// cloneExpression produces a structural copy of an expression so the same
// logical value can be referenced from multiple dispatch branches without
// aliasing AST nodes. Mirrors the TS `cloneExpr` helper.
func cloneExpression(expr Expression) Expression {
	switch e := expr.(type) {
	case BigIntLiteral:
		if e.Value == nil {
			return BigIntLiteral{Value: nil}
		}
		return BigIntLiteral{Value: new(big.Int).Set(e.Value)}
	case BoolLiteral:
		return BoolLiteral{Value: e.Value}
	case ByteStringLiteral:
		return ByteStringLiteral{Value: e.Value}
	case Identifier:
		return Identifier{Name: e.Name}
	case PropertyAccessExpr:
		return PropertyAccessExpr{Property: e.Property}
	case BinaryExpr:
		return BinaryExpr{
			Op:    e.Op,
			Left:  cloneExpression(e.Left),
			Right: cloneExpression(e.Right),
		}
	case UnaryExpr:
		return UnaryExpr{
			Op:      e.Op,
			Operand: cloneExpression(e.Operand),
		}
	case CallExpr:
		args := make([]Expression, len(e.Args))
		for i, a := range e.Args {
			args[i] = cloneExpression(a)
		}
		return CallExpr{
			Callee: cloneExpression(e.Callee),
			Args:   args,
		}
	case MemberExpr:
		return MemberExpr{
			Object:   cloneExpression(e.Object),
			Property: e.Property,
		}
	case TernaryExpr:
		return TernaryExpr{
			Condition:  cloneExpression(e.Condition),
			Consequent: cloneExpression(e.Consequent),
			Alternate:  cloneExpression(e.Alternate),
		}
	case IndexAccessExpr:
		return IndexAccessExpr{
			Object: cloneExpression(e.Object),
			Index:  cloneExpression(e.Index),
		}
	case IncrementExpr:
		return IncrementExpr{
			Operand: cloneExpression(e.Operand),
			Prefix:  e.Prefix,
		}
	case DecrementExpr:
		return DecrementExpr{
			Operand: cloneExpression(e.Operand),
			Prefix:  e.Prefix,
		}
	case ArrayLiteralExpr:
		elems := make([]Expression, len(e.Elements))
		for i, el := range e.Elements {
			elems[i] = cloneExpression(el)
		}
		return ArrayLiteralExpr{Elements: elems}
	}
	return expr
}
