package frontend

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
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
		ParentClass:  contract.ParentClass,
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
	"P256Point":       true,
	"P384Point":       true,
}

var byteReturningFunctions = map[string]bool{
	"sha256":               true,
	"ripemd160":            true,
	"hash160":              true,
	"hash256":              true,
	"cat":                  true,
	"substr":               true,
	"num2bin":              true,
	"reverseBytes":         true,
	"left":                 true,
	"right":                true,
	"int2str":              true,
	"toByteString":         true,
	"pack":                 true,
	"ecAdd":                true,
	"ecMul":                true,
	"ecMulGen":             true,
	"ecNegate":             true,
	"ecMakePoint":          true,
	"ecEncodeCompressed":   true,
	"p256Add":              true,
	"p256Mul":              true,
	"p256MulGen":           true,
	"p256Negate":           true,
	"p256EncodeCompressed": true,
	"p384Add":              true,
	"p384Mul":              true,
	"p384MulGen":           true,
	"p384Negate":           true,
	"p384EncodeCompressed": true,
	"sha256Compress":       true,
	"sha256Finalize":       true,
	"blake3Compress":       true,
	"blake3Hash":           true,
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
			// Expression-form asm<ByteString>({...}) yields a byte value.
			if id.Name == "asm" {
				return e.AsmReturnType == "ByteString"
			}
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
			checkStateBigintMagnitude(&props[i])
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

// stateBigintMagnitudeLimit is the magnitude a bigint state field gets:
// num2bin-le8 is a fixed 8-byte little-endian SIGN-MAGNITUDE word, so bytes
// 0..6 plus the low 7 bits of byte 7 carry the magnitude and 0x80 of byte 7
// carries the sign.
var stateBigintMagnitudeLimit = new(big.Int).Lsh(big.NewInt(1), 63)

// checkStateBigintMagnitude rejects a MUTABLE bigint property initialised
// beyond the 8-byte state word.
//
// The state section writes every bigint field with OP_NUM2BIN 8, which cannot
// represent a magnitude of 2^63 or more. Nothing used to check: the compiler
// stamped `encoding: "num2bin-le8"` on the field and carried the initializer
// verbatim, the SDK wrote the low 8 bytes of it into the deployed state
// section, and the covenant then rebuilt the continuation with its own
// OP_NUM2BIN 8 — which produces different bytes — so hash256(outputs) never
// matched and the UTXO was permanently unspendable. It deployed cleanly, with
// no diagnostic at compile time or deploy time.
//
// This catches the statically-known half. Values that only exist at call time
// are stopped by the SDK serializer (packages/runar-go/sdk_state.go).
//
// READONLY properties are deliberately exempt: they are baked into the locking
// script as script-number pushes, never into the state section, and BSV script
// numbers are arbitrary-precision after Genesis.
func checkStateBigintMagnitude(prop *ir.ANFProperty) {
	if prop.Readonly {
		return
	}
	if prop.Type != "bigint" && prop.Type != "int" {
		return
	}
	v, ok := prop.InitialValue.(*big.Int)
	if !ok {
		return
	}
	if v.CmpAbs(stateBigintMagnitudeLimit) < 0 {
		return
	}
	panic(fmt.Sprintf(
		"Cannot compile state property '%s' initialised to %s: it does not fit "+
			"the fixed 8-byte sign-magnitude state word (magnitude must be < 2^63). "+
			"Reduce the value, or make the property readonly if it is a constant "+
			"rather than state.",
		prop.Name, v.String(),
	))
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

	// Single source of truth for "does this method (transitively) mutate
	// state, emit outputs, or use the preimage?" Shared across the lowering
	// pass so every public method's auto-injection sees private-helper
	// effects, not just direct ones.
	sideEffects := ComputeSideEffectSummary(contract)

	// Lower constructor (the TS reference includes the constructor in output)
	ctorCtx := newLowerCtxWithEffects(contract, sideEffects)
	ctorCtx.setMethodParamTypes(contract.Constructor.Params)
	ctorCtx.lowerStatements(contract.Constructor.Body)
	result = append(result, ir.ANFMethod{
		Name:     "constructor",
		Params:   lowerParams(contract.Constructor.Params),
		Body:     ctorCtx.bindings,
		IsPublic: false,
	})

	// Issue #109: readonly fields carrying a `/** @embedAlways */` directive
	// must survive DCE into the locking script. A readonly field no method
	// references lowers to no load_prop, so no constructor slot is emitted and
	// the field's deploy-time bytes vanish. We inject a load_prop + a `@ref:`
	// alias (the exact shape the `const _bind = this.field;` idiom produces)
	// into the FIRST public method's body — the alias keeps the load_prop alive
	// through dead-binding DCE, and stack lowering threads the pushed value
	// through and cleans it up at method end. One slot in the deployed script
	// suffices; every spending branch shares it.
	var embedFields []PropertyNode
	for _, p := range contract.Properties {
		if p.Readonly && p.EmbedAlways {
			embedFields = append(embedFields, p)
		}
	}
	embedInjected := false

	// Lower each method (including private methods as separate entries)
	for _, method := range contract.Methods {
		methodCtx := newLowerCtxWithEffects(contract, sideEffects)
		methodCtx.setMethodParamTypes(method.Params)

		// Issue #123: a non-default @sighash mode drives the OP_PUSH_TX binding
		// flag for any checkPreimage (auto-injected below, or a manual call) in
		// this method, and rides on the ANF method as a carrier the artifact
		// assembler copies to ABIMethod.SigHashType (omitted for the default).
		var methodSigHash *int
		if method.SighashType != nil && *method.SighashType != SighashDefault {
			methodCtx.sighashFlag = method.SighashType
			methodSigHash = method.SighashType
		}

		// Register the declared param NAMES so a bare identifier resolves to
		// load_param before falling through to load_prop (issue #130). Without
		// this, a param whose name collides with a mutable state property
		// lowered to the stale deserialized property value instead of the
		// witness param. Explicit `this.x` is unaffected: it lowers via
		// lowerMemberExpr / the property_access isProperty branch, which always
		// emit load_prop regardless of param registration.
		for _, p := range method.Params {
			methodCtx.addParam(p.Name)
		}

		if contract.ParentClass == "StatefulSmartContract" && method.Visibility == "public" {
			// Continuation requirements come from the side-effect summary,
			// which walks the private-method call graph. A public method
			// that calls a private helper which mutates state or emits an
			// output must therefore inject the same continuation params
			// as if the public body did so directly.
			eff := sideEffects[method.Name]
			shape := ContinuationShapeFor(eff)
			needsChangeOutput := shape.NeedsChange
			needsNewAmount := shape.NeedsNewAmount

			// Register implicit parameters
			if needsChangeOutput {
				methodCtx.addParam("_changePKH", "Ripemd160")
				methodCtx.addParam("_changeAmount", "bigint")
			}
			if needsNewAmount {
				methodCtx.addParam("_newAmount", "bigint")
			}
			methodCtx.addParam("txPreimage", "SigHashPreimage")

			// Issue #123: the declared per-method sighash mode (default
			// ALL|FORKID). Drives BOTH the OP_PUSH_TX binding flag (so the
			// derived sig re-computes the tx sighash under this mode) AND the
			// runtime preimage-type assert.
			sighashMode := SighashDefault
			if method.SighashType != nil {
				sighashMode = *method.SighashType
			}
			isDefaultSighash := sighashMode == SighashDefault

			// Inject checkPreimage(txPreimage) at the start.
			preimageRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			checkPre := ir.ANFValue{Kind: "check_preimage", Preimage: preimageRef}
			// Omit for the default so the ANF (and pinned binding blob) is unchanged.
			if !isDefaultSighash {
				checkPre.SighashFlag = sighashMode
			}
			checkResult := methodCtx.emit(checkPre)
			methodCtx.emit(makeAssert(checkResult))

			// GAP-302 / #123: pin the sighash type to the declared mode. Without
			// this check the spend could use a DIFFERENT sighash flag than
			// declared that zeroes out preimage fields the contract (or its
			// continuation) relies on (hashOutputs / hashPrevouts / hashSequence).
			// The value defaults to 0x41 (SIGHASH_ALL|FORKID) so existing
			// contracts emit byte-identical ANF.
			sigHashPreimageRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			sigHashTypeRef := methodCtx.emit(makeCall("extractSigHashType", []string{sigHashPreimageRef}))
			expectedSigHashRef := methodCtx.emit(makeLoadConstInt(big.NewInt(int64(sighashMode))))
			sigHashOkRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: sigHashTypeRef, Right: expectedSigHashRef})
			methodCtx.emit(makeAssert(sigHashOkRef))

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

			// Issue #109: preserve @embedAlways fields at the first user-statement
			// position (after the checkPreimage/deserialize preamble), mirroring
			// where a `const _bind = this.field;` idiom would sit.
			if !embedInjected && len(embedFields) > 0 {
				emitEmbedAlwaysPreservation(methodCtx, embedFields)
				embedInjected = true
			}

			// Lower the developer's method body
			methodCtx.lowerStatements(method.Body)

			// Determine state continuation type.
			//
			// === Continuation-hash construction ===
			//
			// The auto-injected continuation assertion verifies that the spending
			// transaction's hashOutputs field matches a compiler-constructed hash
			// over the outputs this method declares. Outputs are concatenated in
			// the following order before hashing with hash256:
			//
			//   1. state outputs   (from this.addOutput / this.addRawOutput)
			//   2. data outputs    (from this.addDataOutput)
			//   3. change output   (P2PKH to _changePKH, value = _changeAmount)
			//
			// For the "single-output" fast path (no addOutput used, but state is
			// mutated OR data outputs were declared), the state output is
			// computed on the fly from (preimage, stateScript, _newAmount)
			// instead of coming from addOutputRefs. Data outputs may still be
			// declared in this mode and are inserted BETWEEN the single state
			// output and the change output.
			addOutputRefs := methodCtx.getAddOutputRefs()
			addDataOutputRefs := methodCtx.getAddDataOutputRefs()
			// Gate the continuation assertion on the same shape used for
			// param injection. Both must agree or the deployed locking
			// script will not match the auto-injected parameter list.
			if needsChangeOutput {
				// Build the P2PKH change output for hashOutputs verification.
				//
				// Issue #116: the SDK's BuildCallTransaction OMITS the change
				// output when `change <= 0` (an exact-cover call) and passes
				// `_changeAmount = 0`. Gate the change segment on `_changeAmount
				// != 0` at runtime so the hashed output set matches the SDK at
				// the exact-zero boundary — the segment is the P2PKH change
				// output when non-zero, and empty bytes (cat with empty is a
				// no-op) when zero, reproducing the omission. For any change > 0
				// the hashed bytes are unchanged; only the emitted script gains
				// the guard.
				changePKHRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "_changePKH"})
				changeAmountRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "_changeAmount"})
				zeroRef := methodCtx.emit(makeLoadConstInt(big.NewInt(0)))
				changeNonZeroRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "!==", Left: changeAmountRef, Right: zeroRef})
				changeThenCtx := methodCtx.subContext()
				changeThenCtx.emit(makeCall("buildChangeOutput", []string{changePKHRef, changeAmountRef}))
				methodCtx.syncCounter(changeThenCtx)
				changeElseCtx := methodCtx.subContext()
				changeElseCtx.emit(makeLoadConstString(""))
				methodCtx.syncCounter(changeElseCtx)
				changeOutputRef := methodCtx.emit(ir.ANFValue{
					Kind: "if",
					Cond: changeNonZeroRef,
					Then: changeThenCtx.bindings,
					Else: changeElseCtx.bindings,
				})

				if len(addOutputRefs) > 0 {
					// Multi-output continuation: concat all state outputs, then
					// all data outputs, then change output, then hash.
					accumulated := addOutputRefs[0]
					for i := 1; i < len(addOutputRefs); i++ {
						accumulated = methodCtx.emit(makeCall("cat", []string{accumulated, addOutputRefs[i]}))
					}
					for _, dataRef := range addDataOutputRefs {
						accumulated = methodCtx.emit(makeCall("cat", []string{accumulated, dataRef}))
					}
					accumulated = methodCtx.emit(makeCall("cat", []string{accumulated, changeOutputRef}))
					hashRef := methodCtx.emit(makeCall("hash256", []string{accumulated}))
					preimageRef2 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
					outputHashRef := methodCtx.emit(makeCall("extractOutputHash", []string{preimageRef2}))
					eqRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: hashRef, Right: outputHashRef, ResultType: "bytes"})
					methodCtx.emit(makeAutoInjectedStateCheckAssert(eqRef))
				} else {
					// Single-output continuation: build raw output bytes, then
					// splice in any declared data outputs, then concat with
					// change, then hash.
					stateScriptRef := methodCtx.emit(ir.ANFValue{Kind: "get_state_script"})
					preimageRef2 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
					newAmountRef := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "_newAmount"})
					contractOutputRef := methodCtx.emit(makeCall("computeStateOutput", []string{preimageRef2, stateScriptRef, newAmountRef}))
					accumulated := contractOutputRef
					for _, dataRef := range addDataOutputRefs {
						accumulated = methodCtx.emit(makeCall("cat", []string{accumulated, dataRef}))
					}
					allOutputs := methodCtx.emit(makeCall("cat", []string{accumulated, changeOutputRef}))
					hashRef := methodCtx.emit(makeCall("hash256", []string{allOutputs}))
					preimageRef4 := methodCtx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
					outputHashRef := methodCtx.emit(makeCall("extractOutputHash", []string{preimageRef4}))
					eqRef := methodCtx.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: hashRef, Right: outputHashRef, ResultType: "bytes"})
					methodCtx.emit(makeAutoInjectedStateCheckAssert(eqRef))
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

			// Intent-covenant intrinsic auto-injected witness params:
			// extractPrevOutputScript adds `_prevOutScript_<inputIndex>`
			// (one per distinct literal index referenced in the method);
			// requireOutputP2PKH adds a single `_serialisedOutputs`. Order
			// follows insertion order via methodScope.autoInjectedParams.
			// Appended AFTER txPreimage so unlocking scripts push them
			// adjacent to the preimage (matches existing _changePKH /
			// _changeAmount / _newAmount convention of trailing the user
			// args before the preimage anchor).
			augmentedParams = append(augmentedParams, methodCtx.methodScope.autoInjectedParams...)

			result = append(result, ir.ANFMethod{
				Name:        method.Name,
				Params:      augmentedParams,
				Body:        methodCtx.bindings,
				IsPublic:    true,
				SigHashType: methodSigHash,
			})
		} else {
			// Issue #109: stateless public methods (and stateless contracts'
			// spending entry points) are lowered here — inject @embedAlways
			// preservation into the first PUBLIC one before its body.
			if !embedInjected && len(embedFields) > 0 && method.Visibility == "public" {
				emitEmbedAlwaysPreservation(methodCtx, embedFields)
				embedInjected = true
			}
			methodCtx.lowerStatements(method.Body)
			augmented := lowerParams(method.Params)
			// Private methods can also call the intent intrinsics; capture
			// their auto-injected witness params so a public method that
			// inlines this private picks them up via the shared methodScope.
			// (Private methods are inlined into public bodies via
			// inlinePrivateMethodCall — that path reuses the public's
			// methodScope, so the auto-injection registers at the public
			// method's ABI augmentation step above. The private's own ABI
			// is still informative for non-inlined callees.)
			augmented = append(augmented, methodCtx.methodScope.autoInjectedParams...)
			result = append(result, ir.ANFMethod{
				Name:        method.Name,
				Params:      augmented,
				Body:        methodCtx.bindings,
				IsPublic:    method.Visibility == "public",
				SigHashType: methodSigHash,
			})
		}
	}

	return result
}

// emitEmbedAlwaysPreservation emits the DCE-surviving preservation pair for
// each `@embedAlways` readonly field into the given (public) method context
// (issue #109). Reproduces exactly what a hand-written `const _bind =
// this.field;` lowers to: a load_prop followed by a load_const("@ref:<t>")
// alias. The alias marks the load_prop as referenced (see dce.go), so
// dead-binding DCE keeps it; stack lowering then emits the field's
// constructor-slot placeholder and NIPs the unused value off the stack at
// method end. The field's bytes therefore remain in the deployed locking
// script for downstream recovery.
func emitEmbedAlwaysPreservation(ctx *lowerCtx, fields []PropertyNode) {
	for _, field := range fields {
		loadRef := ctx.emit(ir.ANFValue{Kind: "load_prop", Name: field.Name})
		ctx.emitNamed("__embedAlways_"+field.Name, makeLoadConstString("@ref:"+loadRef))
	}
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
	bindings          []ir.ANFBinding
	counter           int
	contract          *ContractNode
	localNames        map[string]bool    // tracks variable names registered via addLocal
	paramNames        map[string]bool    // tracks parameter names registered via addParam
	methodParamTypes  map[string]string  // tracks the CURRENT method's parameter types (issue #34); copied into sub-contexts
	addOutputRefs     []string           // tracks addOutput / addRawOutput binding refs (state outputs)
	addDataOutputRefs []string           // tracks addDataOutput binding refs — data outputs are included in the continuation hash AFTER state outputs and BEFORE the change output
	localAliases      map[string]string  // maps local variable names to their current ANF binding name (updated after if-statements that reassign locals in both branches)
	localByteVars     map[string]bool    // tracks local variables known to be byte-typed
	currentSourceLoc  *ir.SourceLocation // Debug: source location to attach to emitted ANF bindings
	// Param substitution stack used when inlining a private method's body
	// directly into this context. Each entry on top is the active alias
	// for that param. When the inlined body references that param, the
	// lowered identifier resolves to the aliased ref instead of emitting
	// load_param. Stacked so nested inlines compose correctly.
	paramAliasStack map[string][]string
	// Side-effect summary shared with auto-injection decisions. Used at
	// lowering time to decide whether a private call should be inlined
	// (so that helper's add_output / add_data_output ANF nodes register
	// on the caller's continuation hash) or remain a method_call for
	// stack lowering to inline later.
	sideEffects SideEffectSummary
	// methodScope is per-method state shared with all sub-contexts. Tracks
	// auto-injected witness parameters needed by intent-covenant intrinsics
	// (extractPrevOutputScript, requireOutputP2PKH) regardless of whether
	// the intrinsic is called from the method's top-level body or from
	// inside a nested block (if/else, ternary). See methodScopeT.
	methodScope *methodScopeT
	// sighashFlag is the declared non-default `@sighash` flag for the method
	// being lowered (issue #123), so a MANUAL checkPreimage(pre) call binds
	// under the same mode as the method's declared sighash. nil = default
	// ALL|FORKID, keeping the pinned binding blob unchanged. Propagated into
	// sub-contexts so a manual call inside an if/for body picks it up.
	sighashFlag *int
	// nested is true in every context produced by subContext() — inside an if
	// arm, a loop body, or an inlined helper's block — and false only in the
	// context a method's own body is lowered into. liftBranchUpdateProps walks
	// method.Body and does NOT recurse, so an `if` its recogniser accepts is
	// only actually REWRITTEN at method top level; lowerIfStatement needs the
	// same distinction before it defers to that pass.
	nested bool
}

// methodScopeT holds per-method bookkeeping shared by parent and
// sub-contexts. The ABI augmentation pass (after method body lowering)
// reads autoInjectedParams to append witness params to the final method
// param list.
type methodScopeT struct {
	autoInjectedParams      []ir.ANFParam   // append-only, insertion order
	autoInjectedSet         map[string]bool // dedup
	didEmitHashOutputsCheck bool            // requireOutputP2PKH emits its hashOutputs(preimage) check at most once per method
}

func newMethodScope() *methodScopeT {
	return &methodScopeT{autoInjectedSet: make(map[string]bool)}
}

// recordAutoInjectedParam adds a witness param to the method's ABI
// augmentation list (idempotent — second call with same name is a no-op).
func (ms *methodScopeT) recordAutoInjectedParam(name, typ string) {
	if ms.autoInjectedSet[name] {
		return
	}
	ms.autoInjectedSet[name] = true
	ms.autoInjectedParams = append(ms.autoInjectedParams, ir.ANFParam{Name: name, Type: typ})
}

func newLowerCtx(contract *ContractNode) *lowerCtx {
	return newLowerCtxWithEffects(contract, nil)
}

func newLowerCtxWithEffects(contract *ContractNode, summary SideEffectSummary) *lowerCtx {
	return &lowerCtx{
		contract:         contract,
		localNames:       make(map[string]bool),
		paramNames:       make(map[string]bool),
		methodParamTypes: make(map[string]string),
		localAliases:     make(map[string]string),
		localByteVars:    make(map[string]bool),
		paramAliasStack:  make(map[string][]string),
		sideEffects:      summary,
		methodScope:      newMethodScope(),
	}
}

// pushParamAlias records that subsequent identifier lookups for `name`
// should resolve to `aliasRef` until the matching pop. Stacked so
// nested inlines compose: pop returns the previous frame.
func (ctx *lowerCtx) pushParamAlias(name, aliasRef string) {
	ctx.paramAliasStack[name] = append(ctx.paramAliasStack[name], aliasRef)
}

func (ctx *lowerCtx) popParamAlias(name string) {
	stack := ctx.paramAliasStack[name]
	if len(stack) == 0 {
		return
	}
	stack = stack[:len(stack)-1]
	if len(stack) == 0 {
		delete(ctx.paramAliasStack, name)
	} else {
		ctx.paramAliasStack[name] = stack
	}
}

func (ctx *lowerCtx) getParamAlias(name string) (string, bool) {
	stack := ctx.paramAliasStack[name]
	if len(stack) == 0 {
		return "", false
	}
	return stack[len(stack)-1], true
}

// shouldInlinePrivate reports whether a call to `name` should be ANF-inlined
// rather than emitted as a method_call. True iff `name` is a private method
// that (transitively) emits state outputs (addOutput / addRawOutput) or data
// outputs (addDataOutput). Those refs MUST appear in the caller's binding
// stream so they participate in the continuation hash; without ANF-level
// inlining they would live in a sibling ANF method and the public method's
// continuation hash would miss them.
//
// Mutation-only private helpers (no output intrinsics) are intentionally
// NOT inlined — state mutation flows through state continuity (the
// continuation hash reads state via get_state_script after all mutations
// apply), not through output refs. Keeping the existing method_call +
// stack-lowering inlining path for those preserves byte-equality with the
// pre-fix corpus.
func (ctx *lowerCtx) shouldInlinePrivate(name string) bool {
	if ctx.sideEffects == nil {
		return false
	}
	if !ctx.isPrivateMethod(name) {
		return false
	}
	eff, ok := ctx.sideEffects[name]
	if !ok {
		return false
	}
	return eff.HasStateOutput || eff.HasDataOutput
}

// getPrivateMethod looks up a private method by name. Returns the method
// and true if found, zero value and false otherwise.
func (ctx *lowerCtx) getPrivateMethod(name string) (MethodNode, bool) {
	for _, m := range ctx.contract.Methods {
		if m.Name == name && m.Visibility == "private" {
			return m, true
		}
	}
	return MethodNode{}, false
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
// An optional type (variadic, at most one element) records the param's
// type in the method-scoped type table — used for auto-injected
// continuation params so getParamType still finds them (issue #34).
func (ctx *lowerCtx) addParam(name string, typ ...string) {
	ctx.paramNames[name] = true
	if len(typ) > 0 {
		ctx.methodParamTypes[name] = typ[0]
	}
}

// setMethodParamTypes records the current method's parameter types in the
// method-scoped table. Must be called once per method/constructor before
// lowering its body so getParamType only sees THIS method's params (issue #34).
func (ctx *lowerCtx) setMethodParamTypes(params []ParamNode) {
	ctx.methodParamTypes = make(map[string]string, len(params))
	for _, p := range params {
		ctx.methodParamTypes[p.Name] = typeNodeToString(p.Type)
	}
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

// addDataOutputRef tracks an addDataOutput binding ref — distinct from
// state outputs. Data outputs are concatenated into the continuation hash
// after all state outputs and before the change output.
func (ctx *lowerCtx) addDataOutputRef(ref string) {
	ctx.addDataOutputRefs = append(ctx.addDataOutputRefs, ref)
}

// getAddDataOutputRefs returns all addDataOutput refs collected during lowering.
func (ctx *lowerCtx) getAddDataOutputRefs() []string {
	return ctx.addDataOutputRefs
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
	// Restricted to the CURRENT method's parameters (issue #34). A cross-method
	// lookup poisoned the byte-type analysis when two methods shared a parameter
	// name (e.g. one method's local `x: bigint` collided with another method's
	// `x: ByteString` parameter), which flipped result_type to 'bytes' and made
	// stack lowering emit OP_CAT for an integer add.
	t, ok := ctx.methodParamTypes[name]
	return t, ok
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
		contract:         ctx.contract,
		counter:          ctx.counter,
		localNames:       make(map[string]bool),
		paramNames:       make(map[string]bool),
		methodParamTypes: make(map[string]string),
		localAliases:     make(map[string]string),
		localByteVars:    make(map[string]bool),
		methodScope:      ctx.methodScope, // shared pointer — auto-injection registers propagate up
		sighashFlag:      ctx.sighashFlag, // #123: nested manual checkPreimage inherits the method's mode
		nested:           true,
	}
	// Share local name set
	for k := range ctx.localNames {
		sub.localNames[k] = true
	}
	// Share param name set
	for k := range ctx.paramNames {
		sub.paramNames[k] = true
	}
	// Share method-scoped param types (issue #34) so nested blocks see the
	// same current-method param types and not other methods' params.
	for k, v := range ctx.methodParamTypes {
		sub.methodParamTypes[k] = v
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
	ctx.lowerStatementsWithReads(stmts, nil)
}

// lowerStatementsWithReads lowers a statement block, threading down the set of
// identifiers the enclosing blocks still read after this block ends. Only the
// block-forming statements (if / for) consume it; see readsAfterStatement.
func (ctx *lowerCtx) lowerStatementsWithReads(stmts []Statement, readsAfterBlock map[string]bool) {
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
			ctx.lowerStatementWithReads(modifiedIf, readsAfterBlock)
			return // remaining stmts are now inside the else branch
		}

		// Only the block-forming statements need to know what the code after
		// them still reads; computing it for every statement would be
		// quadratic for no benefit.
		var readsAfter map[string]bool
		switch stmt.(type) {
		case IfStmt, ForStmt:
			readsAfter = readsAfterStatement(stmts, i, readsAfterBlock)
		}
		ctx.lowerStatementWithReads(stmt, readsAfter)
	}
}

// readsAfterStatement returns the identifiers still readable once statement
// `index` of this block has run: everything the following statements in this
// block read, plus whatever the enclosing blocks read after this block.
//
// Used by lowerIfStatement to tell a branch-merged local that is dead after the
// `if` (safe) from one that is still live (not representable alongside a branch
// output — see branchOutputRejectionReason).
func readsAfterStatement(stmts []Statement, index int, readsAfterBlock map[string]bool) map[string]bool {
	reads := make(map[string]bool, len(readsAfterBlock))
	for name := range readsAfterBlock {
		reads[name] = true
	}
	for j := index + 1; j < len(stmts); j++ {
		collectStatementReads(stmts[j], reads)
	}
	return reads
}

// collectStatementReads collects every identifier a statement READS. The `x` in
// `x = expr` is a write, not a read, so a plain identifier assignment target is
// skipped; every other target form can still read locals.
func collectStatementReads(stmt Statement, out map[string]bool) {
	switch s := stmt.(type) {
	case VariableDeclStmt:
		collectExpressionReads(s.Init, out)
	case AssignmentStmt:
		if _, isIdent := s.Target.(Identifier); !isIdent {
			collectExpressionReads(s.Target, out)
		}
		collectExpressionReads(s.Value, out)
	case IfStmt:
		collectExpressionReads(s.Condition, out)
		for _, inner := range s.Then {
			collectStatementReads(inner, out)
		}
		for _, inner := range s.Else {
			collectStatementReads(inner, out)
		}
	case ForStmt:
		collectExpressionReads(s.Init.Init, out)
		collectExpressionReads(s.Condition, out)
		if s.Update != nil {
			collectStatementReads(s.Update, out)
		}
		for _, inner := range s.Body {
			collectStatementReads(inner, out)
		}
	case ReturnStmt:
		if s.Value != nil {
			collectExpressionReads(s.Value, out)
		}
	case ExpressionStmt:
		collectExpressionReads(s.Expr, out)
	}
}

// collectExpressionReads collects every identifier an expression reads.
func collectExpressionReads(expr Expression, out map[string]bool) {
	switch e := expr.(type) {
	case Identifier:
		out[e.Name] = true
	case BinaryExpr:
		collectExpressionReads(e.Left, out)
		collectExpressionReads(e.Right, out)
	case UnaryExpr:
		collectExpressionReads(e.Operand, out)
	case CallExpr:
		collectExpressionReads(e.Callee, out)
		for _, a := range e.Args {
			collectExpressionReads(a, out)
		}
	case MemberExpr:
		collectExpressionReads(e.Object, out)
	case TernaryExpr:
		collectExpressionReads(e.Condition, out)
		collectExpressionReads(e.Consequent, out)
		collectExpressionReads(e.Alternate, out)
	case IndexAccessExpr:
		collectExpressionReads(e.Object, out)
		collectExpressionReads(e.Index, out)
	case IncrementExpr:
		collectExpressionReads(e.Operand, out)
	case DecrementExpr:
		collectExpressionReads(e.Operand, out)
	case ArrayLiteralExpr:
		for _, el := range e.Elements {
			collectExpressionReads(el, out)
		}
	}
	// Literals and `this.x` property access read no locals.
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
	ctx.lowerStatementWithReads(stmt, nil)
}

func (ctx *lowerCtx) lowerStatementWithReads(stmt Statement, readsAfter map[string]bool) {
	// Propagate source location to emitted ANF bindings
	ctx.currentSourceLoc = stmtSourceLoc(stmt)
	defer func() { ctx.currentSourceLoc = nil }()

	switch s := stmt.(type) {
	case VariableDeclStmt:
		ctx.lowerVariableDecl(s)
	case AssignmentStmt:
		ctx.lowerAssignment(s)
	case IfStmt:
		ctx.lowerIfStatement(s, readsAfter)
	case ForStmt:
		ctx.lowerForStatement(s, readsAfter)
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

func (ctx *lowerCtx) lowerIfStatement(stmt IfStmt, readsAfter map[string]bool) {
	condRef := ctx.lowerExprToRef(stmt.Condition)

	// Lower then-block into sub-context
	thenCtx := ctx.subContext()
	thenCtx.lowerStatementsWithReads(stmt.Then, readsAfter)
	ctx.syncCounter(thenCtx)

	// Lower else-block into sub-context
	elseCtx := ctx.subContext()
	if len(stmt.Else) > 0 {
		elseCtx.lowerStatementsWithReads(stmt.Else, readsAfter)
	}
	ctx.syncCounter(elseCtx)

	// 2026-04-30 audit finding F2: when a branch contains output
	// intrinsics, append a cat-chain inside each branch so the
	// branch's terminal value is the concat of its output bytes
	// (state then data, in declaration order). This balances
	// runtime stack effects across branches and lets the parent's
	// continuation hash see a single ref representing the chosen
	// branch's full output set.
	thenOutputRefs := thenCtx.getAddOutputRefs()
	elseOutputRefs := elseCtx.getAddOutputRefs()
	thenDataRefs := thenCtx.getAddDataOutputRefs()
	elseDataRefs := elseCtx.getAddDataOutputRefs()
	branchHasOutputs := len(thenOutputRefs) > 0 || len(elseOutputRefs) > 0 ||
		len(thenDataRefs) > 0 || len(elseDataRefs) > 0

	thenOutputBytes := ""
	elseOutputBytes := ""
	if branchHasOutputs {
		thenOutputBytes = appendBranchOutputConcat(thenCtx)
		elseOutputBytes = appendBranchOutputConcat(elseCtx)
	}

	// Branch-merged locals (2 or more). An `if` expression carries exactly ONE
	// value, so the alias trick further down can only rewire post-branch
	// references for a SINGLE merged local. With two or more — or with the
	// arms reassigning DIFFERENT locals — every later reference kept naming
	// the pre-branch binding, i.e. the dead initial value, and stack lowering
	// then registered one stackMap slot for N physical results and resolved
	// every later operand one slot off. Reported privately 2026-08-03; see
	// packages/runar-testing/src/__tests__/branch-merged-locals-vm.test.ts.
	//
	// Fix: give both arms the SAME result set in the SAME order by appending
	// an explicit rebind of every merged local to each arm.
	mergedLocals := ctx.collectBranchMergedLocals(thenCtx, elseCtx)

	if branchHasOutputs {
		if reason := branchOutputRejectionReason(
			thenCtx, elseCtx, thenOutputBytes, elseOutputBytes, mergedLocals, readsAfter,
		); reason != "" {
			panic(fmt.Sprintf(
				"Cannot compile conditional that both declares outputs and %s. "+
					"Move the addOutput/addRawOutput/addDataOutput call after the "+
					"if-statement.",
				reason))
		}
	}

	// The `if`'s multi-result contract. Locals first, in the canonical merge
	// order both arms agree on, then the properties either arm writes, in
	// contract declaration order — so all seven tiers derive the same list from
	// the same source. Results[0] is the deepest slot of the block.
	armPropSeen := map[string]bool{}
	armProps := []string{}
	collectUpdatedProps(thenCtx.bindings, armPropSeen, &armProps)
	collectUpdatedProps(elseCtx.bindings, armPropSeen, &armProps)
	resultNames := append([]string{}, mergedLocals...)
	for _, p := range ctx.contract.Properties {
		if armPropSeen[p.Name] {
			resultNames = append(resultNames, p.Name)
		}
	}

	// The result list is keyed by NAME everywhere downstream: appendBranchResults
	// picks the local path or the property path per entry with armPropSeen[name],
	// and stack lowering's layout assertion compares the arm's top-N slot names
	// against this list. A local sharing a contract property's name therefore
	// appears TWICE — once as a merged local, once as an arm-written property —
	// and both entries take the PROPERTY path, so the local's value is silently
	// replaced by the property's. The layout assertion cannot see it: both slots
	// are legitimately named `count`. Refuse the exact collision only; shadowing
	// a property is otherwise fine.
	for _, name := range mergedLocals {
		if armPropSeen[name] {
			panic(fmt.Sprintf(
				"Local variable '%s' shadows contract property 'this.%s', and the "+
					"conditional assigns both. The branch's result slots are identified by "+
					"name, so the two cannot be told apart and the local's value would be "+
					"silently replaced by the property's. Rename the local.", name, name))
		}
	}

	// When to materialise the contract instead of leaving the arms to the
	// stack-lowerer's inference:
	//
	//   - two or more merged locals — the pre-existing normalisation. Kept on
	//     exactly its old trigger so the four `__merge$` goldens do not move.
	//   - any result at all when the ELSE arm carries code. This is the new
	//     case, and it is where every measured miscompile lives: one arm
	//     rebinds its local IN PLACE (net depth 0) while the other pushes a
	//     fresh slot (net +1), or an arm writes a property beside a rebound
	//     local, or the two arms write the same properties in a different
	//     order. The arms then leave different LAYOUTS, which no depth or
	//     liveness predicate can see.
	//
	// An `if` WITHOUT an else keeps the preserve-the-old-value path in lowerIf
	// (phase 3 copies each missing slot's same-named parent value), which
	// already produces exactly these results by construction — deliberately
	// left intact. An arm that emits outputs is excluded: its single value is
	// the serialised output bytes, and branchOutputRejectionReason above
	// already refuses every combination that would need a second result.
	//
	// EXCLUDED: an `if` that liftBranchUpdateProps will rewrite. That pass
	// (deep-review finding C20) turns a conditional-property-assignment chain
	// into one flat single-valued `if` per property plus a top-level
	// update_prop, so the surviving `if`s carry no property result and need no
	// declaration. Appending the normalisation block first would ALSO silently
	// disable that pass: its recogniser requires the arm's last binding to be
	// the update_prop with everything before it side-effect free, and the block
	// adds a second update_prop behind it. TicTacToe's position dispatch is
	// exactly that shape, and losing the lift there produced an unspendable
	// `move` script.
	//
	// The exclusion must be exactly "the lift WILL rewrite this `if`", which is
	// narrower than "the lift's recogniser accepts it" in TWO ways — both were
	// live defects that produced an unspendable UTXO:
	//
	//   1. liftBranchUpdateProps only rewrites chains of TWO OR MORE branches,
	//      but collectUpdateBranches returns a ONE-element list for the
	//      isAssertFalseElse path. `if (n > 0n) { this.count = ... } else
	//      { assert(false) }` — the idiomatic guard — was recognised, excluded,
	//      and then never rewritten.
	//   2. liftBranchUpdateProps only walks method.Body, passing loop bodies
	//      and surviving if arms through untouched, while declaresResults is
	//      evaluated at EVERY nesting depth.
	//
	// A chain's DEEPEST `if` is never at top level, so it now declares results
	// and carries a normalisation block — which is why collectUpdateBranches
	// strips a declared block before matching (stripDeclaredResults). The
	// enclosing chain is still recognised, still lifted, and the lift discards
	// the inner node, so the chain's bytes do not move.
	lifted := collectUpdateBranches(condRef, thenCtx.bindings, elseCtx.bindings)
	willBeLifted := !ctx.nested && lifted != nil && len(lifted) >= 2
	declaresResults := !branchHasOutputs &&
		!willBeLifted &&
		(len(mergedLocals) >= 2 || (len(resultNames) >= 1 && len(elseCtx.bindings) > 0))

	if declaresResults {
		appendBranchResults(thenCtx, resultNames, armPropSeen)
		ctx.syncCounter(thenCtx)
		appendBranchResults(elseCtx, resultNames, armPropSeen)
		ctx.syncCounter(elseCtx)
	}

	elseBindings := elseCtx.bindings
	if elseBindings == nil {
		elseBindings = []ir.ANFBinding{}
	}
	ifValue := ir.ANFValue{
		Kind: "if",
		Cond: condRef,
		Then: thenCtx.bindings,
		Else: elseBindings,
	}
	if declaresResults {
		ifValue.Results = resultNames
	}
	ifName := ctx.emit(ifValue)

	if branchHasOutputs {
		// Register the if's value once with the parent's continuation
		// tracker. CRITICAL: pick the right tracker. If either branch
		// produces a STATE output (addOutput / addRawOutput), the
		// parent must take the multi-output continuation path, so we
		// register as a state output ref. If neither branch produces a
		// state output and at least one branch produces a data output,
		// we register as a DATA output ref so the parent keeps its
		// single-output `computeStateOutput` continuation and the
		// data-output bytes splice in BETWEEN the state output and
		// the change output. Without this, a branch with only
		// `addDataOutput` was incorrectly forced onto the multi-output
		// path, dropping the canonical state continuation.
		branchHasStateOutput := len(thenOutputRefs) > 0 || len(elseOutputRefs) > 0
		if branchHasStateOutput {
			ctx.addOutputRef(ifName)
		} else {
			ctx.addDataOutputRef(ifName)
		}
	}

	// If both branches end by reassigning the same single local variable,
	// alias that variable to the if-expression result so that subsequent
	// references resolve to the branch output, not the dead initial value.
	//
	// Skipped when the arms were normalised above: there the `if` DECLARES its
	// results, and each one keeps its OWN name through the reconcile in the
	// stack lowerer.
	if !declaresResults && len(thenCtx.bindings) > 0 && len(elseCtx.bindings) > 0 {
		thenLast := thenCtx.bindings[len(thenCtx.bindings)-1]
		elseLast := elseCtx.bindings[len(elseCtx.bindings)-1]
		if thenLast.Name == elseLast.Name && ctx.isLocal(thenLast.Name) {
			ctx.setLocalAlias(thenLast.Name, ifName)
		}
	}
}

// collectBranchMergedLocals returns the locals from the enclosing scope that
// either arm of an if-statement reassigns, in a canonical order both arms can
// agree on: the then-arm's reassignments in order of last rebind, then the
// else-only ones in the same order.
//
// Only names the PARENT already knows as locals count — subContext copies the
// local-name set by value, so a local declared inside a branch never reaches
// the parent's set and is correctly excluded (it is not live after the if).
func (ctx *lowerCtx) collectBranchMergedLocals(thenCtx, elseCtx *lowerCtx) []string {
	lastRebindOrder := func(branch *lowerCtx) []string {
		lastIndex := make(map[string]int)
		var order []string
		for i, b := range branch.bindings {
			if !ctx.isLocal(b.Name) {
				continue
			}
			if _, seen := lastIndex[b.Name]; !seen {
				order = append(order, b.Name)
			}
			lastIndex[b.Name] = i
		}
		sort.SliceStable(order, func(a, b int) bool {
			return lastIndex[order[a]] < lastIndex[order[b]]
		})
		return order
	}
	merged := lastRebindOrder(thenCtx)
	for _, name := range lastRebindOrder(elseCtx) {
		found := false
		for _, existing := range merged {
			if existing == name {
				found = true
				break
			}
		}
		if !found {
			merged = append(merged, name)
		}
	}
	return merged
}

// appendBranchResults appends the canonical result block to one arm of an
// if-statement: a copy of every declared result, in the declared order,
// rebound under its own name. This is what makes the `if` node's Results
// contract true rather than hoped-for.
//
// Two passes on purpose. Pass 1 always COPIES: for a LOCAL, `@ref:<local>`
// resolves to the arm's own new value if it rebound one, else to the enclosing
// scope's value; for a PROPERTY, load_prop picks the arm's updated slot when
// the arm wrote it and otherwise the enclosing value. Either way stack
// lowering picks (never rolls) it, because a declared result is
// outer-protected. Pass 2 always CONSUMES, because the temps are bound in this
// arm and this is their last use. The arm's stack effect is therefore exactly
// +N regardless of which of the N results it assigned.
//
// Semantically a no-op for the off-chain ANF interpreters: every binding is an
// ordinary read-then-write of a value the arm already holds.
func appendBranchResults(branchCtx *lowerCtx, resultNames []string, props map[string]bool) {
	for i, name := range resultNames {
		temp := fmt.Sprintf("%s%d", ir.MergedLocalTempPrefix, i)
		if props[name] {
			branchCtx.emitNamed(temp, ir.ANFValue{Kind: "load_prop", Name: name})
		} else {
			branchCtx.emitNamed(temp, makeLoadConstString("@ref:"+name))
		}
	}
	for i, name := range resultNames {
		temp := fmt.Sprintf("%s%d", ir.MergedLocalTempPrefix, i)
		if props[name] {
			branchCtx.emit(makeUpdateProp(name, temp))
		} else {
			branchCtx.emitNamed(name, makeLoadConstString("@ref:"+temp))
		}
	}
}

// appendBranchOutputConcat concatenates a branch's output refs (state
// then data, in declaration order) into a single bytes-ref appended to
// the branch's bindings. If the branch has no outputs, emits an empty
// `load_const` so the branch still leaves one item on the stack —
// required to balance the if's branch shapes when the OTHER branch
// has outputs. 2026-04-30 audit finding F2 fix.
func appendBranchOutputConcat(branchCtx *lowerCtx) string {
	allRefs := append([]string{}, branchCtx.getAddOutputRefs()...)
	allRefs = append(allRefs, branchCtx.getAddDataOutputRefs()...)
	if len(allRefs) == 0 {
		return branchCtx.emit(makeLoadConstString(""))
	}
	if len(allRefs) == 1 {
		return allRefs[0]
	}
	accumulated := allRefs[0]
	for i := 1; i < len(allRefs); i++ {
		accumulated = branchCtx.emit(makeCall("cat", []string{accumulated, allRefs[i]}))
	}
	return accumulated
}

// branchOutputRejectionReason returns why an `if` whose arms declare outputs
// cannot be represented — or "" when it can. The result is the reason clause
// the diagnostic embeds.
//
// An `if` expression carries exactly ONE value, and when an arm emits an output
// that value is already spoken for: it is the output bytes the continuation
// hash consumes (appendBranchOutputConcat). Anything ELSE the arm leaves behind
// breaks one of two invariants that nothing downstream enforces:
//
//	INV-A  the parent registers the if-expression's value as the branch's
//	       contribution to the continuation hash, so "the branch's output
//	       bytes" really means "whatever the arm's LAST binding is". A binding
//	       that lands after the output — a rebound local, a property write —
//	       silently replaces the serialized output with an unrelated value,
//	       and the residue drain then physically drops the real output because
//	       it is no longer on top.
//	INV-B  an arm that emits an output AND leaves any other slot the parent
//	       can still name — a property write anywhere in the arm, or a rebound
//	       local that is still read after the `if` — leaves 2+ results against
//	       the ONE stackMap name the stack lowerer registers, desyncing the
//	       parent stack by a slot from there on. The residue drain cannot save
//	       it: it filters BY NAME and those names are all pre-`if` names.
//
// Neither is visible off-chain, so both shipped as permanently unspendable
// locking scripts. Refuse at compile time rather than emit one. See
// packages/runar-testing/src/__tests__/branch-output-terminal-value-vm.test.ts
// for the real-Script-VM proof of each shape.
//
// The clauses are checked in a fixed order so all seven tiers report the same
// reason for a source that trips more than one.
func branchOutputRejectionReason(
	thenCtx, elseCtx *lowerCtx,
	thenOutputBytes, elseOutputBytes string,
	mergedLocals []string,
	readsAfter map[string]bool,
) string {
	// 1. Two or more merged locals: normalising them would need a multi-result
	//    `if` node, and the arms' single value is already the output concat.
	if len(mergedLocals) >= 2 {
		return fmt.Sprintf("merges %d local variables (%s)",
			len(mergedLocals), strings.Join(mergedLocals, ", "))
	}

	// 2. INV-A: the arm's terminal binding must BE its output bytes.
	labels := []string{"then", "else"}
	branches := []*lowerCtx{thenCtx, elseCtx}
	outputBytes := []string{thenOutputBytes, elseOutputBytes}
	for i, branchCtx := range branches {
		if len(branchCtx.bindings) == 0 ||
			branchCtx.bindings[len(branchCtx.bindings)-1].Name != outputBytes[i] {
			return fmt.Sprintf("continues past its output in the %s-branch", labels[i])
		}
	}

	// 3. INV-B: a property write leaves a slot the parent can still name,
	//    wherever in the arm it sits.
	var writtenProps []string
	seenProps := map[string]bool{}
	for _, branchCtx := range branches {
		collectUpdatedProps(branchCtx.bindings, seenProps, &writtenProps)
	}
	if len(writtenProps) > 0 {
		return fmt.Sprintf("assigns contract properties (%s) inside the branch",
			strings.Join(writtenProps, ", "))
	}

	// 4. INV-B: a rebound local that survives the `if` is protected from being
	//    rolled away, so the arm ends one slot deeper than lowerIf accounts for.
	var liveMerged []string
	for _, name := range mergedLocals {
		if readsAfter[name] {
			liveMerged = append(liveMerged, name)
		}
	}
	if len(liveMerged) > 0 {
		return fmt.Sprintf("reassigns local variables read after it (%s)",
			strings.Join(liveMerged, ", "))
	}

	return ""
}

// collectUpdatedProps appends every property name an ANF binding list assigns,
// including the ones nested inside an `if` arm or a `loop` body — a nested
// write is just as much a named slot the enclosing arm leaves behind.
func collectUpdatedProps(bindings []ir.ANFBinding, seen map[string]bool, out *[]string) {
	for _, binding := range bindings {
		switch binding.Value.Kind {
		case "update_prop":
			if !seen[binding.Value.Name] {
				seen[binding.Value.Name] = true
				*out = append(*out, binding.Value.Name)
			}
		case "if":
			collectUpdatedProps(binding.Value.Then, seen, out)
			collectUpdatedProps(binding.Value.Else, seen, out)
		case "loop":
			collectUpdatedProps(binding.Value.Body, seen, out)
		}
	}
}

func (ctx *lowerCtx) lowerForStatement(stmt ForStmt, readsAfter map[string]bool) {
	// Resolve the loop's compile-time shape: start value, step direction, and
	// iteration count. Rúnar requires bounded loops, so all three must be
	// statically determinable (issue #121).
	start, step, count := extractLoopShape(stmt)

	// Lower body into sub-context. The body repeats, so every read anywhere in
	// it is a read that happens after any given statement inside it.
	bodyReads := make(map[string]bool, len(readsAfter))
	for name := range readsAfter {
		bodyReads[name] = true
	}
	for _, s := range stmt.Body {
		collectStatementReads(s, bodyReads)
	}

	bodyCtx := ctx.subContext()
	bodyCtx.lowerStatementsWithReads(stmt.Body, bodyReads)
	ctx.syncCounter(bodyCtx)

	ctx.emit(ir.ANFValue{
		Kind:     "loop",
		Count:    count,
		Body:     bodyCtx.bindings,
		IterVar:  stmt.Init.Name,
		Start:    start,
		StartRaw: bigIntStartRaw(start),
		Step:     step,
	})
}

// extractLoopShape resolves a for-statement's compile-time loop shape (issue
// #121): the iterator start value, step direction (+1/-1), and iteration count.
//
// Supports counting-up and counting-down loops:
//
//	for (let i = 0n; i < 10n; i++)  -> start 0, step +1, count 10
//	for (let i = 1n; i <= 3n; i++)  -> start 1, step +1, count 3
//	for (let i = 3n; i > 0n; i--)   -> start 3, step -1, count 3
//	for (let i = 3n; i >= 1n; i--)  -> start 3, step -1, count 3
//
// The loop is unrolled `count` times; on iteration i the iterator holds
// `start + i*step`. Start and bound must be compile-time integer literals; in
// the normal pipeline the validate pass rejects non-literal bounds first, so
// these panics guard callers that lower without validating.
func extractLoopShape(stmt ForStmt) (*big.Int, int, int) {
	start := extractBigIntValue(stmt.Init.Init)
	if start == nil {
		panic("Cannot determine loop start at compile time. For-loop iterators must start at an integer literal.")
	}

	bin, ok := stmt.Condition.(BinaryExpr)
	if !ok {
		panic("Cannot determine loop bound at compile time. For-loop bounds must be integer literals.")
	}
	bound := extractBigIntValue(bin.Right)
	if bound == nil {
		panic("Cannot determine loop bound at compile time. For-loop bounds must be integer literals.")
	}

	step := extractLoopStep(stmt)

	// Count = number of iterations before the condition first turns false.
	var count *big.Int
	if step == 1 {
		switch bin.Op {
		case "<":
			count = new(big.Int).Sub(bound, start)
		case "<=":
			count = new(big.Int).Add(new(big.Int).Sub(bound, start), big.NewInt(1))
		default:
			panic(fmt.Sprintf("For loop counting up (i++) must use '<' or '<=' (got '%s').", bin.Op))
		}
	} else {
		switch bin.Op {
		case ">":
			count = new(big.Int).Sub(start, bound)
		case ">=":
			count = new(big.Int).Add(new(big.Int).Sub(start, bound), big.NewInt(1))
		default:
			panic(fmt.Sprintf("For loop counting down (i--) must use '>' or '>=' (got '%s').", bin.Op))
		}
	}

	n := 0
	if count.Sign() > 0 {
		n = int(count.Int64())
	}
	return start, step, n
}

// extractLoopStep determines the iterator step direction (+1/-1) from the
// for-statement's update clause, falling back to the condition direction. Only
// unit steps are supported (issue #121).
func extractLoopStep(stmt ForStmt) int {
	if u, ok := stmt.Update.(ExpressionStmt); ok {
		switch u.Expr.(type) {
		case IncrementExpr:
			return 1
		case DecrementExpr:
			return -1
		}
	}
	// Fall back to the comparison direction for other unit-step spellings
	// (e.g. `i = i + 1n`): `<`/`<=` counts up, `>`/`>=` counts down.
	if bin, ok := stmt.Condition.(BinaryExpr); ok {
		if bin.Op == ">" || bin.Op == ">=" {
			return -1
		}
	}
	return 1
}

// bigIntStartRaw encodes a loop iterator start value into the raw JSON form the
// loop ANF node emits (issue #121), mirroring the load_const bigint encoding.
func bigIntStartRaw(val *big.Int) json.RawMessage {
	return ir.BigIntToRawJSON(val)
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
		// Explicit `this.x`: a real contract property always wins, even when a
		// method param shares the name (issue #130). Now that declared params
		// are registered, the isParam branch below must not shadow a stored
		// property.
		if ctx.isProperty(e.Property) {
			return ctx.emit(ir.ANFValue{Kind: "load_prop", Name: e.Property})
		}
		// this.txPreimage in StatefulSmartContract -> load_param (it's an
		// implicit injected param, not a stored property).
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

	// Param alias takes precedence over normal param lookup. Set when a
	// private method's body is being inlined into this context — the
	// private's param names map to the caller's arg refs.
	if alias, ok := ctx.getParamAlias(name); ok {
		return alias
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
			cp := ir.ANFValue{Kind: "check_preimage", Preimage: preimageRef}
			// Issue #123: honour the method's declared @sighash on manual calls.
			if ctx.sighashFlag != nil {
				cp.SighashFlag = *ctx.sighashFlag
			}
			return ctx.emit(cp)
		}
	}

	// extractPrevOutputScript(inputIndex_literal, expectedScriptHash) -> ByteString
	// extractPrevOutputScript(inputIndex_literal, expectedScriptPrefixHash, prefixLen_literal) -> ByteString
	//
	// Witness-bridge sugar (BSVM Phase 13). Auto-injects a hidden method
	// parameter named `_prevOutScript_<inputIndex>` (one per distinct index
	// in the method body), emits a hash assertion, and returns the witness
	// ref for caller substring extraction.
	//
	// 2-arg form: hash256(witness) === expectedScriptHash. Pins the full
	//   prev-output script byte-for-byte. Use when the prev-output is a
	//   single fixed-shape contract (e.g. bridge.runar.go pattern).
	// 3-arg form: hash256(substr(witness, 0, prefixLen)) ===
	//   expectedScriptPrefixHash. Pins the policy prefix only, leaving the
	//   pushdata tail free to vary. Required for the intent-template
	//   matching use case where each successor intent UTXO has a unique
	//   tail (BSVM Mode 3 permissionless step-in).
	if id, ok := callee.(Identifier); ok && id.Name == "extractPrevOutputScript" {
		if len(e.Args) != 2 && len(e.Args) != 3 {
			return ctx.emit(makeLoadConstString(""))
		}
		idxLit, ok := e.Args[0].(BigIntLiteral)
		if !ok || idxLit.Value == nil {
			return ctx.emit(makeLoadConstString(""))
		}
		idx := idxLit.Value.Int64()
		paramName := fmt.Sprintf("_prevOutScript_%d", idx)
		ctx.methodScope.recordAutoInjectedParam(paramName, "ByteString")
		ctx.addParam(paramName)
		witnessRef := ctx.emit(ir.ANFValue{Kind: "load_param", Name: paramName})
		expectedHashRef := ctx.lowerExprToRef(e.Args[1])

		// Determine which bytes to hash: full witness (2-arg) or
		// prefix (3-arg). The substr happens at script-execution time;
		// the literal prefixLen is baked into the emitted Stack-IR.
		var bytesToHashRef string
		if len(e.Args) == 3 {
			prefixLenLit, ok := e.Args[2].(BigIntLiteral)
			if !ok || prefixLenLit.Value == nil {
				return ctx.emit(makeLoadConstString(""))
			}
			zeroRef := ctx.emit(makeLoadConstInt(big.NewInt(0)))
			prefixLenRef := ctx.emit(makeLoadConstInt(new(big.Int).Set(prefixLenLit.Value)))
			bytesToHashRef = ctx.emit(makeCall("substr", []string{witnessRef, zeroRef, prefixLenRef}))
		} else {
			bytesToHashRef = witnessRef
		}

		actualHashRef := ctx.emit(makeCall("hash256", []string{bytesToHashRef}))
		eqRef := ctx.emit(ir.ANFValue{
			Kind: "bin_op", Op: "===",
			Left: actualHashRef, Right: expectedHashRef,
			ResultType: "bytes",
		})
		ctx.emit(makeAssert(eqRef))
		return witnessRef
	}

	// requireOutputP2PKH(outputIndex_literal, pubkeyHash, amount) -> void.
	// Asserts that the tx's output at outputIndex is a standard P2PKH paying
	// `amount` satoshis to `pubkeyHash`. Auto-injects `_serialisedOutputs`
	// (once per method) and emits hash256(serialisedOutputs) ==
	// extractOutputHash(txPreimage) the first time the intrinsic is called
	// in a method body. Subsequent calls in the same method skip the
	// hashOutputs check (already established) and emit only the per-output
	// substring assertion.
	//
	// v1 assumes all outputs in the serialised set are exactly 34 bytes
	// (8-byte LE amount ‖ 0x19 length ‖ 25-byte P2PKH script). Byte offset
	// of output i is i*34. If the method also calls c.AddDataOutput(...)
	// the assumption breaks (variable-length OP_RETURN) — typecheck
	// rejects that mix; see checkMethod in typecheck.go (Crit-3).
	if id, ok := callee.(Identifier); ok && id.Name == "requireOutputP2PKH" {
		if len(e.Args) != 3 {
			return ctx.emit(makeLoadConstString(""))
		}
		idxLit, ok := e.Args[0].(BigIntLiteral)
		if !ok || idxLit.Value == nil {
			return ctx.emit(makeLoadConstString(""))
		}
		idx := idxLit.Value.Int64()

		ctx.methodScope.recordAutoInjectedParam("_serialisedOutputs", "ByteString")
		ctx.addParam("_serialisedOutputs")

		// Emit the hashOutputs(preimage) check exactly once per method.
		if !ctx.methodScope.didEmitHashOutputsCheck {
			ctx.methodScope.didEmitHashOutputsCheck = true
			serialisedRef := ctx.emit(ir.ANFValue{Kind: "load_param", Name: "_serialisedOutputs"})
			actualOutHashRef := ctx.emit(makeCall("hash256", []string{serialisedRef}))
			preimageRef := ctx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
			expectedOutHashRef := ctx.emit(makeCall("extractOutputHash", []string{preimageRef}))
			hashEqRef := ctx.emit(ir.ANFValue{
				Kind: "bin_op", Op: "===",
				Left: actualOutHashRef, Right: expectedOutHashRef,
				ResultType: "bytes",
			})
			ctx.emit(makeAssert(hashEqRef))
		}

		// Lower the user-supplied args (pubkeyHash, amount).
		pubkeyHashRef := ctx.lowerExprToRef(e.Args[1])
		amountRef := ctx.lowerExprToRef(e.Args[2])

		// Construct expected P2PKH output bytes:
		//   <amount: 8-byte LE> ‖ 0x19 0x76 0xa9 0x14 ‖ <pubkeyHash: 20 bytes> ‖ 0x88 0xac
		eightRef := ctx.emit(makeLoadConstInt(big.NewInt(8)))
		amountBytesRef := ctx.emit(makeCall("num2bin", []string{amountRef, eightRef}))
		// 0x19 0x76 0xa9 0x14 — script length byte + OP_DUP OP_HASH160 OP_PUSH20
		prefixRef := ctx.emit(makeLoadConstString("1976a914"))
		// 0x88 0xac — OP_EQUALVERIFY OP_CHECKSIG
		suffixRef := ctx.emit(makeLoadConstString("88ac"))
		cat1Ref := ctx.emit(makeCall("cat", []string{amountBytesRef, prefixRef}))
		cat2Ref := ctx.emit(makeCall("cat", []string{cat1Ref, pubkeyHashRef}))
		expectedOutputRef := ctx.emit(makeCall("cat", []string{cat2Ref, suffixRef}))

		// Substring extract at idx*34 length 34, assert equal.
		serialisedRef := ctx.emit(ir.ANFValue{Kind: "load_param", Name: "_serialisedOutputs"})
		offsetRef := ctx.emit(makeLoadConstInt(big.NewInt(idx * 34)))
		lengthRef := ctx.emit(makeLoadConstInt(big.NewInt(34)))
		extractedRef := ctx.emit(makeCall("substr", []string{serialisedRef, offsetRef, lengthRef}))
		outEqRef := ctx.emit(ir.ANFValue{
			Kind: "bin_op", Op: "===",
			Left: extractedRef, Right: expectedOutputRef,
			ResultType: "bytes",
		})
		return ctx.emit(makeAssert(outEqRef))
	}

	// currentBlockHeight() -> bigint. Pure source-level desugar to
	// extractLocktime(this.txPreimage). Only valid in StatefulSmartContract
	// methods (typecheck enforces). No new ANF kind or stack codegen needed.
	if id, ok := callee.(Identifier); ok && id.Name == "currentBlockHeight" {
		preimageRef := ctx.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
		return ctx.emit(makeCall("extractLocktime", []string{preimageRef}))
	}

	// this.addOutput(satoshis, val1, val2, ...) -> special node.
	// Mirrors flattenAddOutputArgs in 04-anf-lower.ts: when addOutput is
	// called as `this.addOutput(satoshis, .{ v1, v2, ... })` (the surface
	// form Zig / Move tuple syntax produce), unwrap the trailing array
	// literal so each element becomes an individual state value.
	if pa, ok := callee.(PropertyAccessExpr); ok && pa.Property == "addOutput" {
		flatArgs := flattenAddOutputArgs(e.Args)
		argRefs := ctx.lowerArgs(flatArgs)
		satoshis := argRefs[0]
		stateValues := argRefs[1:]
		ref := ctx.emit(ir.ANFValue{Kind: "add_output", Satoshis: satoshis, StateValues: stateValues, Preimage: ""})
		ctx.addOutputRef(ref)
		return ref
	}
	if me, ok := callee.(MemberExpr); ok {
		if id, ok := me.Object.(Identifier); ok && id.Name == "this" && me.Property == "addOutput" {
			flatArgs := flattenAddOutputArgs(e.Args)
			argRefs := ctx.lowerArgs(flatArgs)
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

	// this.addDataOutput(satoshis, scriptBytes) -> special node. Wire shape
	// is identical to addRawOutput, but the continuation hash includes these
	// AFTER state outputs and BEFORE the change output.
	if pa, ok := callee.(PropertyAccessExpr); ok && pa.Property == "addDataOutput" {
		argRefs := ctx.lowerArgs(e.Args)
		satoshis := argRefs[0]
		scriptBytes := argRefs[1]
		ref := ctx.emit(ir.ANFValue{Kind: "add_data_output", Satoshis: satoshis, ScriptBytes: scriptBytes})
		ctx.addDataOutputRef(ref)
		return ref
	}
	if me, ok := callee.(MemberExpr); ok {
		if id, ok := me.Object.(Identifier); ok && id.Name == "this" && me.Property == "addDataOutput" {
			argRefs := ctx.lowerArgs(e.Args)
			satoshis := argRefs[0]
			scriptBytes := argRefs[1]
			ref := ctx.emit(ir.ANFValue{Kind: "add_data_output", Satoshis: satoshis, ScriptBytes: scriptBytes})
			ctx.addDataOutputRef(ref)
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

	// this.method(...) via PropertyAccessExpr (or inlined if the target
	// is a private method with continuation-relevant side effects).
	if pa, ok := callee.(PropertyAccessExpr); ok {
		argRefs := ctx.lowerArgs(e.Args)
		if ctx.shouldInlinePrivate(pa.Property) {
			return ctx.inlinePrivateMethodCall(pa.Property, argRefs)
		}
		thisRef := ctx.emit(makeLoadConstString("@this"))
		return ctx.emit(ir.ANFValue{Kind: "method_call", Object: thisRef, Method: pa.Property, Args: argRefs})
	}

	// this.method(...) via MemberExpr
	if me, ok := callee.(MemberExpr); ok {
		if id, ok := me.Object.(Identifier); ok && id.Name == "this" {
			argRefs := ctx.lowerArgs(e.Args)
			if ctx.shouldInlinePrivate(me.Property) {
				return ctx.inlinePrivateMethodCall(me.Property, argRefs)
			}
			thisRef := ctx.emit(makeLoadConstString("@this"))
			return ctx.emit(ir.ANFValue{Kind: "method_call", Object: thisRef, Method: me.Property, Args: argRefs})
		}
	}

	// asm({...}) compiler intrinsic — the parser has already normalised the
	// object-literal argument into three positional args
	// (body, in_arity, out_arity). Lower it to a single opaque raw_script
	// ANF binding; the hex body passes through unchanged. Diagnostics for
	// malformed args were already pushed by the validator — here we
	// defensively coerce missing values to safe defaults.
	if id, ok := callee.(Identifier); ok && id.Name == "asm" {
		bytes := ""
		inArity := 0
		outArity := 1
		if len(e.Args) >= 1 {
			if bs, ok := e.Args[0].(ByteStringLiteral); ok {
				bytes = bs.Value
			}
		}
		if len(e.Args) >= 2 {
			if bi, ok := e.Args[1].(BigIntLiteral); ok && bi.Value != nil {
				inArity = int(bi.Value.Int64())
			}
		}
		if len(e.Args) >= 3 {
			if bi, ok := e.Args[2].(BigIntLiteral); ok && bi.Value != nil {
				outArity = int(bi.Value.Int64())
			}
		}
		return ctx.emit(ir.ANFValue{
			Kind:     "raw_script",
			Bytes:    bytes,
			InArity:  inArity,
			OutArity: outArity,
		})
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
			if ctx.shouldInlinePrivate(id.Name) {
				return ctx.inlinePrivateMethodCall(id.Name, argRefs)
			}
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

// lowerTernaryArm lowers one arm of a ternary, guaranteeing the arm ENDS with
// the binding that holds its result.
//
// NEW-016: lowerExprToRef returns an existing ref without emitting anything
// when the arm is a bare identifier — `g ? f : c === 0n` produced `then: []`,
// an if arm with no bindings at all. Stack lowering reads an arm's result off
// its stack effect, so a +0 arm has no result to adopt and the depth reconcile
// padded the shortfall with an EMPTY push. The contract compiled clean, the
// AST interpreter accepted it, and the real engine rejected the spend with
// "OP_VERIFY requires the top stack value to be truthy" over a stack of
// [01, ] — the arm's true replaced by an empty (false) value. An ordinary
// contract deployed to a permanently unspendable UTXO.
//
// Aliasing through load_const "@ref:" — the same idiom `let x = y` and the
// increment/decrement lowerings already use — makes the arm's stack effect +1
// and copies the parent slot instead of trying to move it. The alias is only
// emitted when the result was NOT produced inside the arm, so every arm that
// already ended on its own result keeps its exact bytes.
func (ctx *lowerCtx) lowerTernaryArm(e Expression) {
	ref := ctx.lowerExprToRef(e)
	if len(ctx.bindings) == 0 || ctx.bindings[len(ctx.bindings)-1].Name != ref {
		ctx.emit(makeLoadConstString("@ref:" + ref))
	}
}

func (ctx *lowerCtx) lowerTernaryExpr(e TernaryExpr) string {
	condRef := ctx.lowerExprToRef(e.Condition)

	thenCtx := ctx.subContext()
	thenCtx.lowerTernaryArm(e.Consequent)
	ctx.syncCounter(thenCtx)

	elseCtx := ctx.subContext()
	elseCtx.lowerTernaryArm(e.Alternate)
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
	// big.Int's default JSON marshaler emits the value as a JSON number,
	// which Go's encoding/json prints in scientific notation for magnitudes
	// > ~1e15 — silently losing precision for 256-bit constants like the
	// secp256k1 group order used in schnorr-zkp's s-bound assert. Emit
	// oversize bigints as a quoted decimal string with the canonical JS
	// BigInt `n` suffix so the IR round-trips losslessly across tiers AND
	// so the consuming IR decoder can distinguish a decimal-encoded big
	// integer from a hex-encoded ByteString literal. The boundary is
	// Number.MAX_SAFE_INTEGER, not int64: a bare JSON number is read as an
	// IEEE-754 double by every JS consumer (and by Go itself when decoding
	// into interface{}), so `9007199254740993` — comfortably inside int64 —
	// still round-trips as `9007199254740992`.
	raw := ir.BigIntToRawJSON(val)
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

// makeAutoInjectedStateCheckAssert builds the auto-injected
// stateful-continuation hash-equality assert with the
// IsAutoInjectedStateCheck marker set. Off-chain SDK interpreters use
// this marker to skip the equality check via a direct lookup instead of
// structural / taint heuristics that misfire on developer covenant
// asserts whose IR shape is identical.
func makeAutoInjectedStateCheckAssert(valueRef string) ir.ANFValue {
	raw, _ := json.Marshal(valueRef)
	return ir.ANFValue{
		Kind:                     "assert",
		RawValue:                 raw,
		ValueRef:                 valueRef,
		IsAutoInjectedStateCheck: true,
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

// inlinePrivateMethodCall lowers a private method's body directly into
// the caller's context. Used when the private has continuation-relevant
// side effects (state mutation, addOutput, addRawOutput, addDataOutput)
// so the helper's emitted ANF nodes register output refs on the caller.
//
// Caller's arg refs are mapped onto the private's parameter names via
// pushParamAlias. While the private's body lowers, any identifier
// expression matching one of those param names resolves to the caller's
// ref (see lowerIdentifier). The aliases are popped afterwards so
// subsequent lowering in the caller's body sees its own scope.
//
// Recursion across private helpers is forbidden by validation, so this
// always terminates. Nested inlining (private A calls private B) works
// naturally: when we lower A's body and hit the call to B, the same
// dispatch path runs and inlines B too.
func (ctx *lowerCtx) inlinePrivateMethodCall(methodName string, argRefs []string) string {
	method, ok := ctx.getPrivateMethod(methodName)
	if !ok {
		// Should not happen — caller checked shouldInlinePrivate which
		// requires the method to exist. Fall back to a method_call so
		// the stack lowering pass surfaces a clear error.
		thisRef := ctx.emit(makeLoadConstString("@this"))
		return ctx.emit(ir.ANFValue{Kind: "method_call", Object: thisRef, Method: methodName, Args: argRefs})
	}

	// Bind caller arg refs to the private's parameter names.
	var aliasedParams []string
	for i := 0; i < len(method.Params) && i < len(argRefs); i++ {
		paramName := method.Params[i].Name
		ctx.pushParamAlias(paramName, argRefs[i])
		aliasedParams = append(aliasedParams, paramName)
	}

	startIndex := len(ctx.bindings)
	ctx.lowerStatements(method.Body)
	endIndex := len(ctx.bindings)

	// Pop aliases in reverse order so nested inlines compose correctly.
	for i := len(aliasedParams) - 1; i >= 0; i-- {
		ctx.popParamAlias(aliasedParams[i])
	}

	// Method's "return value" is the last binding emitted by the body.
	// Void methods (e.g., a private helper that just calls addOutput)
	// still produce a binding which the caller expression-statement
	// path will discard.
	if endIndex > startIndex {
		return ctx.bindings[endIndex-1].Name
	}
	// Empty body — emit a load_const placeholder so the caller has a ref.
	return ctx.emit(makeLoadConstString("@void"))
}

// flattenAddOutputArgs mirrors flattenAddOutputArgs in 04-anf-lower.ts:
// when this.addOutput is called as `this.addOutput(satoshis, .{ v1, v2, ... })`
// (the surface form Zig / Move tuple syntax produce), unwrap the trailing
// array literal so each element becomes an individual state value.
func flattenAddOutputArgs(args []Expression) []Expression {
	if len(args) == 2 {
		if al, ok := args[1].(ArrayLiteralExpr); ok {
			out := make([]Expression, 0, 1+len(al.Elements))
			out = append(out, args[0])
			out = append(out, al.Elements...)
			return out
		}
	}
	return args
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
// Both sides of the discriminant are enumerated explicitly so an
// unknown kind cannot silently default to "has side effect" (which
// would conservatively preserve the binding but mask a missing
// dispatch wire-up in the rest of the pipeline).
func isSideEffectFree(v *ir.ANFValue) bool {
	switch v.Kind {
	case "load_prop", "load_param", "load_const", "bin_op", "unary_op",
		"get_state_script", "if", "loop", "array_literal":
		return true
	case "assert", "update_prop", "check_preimage", "deserialize_state",
		"add_output", "add_raw_output", "add_data_output",
		"call", "method_call", "raw_script":
		return false
	default:
		// Exhaustiveness guard. A silent default here would either
		// preserve every unknown binding (masking a missing dispatch)
		// or — depending on caller polarity — strand a side-effecting
		// new kind in dead-code-elimination's path.
		panic(&ir.UnknownANFKindError{Kind: v.Kind, Location: "anf-lower.isSideEffectFree"})
	}
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

// stripDeclaredResults returns an arm with its declared-results block removed.
//
// appendBranchResults adds exactly 2*len(results) trailing bindings to each arm
// of an `if` that declares results: K copies to `__merge$i` temps, then K
// rebinds off those temps. They are a materialisation mechanism, not program
// logic, and they hide the arm's real shape from this pass — the second
// update_prop becomes the arm's last binding and the original lands in the
// "everything before must be side-effect free" prefix. A dispatch chain's
// deepest `if` is nested by definition, so it declares results; without this,
// the enclosing chain stops being recognised and TicTacToe's position dispatch
// loses the C20 lift (an unspendable `move` script).
func stripDeclaredResults(bindings []ir.ANFBinding, results []string) []ir.ANFBinding {
	n := len(results)
	if n == 0 {
		return bindings
	}
	cut := len(bindings) - 2*n
	if cut < 0 {
		cut = 0
	}
	return bindings[:cut]
}

// collectUpdateBranches recursively collects update branches from a nested if-else chain.
func collectUpdateBranches(ifCond string, thenBindings, elseBindings []ir.ANFBinding) []updateBranch {
	propName, valBindings, valRef, ok := extractBranchUpdate(thenBindings)
	if !ok {
		return nil
	}

	branches := []updateBranch{{
		condRef:       &ifCond,
		propName:      propName,
		valueBindings: valBindings,
		valueRef:      valRef,
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

		innerBranches := collectUpdateBranches(
			lastElse.Value.Cond,
			stripDeclaredResults(lastElse.Value.Then, lastElse.Value.Results),
			stripDeclaredResults(lastElse.Value.Else, lastElse.Value.Results),
		)
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
	case "add_data_output":
		v.Satoshis = r(v.Satoshis)
		v.ScriptBytes = r(v.ScriptBytes)
		return v
	case "if":
		v.Cond = r(v.Cond)
		return v
	case "loop":
		return v
	default:
		// Exhaustiveness guard. A silent fall-through here would return
		// the value unchanged when a remap was actually required —
		// resulting in a binding that references a hoisted/renamed
		// temp by its pre-remap name, producing dangling SSA refs.
		panic(&ir.UnknownANFKindError{Kind: v.Kind, Location: "anf-lower.remapValueRefs"})
	}
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

		branches := collectUpdateBranches(
			binding.Value.Cond,
			stripDeclaredResults(binding.Value.Then, binding.Value.Results),
			stripDeclaredResults(binding.Value.Else, binding.Value.Results),
		)

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

		// 2b. C20 — preserve a dropped terminal `assert(false)` else.
		//
		// `collectUpdateBranches` transforms a dispatch chain whose branches each
		// end in a single `update_prop` into this flat conditional-assignment form.
		// When the chain's terminal else is `assert(false)` it returns the branches
		// WITHOUT a catch-all final branch (every branch keeps a non-null condRef),
		// dropping the abort. But that assert(false) is the ONLY thing rejecting a
		// selector value that matches no branch: without it, an unmatched selector
		// leaves every property at its old value — a spendable NO-OP state
		// continuation instead of a failed script (a funds-safety bug).
		//
		// A real final else (`else { prop = ... }`) instead yields a catch-all
		// branch with condRef === null, and needs no guard because every selector
		// value maps to some branch. So the presence of a null-condRef terminal
		// branch exactly distinguishes the two cases.
		//
		// Re-introduce the abort as `assert(cond0 || cond1 || ... || cond_{N-1})`:
		// if no branch condition held, the OR is false and the script aborts —
		// byte-identical to the original `assert(false)` semantics for the
		// unmatched position, and a no-op (`assert(true)`) whenever a branch runs.
		hasCatchAllElse := condRefs[len(condRefs)-1] == nil
		if !hasCatchAllElse {
			// Every branch here has a non-null condRef (only a catch-all final
			// else is null, and there is none), so the OR fully covers the
			// selector space.
			orRef := *condRefs[0]
			for i := 1; i < len(condRefs); i++ {
				orName := fresh()
				result = append(result, ir.ANFBinding{
					Name: orName,
					Value: ir.ANFValue{
						Kind:  "bin_op",
						Op:    "||",
						Left:  orRef,
						Right: *condRefs[i],
					},
				})
				orRef = orName
			}
			result = append(result, ir.ANFBinding{
				Name: fresh(),
				Value: ir.ANFValue{
					Kind:     "assert",
					ValueRef: orRef,
				},
			})
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
