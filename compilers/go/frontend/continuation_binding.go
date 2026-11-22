package frontend

// D25 — bind every state continuation to the input that made it.
//
// Mirrors packages/runar-compiler/src/passes/continuation-binding.ts (the
// reference; read its module comment for the full argument). SECURITY CORE
// (fund safety): before D25 two UTXOs of one stateful contract spent in one
// transaction that reach the same post-state were BOTH satisfied by ONE
// continuation output (the covenant hashes the whole output list and the
// BIP-143 preimage carries no input position).
//
// The contract is classified once:
//
//	"single"    every continuation-producing public method is mutate-only and
//	            reads nothing SINGLE zeroes or redefines -> those methods
//	            default to SIGHASH_SINGLE|FORKID (ALL|ANYONECANPAY|FORKID
//	            becomes SINGLE|ANYONECANPAY|FORKID); an explicit pure ALL is
//	            refused.
//	"bind"      has an auto-continuation method but is not "single" -> a hidden
//	            last state field `_spentOutpointHash` = sha256(extractOutpoint).
//	"explicit"  every continuation method sizes its own outputs -> unchanged
//	            bytes; an unsigned addOutput(extractAmount(...)) is warned about.
//	"none"      stateless, or no public method produces a continuation.

import (
	"fmt"
	"strings"
)

// TwinBindingField is the hidden state field of a "bind" contract (reserved;
// last mutable property).
const TwinBindingField = "_spentOutpointHash"

// SighashSingleForkID is SIGHASH_SINGLE|FORKID.
const SighashSingleForkID = sighashBaseSingle | sighashFlagForkID

// ContinuationClass is the D25 class of a contract.
type ContinuationClass string

const (
	ContinuationNone     ContinuationClass = "none"
	ContinuationSingle   ContinuationClass = "single"
	ContinuationBind     ContinuationClass = "bind"
	ContinuationExplicit ContinuationClass = "explicit"
)

// Builtins whose meaning SINGLE zeroes or redefines (a mutate-only method
// reading one keeps ALL).
var singleIncompatibleReads = map[string]bool{
	"extractHashSequence": true,
	"extractOutputHash":   true,
	"extractOutputs":      true,
	"extractSigHashType":  true,
	"requireOutputP2PKH":  true,
}

// ExplicitAllSiblingMessage is the shared error text for an explicit ALL
// sibling in a "single" contract.
func ExplicitAllSiblingMessage(method string) string {
	return fmt.Sprintf("method '%s': @sighash ALL|FORKID on a state-continuation method of a contract whose "+
		"continuation methods are all mutate-only reopens twin-input theft: such a contract commits each "+
		"continuation under SIGHASH_SINGLE (one output per input), and one ALL method lets its input reuse "+
		"a sibling's output while its own value leaves as change. Remove the directive (the default is "+
		"SINGLE|FORKID) or write @sighash SINGLE|FORKID", method)
}

// UnsignedAddOutputMessage is the shared warning text for an unsigned
// value-conserving addOutput (D12 C1).
func UnsignedAddOutputMessage(method string) string {
	return fmt.Sprintf("method '%s' re-creates the contract with addOutput(extractAmount(...), ...) and checks no "+
		"signature: two UTXOs of this contract spent in one transaction that reach the same state are both "+
		"satisfied by ONE such output, and the other input's value leaves as anyone's change (twin-input "+
		"aliasing). A method that sizes its own outputs is not bound to its input; require a signature, or "+
		"let the compiler size the continuation (write state instead of calling addOutput)", method)
}

func bindingCalleeName(callee Expression) string {
	switch c := callee.(type) {
	case Identifier:
		return c.Name
	case PropertyAccessExpr:
		return c.Property
	case MemberExpr:
		return c.Property
	}
	return ""
}

// reachableCalls: every call name reachable from body, through private
// helpers (cycle-guarded). Same walk as the TS reference.
func reachableCalls(body []Statement, privates map[string]MethodNode) map[string]bool {
	names := map[string]bool{}
	visiting := map[string]bool{}
	var stmts func(ss []Statement)
	var stmt func(s Statement)
	var expr func(e Expression)
	stmts = func(ss []Statement) {
		for _, s := range ss {
			stmt(s)
		}
	}
	stmt = func(s Statement) {
		switch x := s.(type) {
		case AssignmentStmt:
			expr(x.Target)
			expr(x.Value)
		case ExpressionStmt:
			expr(x.Expr)
		case IfStmt:
			expr(x.Condition)
			stmts(x.Then)
			if x.Else != nil {
				stmts(x.Else)
			}
		case ForStmt:
			stmt(x.Init)
			expr(x.Condition)
			stmt(x.Update)
			stmts(x.Body)
		case ReturnStmt:
			if x.Value != nil {
				expr(x.Value)
			}
		case VariableDeclStmt:
			if x.Init != nil {
				expr(x.Init)
			}
		}
	}
	expr = func(e Expression) {
		switch x := e.(type) {
		case CallExpr:
			if n := bindingCalleeName(x.Callee); n != "" {
				names[n] = true
				if t, ok := privates[n]; ok && !visiting[n] {
					visiting[n] = true
					stmts(t.Body)
					delete(visiting, n)
				}
			}
			for _, a := range x.Args {
				expr(a)
			}
			if _, isID := x.Callee.(Identifier); !isID {
				expr(x.Callee)
			}
		case BinaryExpr:
			expr(x.Left)
			expr(x.Right)
		case UnaryExpr:
			expr(x.Operand)
		case TernaryExpr:
			expr(x.Condition)
			expr(x.Consequent)
			expr(x.Alternate)
		case IndexAccessExpr:
			expr(x.Object)
			expr(x.Index)
		case MemberExpr:
			expr(x.Object)
		case ArrayLiteralExpr:
			for _, el := range x.Elements {
				expr(el)
			}
		}
	}
	stmts(body)
	return names
}

func bindingPrivatesOf(contract *ContractNode) map[string]MethodNode {
	m := map[string]MethodNode{}
	for _, x := range contract.Methods {
		if x.Visibility == "private" {
			m[x.Name] = x
		}
	}
	return m
}

// classifyContinuation returns the class and the indices (into
// contract.Methods) of the public continuation methods, in declaration order.
func classifyContinuation(contract *ContractNode) (ContinuationClass, []int) {
	if contract.ParentClass != "StatefulSmartContract" {
		return ContinuationNone, nil
	}
	effects := ComputeSideEffectSummary(contract)
	privates := bindingPrivatesOf(contract)
	var cont []int
	anyAuto := false
	allSingleEligible := true
	for i, m := range contract.Methods {
		if m.Visibility != "public" {
			continue
		}
		e, ok := effects[m.Name]
		if !ok || !ContinuationShapeFor(e).NeedsChange {
			continue
		}
		cont = append(cont, i)
		if !e.HasStateOutput {
			anyAuto = true
		}
		base := sighashBaseAll
		if m.SighashType != nil {
			base = *m.SighashType & sighashBaseTypeMask
		}
		modeOk := base == sighashBaseAll || base == sighashBaseSingle
		readsOk := true
		for n := range reachableCalls(m.Body, privates) {
			if singleIncompatibleReads[n] {
				readsOk = false
				break
			}
		}
		if e.HasStateOutput || e.HasDataOutput || !modeOk || !readsOk {
			allSingleEligible = false
		}
	}
	if len(cont) == 0 {
		return ContinuationNone, cont
	}
	if !anyAuto {
		return ContinuationExplicit, cont
	}
	if allSingleEligible {
		return ContinuationSingle, cont
	}
	return ContinuationBind, cont
}

// ContinuationClassOf returns the contract's D25 class.
func ContinuationClassOf(contract *ContractNode) ContinuationClass {
	c, _ := classifyContinuation(contract)
	return c
}

// ResolveContinuationBinding is the D25 resolution, run by Validate right
// before the @sighash field checks so every later pass sees the effective
// mode. In a "single" contract it sets each continuation method's SighashType
// (in place, on contract.Methods); it refuses an explicit pure-ALL directive
// there; in an "explicit" contract it warns about unsigned value-conserving
// addOutput methods. Idempotent.
func ResolveContinuationBinding(contract *ContractNode) []Diagnostic {
	var diags []Diagnostic
	cls, cont := classifyContinuation(contract)
	switch cls {
	case ContinuationSingle:
		for _, i := range cont {
			m := &contract.Methods[i]
			if m.SighashType == nil {
				v := SighashSingleForkID
				m.SighashType = &v
			} else if *m.SighashType&sighashBaseTypeMask == sighashBaseAll {
				if *m.SighashType&sighashFlagAnyone != 0 {
					v := (*m.SighashType &^ sighashBaseTypeMask) | sighashBaseSingle
					m.SighashType = &v
				} else {
					loc := m.SourceLocation
					diags = append(diags, MakeDiagnostic(ExplicitAllSiblingMessage(m.Name), SeverityError, &loc))
				}
			}
		}
	case ContinuationExplicit:
		privates := bindingPrivatesOf(contract)
		for _, i := range cont {
			m := contract.Methods[i]
			if m.SighashType != nil && *m.SighashType&sighashBaseTypeMask != sighashBaseAll {
				continue
			}
			if found, loc := unsignedValueConservingAddOutput(m, privates); found {
				if loc == nil {
					l := m.SourceLocation
					loc = &l
				}
				diags = append(diags, MakeDiagnostic(UnsignedAddOutputMessage(m.Name), SeverityWarning, loc))
			}
		}
	}
	return diags
}

// isSignatureCheck: a call name that verifies a signature (any scheme).
func isSignatureCheck(name string) bool {
	return name == "checkSig" || name == "checkMultiSig" || strings.HasPrefix(name, "verify")
}

// unsignedValueConservingAddOutput (D12 C1): whether the method has an
// addOutput whose satoshis argument reads extractAmount (directly, or through
// a local initialised from it) while verifying no signature, and its location
// when known. Same (narrower) walk as the TS reference.
func unsignedValueConservingAddOutput(method MethodNode, privates map[string]MethodNode) (bool, *SourceLocation) {
	for n := range reachableCalls(method.Body, privates) {
		if isSignatureCheck(n) {
			return false, nil
		}
	}
	amountLocals := map[string]bool{}
	var readsAmount func(e Expression) bool
	readsAmount = func(e Expression) bool {
		switch x := e.(type) {
		case CallExpr:
			if bindingCalleeName(x.Callee) == "extractAmount" {
				return true
			}
			for _, a := range x.Args {
				if readsAmount(a) {
					return true
				}
			}
			return false
		case Identifier:
			return amountLocals[x.Name]
		case BinaryExpr:
			return readsAmount(x.Left) || readsAmount(x.Right)
		case UnaryExpr:
			return readsAmount(x.Operand)
		case TernaryExpr:
			return readsAmount(x.Condition) || readsAmount(x.Consequent) || readsAmount(x.Alternate)
		}
		return false
	}
	found := false
	var foundLoc *SourceLocation
	visiting := map[string]bool{}
	var stmts func(ss []Statement)
	var stmt func(s Statement)
	var expr func(e Expression)
	stmts = func(ss []Statement) {
		for _, s := range ss {
			stmt(s)
		}
	}
	stmt = func(s Statement) {
		switch x := s.(type) {
		case VariableDeclStmt:
			if x.Init != nil {
				if readsAmount(x.Init) {
					amountLocals[x.Name] = true
				}
				expr(x.Init)
			}
		case AssignmentStmt:
			expr(x.Value)
		case ExpressionStmt:
			expr(x.Expr)
		case IfStmt:
			expr(x.Condition)
			stmts(x.Then)
			if x.Else != nil {
				stmts(x.Else)
			}
		case ForStmt:
			stmts(x.Body)
		case ReturnStmt:
			if x.Value != nil {
				expr(x.Value)
			}
		}
	}
	expr = func(e Expression) {
		x, ok := e.(CallExpr)
		if !ok {
			return
		}
		n := bindingCalleeName(x.Callee)
		if n == "addOutput" && len(x.Args) > 0 && readsAmount(x.Args[0]) && !found {
			found = true
			foundLoc = exprLoc(x)
		}
		if t, ok := privates[n]; ok && n != "" && !visiting[t.Name] {
			visiting[t.Name] = true
			stmts(t.Body)
			delete(visiting, t.Name)
		}
		for _, a := range x.Args {
			expr(a)
		}
	}
	stmts(method.Body)
	return found, foundLoc
}

// InjectContinuationBinding is the D25 injection, run after typecheck (before
// fixed-array expansion): a "bind" contract gains the hidden
// `_spentOutpointHash: Sha256 = 0x00..00` as its LAST property. ANF lowering
// then writes it in every auto-continuation and appends it to every
// addOutput. The zero initializer keeps it out of the constructor ABI.
// Returns the contract unchanged for any other class (a shallow copy with the
// extra property otherwise; the input is not mutated).
func InjectContinuationBinding(contract *ContractNode) *ContractNode {
	if contract == nil || ContinuationClassOf(contract) != ContinuationBind {
		return contract
	}
	for _, p := range contract.Properties {
		if p.Name == TwinBindingField {
			return contract
		}
	}
	out := *contract
	props := make([]PropertyNode, 0, len(contract.Properties)+1)
	props = append(props, contract.Properties...)
	props = append(props, PropertyNode{
		Name:           TwinBindingField,
		Type:           PrimitiveType{Name: "Sha256"},
		Readonly:       false,
		Initializer:    ByteStringLiteral{Value: strings.Repeat("00", 32)},
		SourceLocation: contract.Constructor.SourceLocation,
	})
	out.Properties = props
	return &out
}
