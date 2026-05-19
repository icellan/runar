package runar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ripemd160"
)

// ---------------------------------------------------------------------------
// ANF IR types (mirrors runar-ir-schema for Go)
// ---------------------------------------------------------------------------

// ANFProgram is the top-level ANF IR for a compiled contract.
type ANFProgram struct {
	ContractName string        `json:"contractName"`
	Properties   []ANFProperty `json:"properties"`
	Methods      []ANFMethod   `json:"methods"`
}

// ANFProperty describes a contract property in ANF IR.
type ANFProperty struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Readonly     bool        `json:"readonly"`
	InitialValue interface{} `json:"initialValue,omitempty"`
}

// ANFMethod describes a contract method in ANF IR.
type ANFMethod struct {
	Name     string       `json:"name"`
	Params   []ANFParam   `json:"params"`
	Body     []ANFBinding `json:"body"`
	IsPublic bool         `json:"isPublic"`
}

// ANFParam describes a method parameter in ANF IR.
type ANFParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ANFBinding represents a single let-binding in the ANF IR.
// The Value field is a raw JSON object whose "kind" field discriminates
// the variant (load_param, load_const, bin_op, call, update_prop, etc.).
type ANFBinding struct {
	Name  string                 `json:"name"`
	Value map[string]interface{} `json:"value"`
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// AssertionFailureError is returned by ExecuteStrict when an `assert(...)`
// predicate evaluates to a falsy value during strict-mode interpretation.
// It carries the contract method name plus the ANF binding name (e.g.
// `t17`, `t8`) so a developer can pinpoint the exact failing guard.
type AssertionFailureError struct {
	MethodName  string
	BindingName string
}

// Error renders the failure with the same shape the TS / Java / Zig SDKs
// produce so cross-tier diffing on the wire is byte-stable.
func (e *AssertionFailureError) Error() string {
	return fmt.Sprintf(
		"assert failed in %s: binding '%s' evaluated to false",
		e.MethodName, e.BindingName,
	)
}

// strictCtx is the per-evaluation strict-mode handle. nil = lenient mode.
//
// When realCrypto != nil, crypto built-ins (`checkSig`, `checkMultiSig`,
// `checkPreimage`) verify against `realCrypto.Sighash` instead of mock-returning
// `true`. realCrypto != nil implies strict assert enforcement (the on-chain
// authoritative mode used by ExecuteOnChainAuthoritative).
type strictCtx struct {
	methodName string
	realCrypto *RealCryptoCtx
}

// IntentIntrinsicError signals a runtime failure inside one of the three
// intent-covenant intrinsic handlers (`extractPrevOutputScript`,
// `requireOutputP2PKH`, `currentBlockHeight`). The error covers two distinct
// failure shapes used by the TS reference:
//
//   - MissingWitness == true → the test caller forgot to supply the
//     witness bytes via SetPrevOutScript / SetSerialisedOutputs. The TS
//     reference throws a plain Error in that case.
//   - MissingWitness == false → the supplied witness bytes did not match
//     the expected hash / per-output bytes. The TS reference throws an
//     AssertionError; we surface the same shape.
//
// Both shapes propagate via panic+recover (mirroring AssertionFailureError)
// so they unwind out of nested if/loop/method-call evaluation in a single
// hop. runMethod recovers and returns the value as a typed Go error.
type IntentIntrinsicError struct {
	Intrinsic      string
	MethodName     string
	MissingWitness bool
	Message        string
}

func (e *IntentIntrinsicError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("%s: intrinsic failure in %s", e.Intrinsic, e.MethodName)
}

// InterpreterFixture carries the witness bytes and mock-preimage values that
// the AST interpreter consumes when evaluating the three intent-covenant
// intrinsics (`extractPrevOutputScript`, `requireOutputP2PKH`,
// `currentBlockHeight`). It mirrors the per-test handle the TS reference
// holds on the TestContract:
//
//   - witnessBytes      → `_prevOutScript_<i>` ‖ `_serialisedOutputs`
//   - mockPreimage      → numeric SIGHASH preimage fields (locktime, amount,
//                         version, sequence). Only `locktime` is consumed by
//                         the three Go-tier handlers, but we mirror the TS
//                         shape so the wider preimage builtins can read it
//                         consistently in future ports.
//   - mockPreimageBytes → byte-valued SIGHASH preimage fields (`outputHash`,
//                         `hashPrevouts`, `hashSequence`, `outpoint`).
//
// The fixture is supplied to ExecuteWithFixture / ExecuteStrictWithFixture;
// the legacy ExecuteStrict / ComputeNewState entry points pass nil so
// existing callers see no behavioural change.
type InterpreterFixture struct {
	witnessBytes      map[string][]byte
	mockPreimage      map[string]*big.Int
	mockPreimageBytes map[string][]byte
}

// NewInterpreterFixture returns an empty fixture with default mock-preimage
// values matching the TS reference (locktime=0).
func NewInterpreterFixture() *InterpreterFixture {
	return &InterpreterFixture{
		witnessBytes: make(map[string][]byte),
		mockPreimage: map[string]*big.Int{
			"locktime": big.NewInt(0),
		},
		mockPreimageBytes: make(map[string][]byte),
	}
}

// SetPrevOutScript records the previous-output locking-script bytes for the
// witness param `_prevOutScript_<inputIndex>`. Equivalent to the TS
// `TestContract.setPrevOutScript(idx, bytes)` channel.
func (f *InterpreterFixture) SetPrevOutScript(inputIndex int64, bytes []byte) {
	if f.witnessBytes == nil {
		f.witnessBytes = make(map[string][]byte)
	}
	key := fmt.Sprintf("_prevOutScript_%d", inputIndex)
	cp := make([]byte, len(bytes))
	copy(cp, bytes)
	f.witnessBytes[key] = cp
}

// SetSerialisedOutputs records the concatenated serialised outputs bytes for
// the witness param `_serialisedOutputs`. Equivalent to the TS
// `TestContract.setSerialisedOutputs(bytes)` channel.
func (f *InterpreterFixture) SetSerialisedOutputs(bytes []byte) {
	if f.witnessBytes == nil {
		f.witnessBytes = make(map[string][]byte)
	}
	cp := make([]byte, len(bytes))
	copy(cp, bytes)
	f.witnessBytes["_serialisedOutputs"] = cp
}

// SetMockPreimageLocktime sets the locktime field of the mock SIGHASH preimage,
// which is what `currentBlockHeight` (sugar for `extractLocktime(this.txPreimage)`)
// returns.
func (f *InterpreterFixture) SetMockPreimageLocktime(locktime *big.Int) {
	if f.mockPreimage == nil {
		f.mockPreimage = make(map[string]*big.Int)
	}
	if locktime == nil {
		f.mockPreimage["locktime"] = big.NewInt(0)
	} else {
		f.mockPreimage["locktime"] = new(big.Int).Set(locktime)
	}
}

// SetMockPreimageOutputHash sets the `outputHash` field of the mock SIGHASH
// preimage, which `requireOutputP2PKH` compares hash256(serialisedOutputs)
// against (the outer-hash assertion).
func (f *InterpreterFixture) SetMockPreimageOutputHash(bytes []byte) {
	if f.mockPreimageBytes == nil {
		f.mockPreimageBytes = make(map[string][]byte)
	}
	cp := make([]byte, len(bytes))
	copy(cp, bytes)
	f.mockPreimageBytes["outputHash"] = cp
}

// RealCryptoCtx carries the cryptographic context required by
// ExecuteOnChainAuthoritative. Sighash is the 32-byte BIP-143 sighash digest
// the on-chain VM would verify signatures against (and that the caller would
// have signed with LocalSigner.Sign before broadcasting).
//
//   - checkSig(sig, pk) parses pk as SEC1 secp256k1 (compressed/uncompressed),
//     parses sig as DER (with optional trailing sighash byte stripped — Bitcoin
//     convention), and ECDSA-verifies against Sighash. On mismatch, returns
//     false; the enclosing assert(...) trips and yields *AssertionFailureError.
//   - checkMultiSig(sigs, pks) iterates signatures left-to-right and consumes
//     pubkeys greedily, mirroring Bitcoin's OP_CHECKMULTISIG. Returns true iff
//     every signature finds a matching pubkey.
//   - checkPreimage(preimage) computes hash256(preimage) (SHA-256 of SHA-256)
//     and byte-compares to Sighash. Returns true on match. Mirrors the on-chain
//     OP_PUSH_TX semantic.
type RealCryptoCtx struct {
	Sighash [32]byte
}

// NewRealCryptoCtxFromHex builds a RealCryptoCtx from a hex-encoded sighash
// string (with or without 0x prefix). Returns an error if the hex is malformed
// or does not decode to exactly 32 bytes.
func NewRealCryptoCtxFromHex(sighashHex string) (*RealCryptoCtx, error) {
	s := strings.TrimPrefix(sighashHex, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("RealCryptoCtx: invalid sighash hex: %w", err)
	}
	return NewRealCryptoCtxFromBytes(b)
}

// NewRealCryptoCtxFromBytes builds a RealCryptoCtx from a 32-byte slice.
// Returns an error if the slice is not exactly 32 bytes.
func NewRealCryptoCtxFromBytes(sighash []byte) (*RealCryptoCtx, error) {
	if len(sighash) != 32 {
		return nil, fmt.Errorf("RealCryptoCtx: sighash must be exactly 32 bytes, got %d", len(sighash))
	}
	ctx := &RealCryptoCtx{}
	copy(ctx.Sighash[:], sighash)
	return ctx, nil
}

// ComputeNewState interprets the ANF IR to compute the state transition for
// a contract method call. It returns the updated state (merged with current).
// constructorArgs provides deploy-time values for readonly properties that are
// not in currentState (which only contains mutable fields).
func ComputeNewState(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
	constructorArgs []interface{},
) (map[string]interface{}, error) {
	state, _, _, err := ComputeNewStateAndDataOutputs(anf, methodName, currentState, args, constructorArgs)
	return state, err
}

// ExecuteStrict is the strict-mode counterpart of
// ComputeNewStateAndDataOutputs: it walks the same ANF body but returns
// (nil, nil, nil, *AssertionFailureError) on the first `assert(predicate)`
// whose predicate is falsy. Crypto built-ins (`checkSig`, `checkMultiSig`,
// `checkPreimage`) still mock-return `true`; only explicit `assert(...)`
// predicates are enforced.
//
// The third return value is the slice of raw outputs resolved from
// `this.addRawOutput(satoshis, scriptBytes)` calls in declaration order.
// The simulator does not introspect the script bytes; it surfaces them so
// the caller can splice them into the broadcast transaction.
func ExecuteStrict(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
	constructorArgs []interface{},
) (map[string]interface{}, []ContractOutput, []ContractOutput, error) {
	return runMethod(anf, methodName, currentState, args, constructorArgs, &strictCtx{methodName: methodName}, nil)
}

// ExecuteWithFixture is the lenient-mode (asserts skipped) counterpart of
// ExecuteStrict that also threads an InterpreterFixture through to the three
// intent-covenant intrinsics (`extractPrevOutputScript`, `requireOutputP2PKH`,
// `currentBlockHeight`). The fixture is consulted only by those handlers; all
// other call kinds are unaffected.
//
// Intent-intrinsic failures (hash mismatch, missing witness) panic with
// *IntentIntrinsicError and are surfaced as the returned error — even in
// lenient mode, mirroring the TS AST interpreter which throws regardless of
// whether asserts elsewhere are enforced.
func ExecuteWithFixture(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
	constructorArgs []interface{},
	fixture *InterpreterFixture,
) (map[string]interface{}, []ContractOutput, []ContractOutput, error) {
	return runMethod(anf, methodName, currentState, args, constructorArgs, nil, fixture)
}

// ExecuteStrictWithFixture is ExecuteStrict with an additional
// InterpreterFixture: asserts are enforced (returning *AssertionFailureError
// on the first falsy predicate) AND the three intent-covenant intrinsics
// consult the fixture for witness bytes and mock-preimage values.
func ExecuteStrictWithFixture(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
	constructorArgs []interface{},
	fixture *InterpreterFixture,
) (map[string]interface{}, []ContractOutput, []ContractOutput, error) {
	return runMethod(anf, methodName, currentState, args, constructorArgs, &strictCtx{methodName: methodName}, fixture)
}

// ExecuteOnChainAuthoritative is like ExecuteStrict but also performs real
// cryptographic verification of `checkSig`, `checkMultiSig`, and `checkPreimage`
// against the supplied sighash carried in ctx. Returns
// (nil, nil, nil, *AssertionFailureError) when any assert(...) — including the
// implicit one wrapping a failed crypto built-in — fires.
//
// The ctx parameter is mandatory: the signature shape requires the caller to
// provide the sighash up front, so it is impossible to invoke this mode
// accidentally without the cryptographic inputs.
//
// See RealCryptoCtx for the verification semantics. The returned envelope shape
// matches ExecuteStrict (state + dataOutputs + rawOutputs).
func ExecuteOnChainAuthoritative(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
	constructorArgs []interface{},
	ctx *RealCryptoCtx,
) (map[string]interface{}, []ContractOutput, []ContractOutput, error) {
	if ctx == nil {
		return nil, nil, nil, fmt.Errorf("ExecuteOnChainAuthoritative: ctx must not be nil")
	}
	return runMethod(anf, methodName, currentState, args, constructorArgs, &strictCtx{
		methodName: methodName,
		realCrypto: ctx,
	}, nil)
}

// ComputeNewStateAndDataOutputs is like ComputeNewState but also returns
// data outputs resolved from this.addDataOutput(...) calls and raw outputs
// resolved from this.addRawOutput(...) calls in the method body, in
// declaration order. The returned ContractOutput entries have Script as the
// hex-encoded ByteString and Satoshis as declared.
//
// Data outputs are what the compiler's auto-injected continuation-hash
// check expects to see in the spending tx between the state outputs and
// the change output. The SDK uses the returned slice to populate
// BuildCallOptions.DataOutputs so BuildCallTransaction emits them at the
// correct position.
//
// Raw outputs are caller-supplied locking-script outputs declared via
// `this.addRawOutput(satoshis, scriptBytes)`. The simulator forwards the
// script bytes (hex-encoded) without introspecting them so an off-chain
// transaction builder can splice them in at the correct index.
func ComputeNewStateAndDataOutputs(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
	constructorArgs []interface{},
) (map[string]interface{}, []ContractOutput, []ContractOutput, error) {
	return runMethod(anf, methodName, currentState, args, constructorArgs, nil, nil)
}

// runMethod is the shared entry-point for both lenient and strict modes.
// strict == nil -> lenient (asserts skipped).
// strict != nil -> strict (asserts enforced; first falsy predicate returns
// *AssertionFailureError).
// fixture may be nil; when set, the three intent-covenant intrinsics
// (`extractPrevOutputScript`, `requireOutputP2PKH`, `currentBlockHeight`)
// read witness bytes / mock-preimage values from it.
func runMethod(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
	constructorArgs []interface{},
	strict *strictCtx,
	fixture *InterpreterFixture,
) (resultState map[string]interface{}, resultDataOutputs []ContractOutput, resultRawOutputs []ContractOutput, retErr error) {
	// Find the method
	var method *ANFMethod
	for i := range anf.Methods {
		if anf.Methods[i].Name == methodName && anf.Methods[i].IsPublic {
			method = &anf.Methods[i]
			break
		}
	}
	if method == nil {
		return nil, nil, nil, fmt.Errorf("computeNewState: method '%s' not found in ANF IR", methodName)
	}

	// Initialize environment with property values: mutable fields from
	// currentState, non-initialized fields from constructorArgs (by constructor
	// param index, which excludes initialized properties).
	env := make(map[string]interface{})
	// Build constructor param name→index map (non-initialized properties only)
	ctorIdx := make(map[string]int)
	ci := 0
	for _, p := range anf.Properties {
		if p.InitialValue == nil {
			ctorIdx[p.Name] = ci
			ci++
		}
	}
	for _, prop := range anf.Properties {
		if v, ok := currentState[prop.Name]; ok {
			env[prop.Name] = v
		} else if prop.InitialValue != nil {
			env[prop.Name] = prop.InitialValue
		} else if idx, ok := ctorIdx[prop.Name]; ok && idx < len(constructorArgs) {
			env[prop.Name] = constructorArgs[idx]
		}
	}

	// Load method params, skip implicit ones
	implicit := map[string]bool{
		"_changePKH":    true,
		"_changeAmount": true,
		"_newAmount":    true,
		"txPreimage":    true,
	}
	for _, param := range method.Params {
		if implicit[param.Name] {
			continue
		}
		if v, ok := args[param.Name]; ok {
			env[param.Name] = v
		}
	}

	// Track state mutations, data outputs, and raw outputs.
	// rawOutputs holds entries from `add_raw_output` ANF kinds; the simulator
	// does not introspect the script bytes (caller-supplied locking script).
	stateDelta := make(map[string]interface{})
	var dataOutputs []ContractOutput
	var rawOutputs []ContractOutput

	// Strict mode signals an assert failure by panicking with a sentinel
	// so the panic unwinds out of nested if / loop / private-method calls
	// without threading an error return through every recursion. Recover
	// here and surface as a typed *AssertionFailureError.
	//
	// Intent-intrinsic failures (hash mismatch, missing witness) panic with
	// *IntentIntrinsicError. They unwind the same way and are surfaced even
	// in lenient mode — the TS reference also throws AssertionError /
	// missing-witness Error regardless of strict/lenient.
	defer func() {
		if r := recover(); r != nil {
			if af, ok := r.(*AssertionFailureError); ok {
				resultState = nil
				resultDataOutputs = nil
				resultRawOutputs = nil
				retErr = af
				return
			}
			if ie, ok := r.(*IntentIntrinsicError); ok {
				resultState = nil
				resultDataOutputs = nil
				resultRawOutputs = nil
				retErr = ie
				return
			}
			// Re-panic on anything that isn't a known interpreter sentinel —
			// those are real bugs and should not be silently coerced.
			panic(r)
		}
	}()

	// Walk bindings
	anfEvalBindings(anf, method.Body, env, stateDelta, &dataOutputs, &rawOutputs, strict, fixture)

	// Merge delta into current state
	result := make(map[string]interface{})
	for k, v := range currentState {
		result[k] = v
	}
	for k, v := range stateDelta {
		result[k] = v
	}
	return result, dataOutputs, rawOutputs, nil
}

// ---------------------------------------------------------------------------
// Binding evaluation
// ---------------------------------------------------------------------------

func anfEvalBindings(
	anf *ANFProgram,
	bindings []ANFBinding,
	env map[string]interface{},
	stateDelta map[string]interface{},
	dataOutputs *[]ContractOutput,
	rawOutputs *[]ContractOutput,
	strict *strictCtx,
	fixture *InterpreterFixture,
) {
	for _, binding := range bindings {
		val := anfEvalValue(anf, binding.Value, env, stateDelta, dataOutputs, rawOutputs, strict, fixture, binding.Name)
		env[binding.Name] = val
	}
}

func anfEvalValue(
	anf *ANFProgram,
	value map[string]interface{},
	env map[string]interface{},
	stateDelta map[string]interface{},
	dataOutputs *[]ContractOutput,
	rawOutputs *[]ContractOutput,
	strict *strictCtx,
	fixture *InterpreterFixture,
	bindingName string,
) interface{} {
	kind, _ := value["kind"].(string)

	switch kind {
	case "load_param":
		name, _ := value["name"].(string)
		return env[name]

	case "load_prop":
		name, _ := value["name"].(string)
		return env[name]

	case "load_const":
		v := value["value"]
		// Handle @ref: aliases
		if s, ok := v.(string); ok && strings.HasPrefix(s, "@ref:") {
			return env[s[5:]]
		}
		return v

	case "bin_op":
		op, _ := value["op"].(string)
		leftName, _ := value["left"].(string)
		rightName, _ := value["right"].(string)
		resultType, _ := value["result_type"].(string)
		return anfEvalBinOp(op, env[leftName], env[rightName], resultType)

	case "unary_op":
		op, _ := value["op"].(string)
		operandName, _ := value["operand"].(string)
		resultType, _ := value["result_type"].(string)
		return anfEvalUnaryOp(op, env[operandName], resultType)

	case "call":
		funcName, _ := value["func"].(string)
		argNames := anfGetStringSlice(value["args"])
		argVals := make([]interface{}, len(argNames))
		for i, name := range argNames {
			argVals[i] = env[name]
		}
		// Strict mode: a `call(assert, x)` lowering path enforces the
		// predicate the same way the dedicated `assert` ANF node does.
		if strict != nil && funcName == "assert" {
			var pred interface{}
			if len(argVals) > 0 {
				pred = argVals[0]
			}
			if !anfIsTruthy(pred) {
				panic(&AssertionFailureError{MethodName: strict.methodName, BindingName: bindingName})
			}
			return nil
		}
		var rc *RealCryptoCtx
		if strict != nil {
			rc = strict.realCrypto
		}
		methodNameForErr := ""
		if strict != nil {
			methodNameForErr = strict.methodName
		}
		return anfEvalCall(funcName, argVals, rc, fixture, methodNameForErr)

	case "method_call":
		methodName, _ := value["method"].(string)
		argNames := anfGetStringSlice(value["args"])
		argVals := make([]interface{}, len(argNames))
		for i, name := range argNames {
			argVals[i] = env[name]
		}
		// Look up private method in ANF program
		if anf != nil {
			for i := range anf.Methods {
				if anf.Methods[i].Name == methodName && !anf.Methods[i].IsPublic {
					m := &anf.Methods[i]
					// Create new env with params mapped to args
					callEnv := make(map[string]interface{})
					// Copy property values from caller env
					for _, prop := range anf.Properties {
						if v, ok := env[prop.Name]; ok {
							callEnv[prop.Name] = v
						}
					}
					// Map params to arg values
					for j, param := range m.Params {
						if j < len(argVals) {
							callEnv[param.Name] = argVals[j]
						}
					}
					// Evaluate method body
					anfEvalBindings(anf, m.Body, callEnv, stateDelta, dataOutputs, rawOutputs, strict, fixture)
					// Copy updated property values back to caller env
					for _, prop := range anf.Properties {
						if v, ok := callEnv[prop.Name]; ok {
							env[prop.Name] = v
						}
					}
					// Return last binding's value
					if len(m.Body) > 0 {
						return callEnv[m.Body[len(m.Body)-1].Name]
					}
					return nil
				}
			}
		}
		return nil

	case "if":
		condName, _ := value["cond"].(string)
		cond := env[condName]
		var branch []ANFBinding
		if anfIsTruthy(cond) {
			branch = anfGetBindings(value["then"])
		} else {
			branch = anfGetBindings(value["else"])
		}
		// Create a child env for the branch
		childEnv := make(map[string]interface{})
		for k, v := range env {
			childEnv[k] = v
		}
		anfEvalBindings(anf, branch, childEnv, stateDelta, dataOutputs, rawOutputs, strict, fixture)
		// Copy new bindings back
		for k, v := range childEnv {
			env[k] = v
		}
		// Return last binding's value
		if len(branch) > 0 {
			return childEnv[branch[len(branch)-1].Name]
		}
		return nil

	case "loop":
		count := anfToInt(value["count"])
		iterVar, _ := value["iterVar"].(string)
		body := anfGetBindings(value["body"])
		var lastVal interface{}
		for i := int64(0); i < count; i++ {
			env[iterVar] = big.NewInt(i)
			loopEnv := make(map[string]interface{})
			for k, v := range env {
				loopEnv[k] = v
			}
			anfEvalBindings(anf, body, loopEnv, stateDelta, dataOutputs, rawOutputs, strict, fixture)
			for k, v := range loopEnv {
				env[k] = v
			}
			if len(body) > 0 {
				lastVal = loopEnv[body[len(body)-1].Name]
			}
		}
		return lastVal

	case "assert":
		// Lenient mode: skip; the on-chain script enforces.
		// Strict mode: enforce — falsy predicate panics with
		// *AssertionFailureError, recovered in runMethod.
		if strict != nil {
			predRef, _ := value["value"].(string)
			pred := env[predRef]
			if !anfIsTruthy(pred) {
				panic(&AssertionFailureError{MethodName: strict.methodName, BindingName: bindingName})
			}
		}
		return nil

	case "update_prop":
		propName, _ := value["name"].(string)
		valName, _ := value["value"].(string)
		newVal := env[valName]
		env[propName] = newVal
		stateDelta[propName] = newVal
		return nil

	case "add_output":
		// If stateValues are present, map them to mutable properties in declaration order
		if stateVals, ok := value["stateValues"]; ok {
			stateNames := anfGetStringSlice(stateVals)
			if anf != nil && len(stateNames) > 0 {
				// Collect mutable properties in declaration order
				var mutableProps []ANFProperty
				for _, prop := range anf.Properties {
					if !prop.Readonly {
						mutableProps = append(mutableProps, prop)
					}
				}
				// Map each state value to the corresponding mutable property
				for j, name := range stateNames {
					if j < len(mutableProps) {
						newVal := env[name]
						env[mutableProps[j].Name] = newVal
						stateDelta[mutableProps[j].Name] = newVal
					}
				}
			}
		}
		return nil

	case "add_data_output":
		// Resolve the two arg refs from env and record the data output.
		// satoshis operand: bigint/int/float — coerce via *big.Int.Int64().
		// scriptBytes operand: ByteString stored as a hex string.
		satRef, _ := value["satoshis"].(string)
		scriptRef, _ := value["scriptBytes"].(string)
		sats := anfToBigInt(env[satRef]).Int64()
		scriptHex := anfToString(env[scriptRef])
		if dataOutputs != nil {
			*dataOutputs = append(*dataOutputs, ContractOutput{
				Script:   scriptHex,
				Satoshis: sats,
			})
		}
		return nil

	case "add_raw_output":
		// `addRawOutput(satoshis, scriptBytes)`. The simulator does not
		// introspect the script bytes (they're caller-supplied raw locking
		// script); it simply forwards them in the result envelope so an
		// off-chain transaction builder can emit the output at the correct
		// index. Crypto built-ins remain mocked even in strict mode.
		satRef, _ := value["satoshis"].(string)
		scriptRef, _ := value["scriptBytes"].(string)
		sats := anfToBigInt(env[satRef]).Int64()
		scriptHex := anfToString(env[scriptRef])
		if rawOutputs != nil {
			*rawOutputs = append(*rawOutputs, ContractOutput{
				Script:   scriptHex,
				Satoshis: sats,
			})
		}
		return nil

	// On-chain-only operations — skip
	case "check_preimage", "deserialize_state", "get_state_script":
		return nil
	}

	return nil
}

// ---------------------------------------------------------------------------
// Binary operations
// ---------------------------------------------------------------------------

func anfEvalBinOp(op string, left, right interface{}, resultType string) interface{} {
	if resultType == "bytes" || (isHexString(left) && isHexString(right)) {
		return anfEvalBytesBinOp(op, anfToString(left), anfToString(right))
	}

	l := anfToBigInt(left)
	r := anfToBigInt(right)

	switch op {
	case "+":
		return new(big.Int).Add(l, r)
	case "-":
		return new(big.Int).Sub(l, r)
	case "*":
		return new(big.Int).Mul(l, r)
	case "/":
		if r.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Quo(l, r)
	case "%":
		if r.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Rem(l, r)
	case "==", "===":
		return l.Cmp(r) == 0
	case "!=", "!==":
		return l.Cmp(r) != 0
	case "<":
		return l.Cmp(r) < 0
	case "<=":
		return l.Cmp(r) <= 0
	case ">":
		return l.Cmp(r) > 0
	case ">=":
		return l.Cmp(r) >= 0
	case "&&":
		return anfIsTruthy(left) && anfIsTruthy(right)
	case "||":
		return anfIsTruthy(left) || anfIsTruthy(right)
	case "&":
		return new(big.Int).And(l, r)
	case "|":
		return new(big.Int).Or(l, r)
	case "^":
		return new(big.Int).Xor(l, r)
	case "<<":
		shift := uint(r.Int64())
		return new(big.Int).Lsh(l, shift)
	case ">>":
		shift := uint(r.Int64())
		return new(big.Int).Rsh(l, shift)
	}
	return big.NewInt(0)
}

func anfEvalBytesBinOp(op, left, right string) interface{} {
	switch op {
	case "+": // cat
		return left + right
	case "==", "===":
		return left == right
	case "!=", "!==":
		return left != right
	}
	return ""
}

// ---------------------------------------------------------------------------
// Unary operations
// ---------------------------------------------------------------------------

func anfEvalUnaryOp(op string, operand interface{}, resultType string) interface{} {
	if resultType == "bytes" {
		if op == "~" {
			h := anfToString(operand)
			b, _ := hex.DecodeString(h)
			for i := range b {
				b[i] = ^b[i]
			}
			return hex.EncodeToString(b)
		}
		return operand
	}

	val := anfToBigInt(operand)
	switch op {
	case "-":
		return new(big.Int).Neg(val)
	case "!":
		return !anfIsTruthy(operand)
	case "~":
		return new(big.Int).Not(val)
	}
	return val
}

// ---------------------------------------------------------------------------
// Built-in function calls
// ---------------------------------------------------------------------------

func anfEvalCall(funcName string, args []interface{}, realCrypto *RealCryptoCtx, fixture *InterpreterFixture, methodName string) interface{} {
	switch funcName {
	// Crypto — mocked unless real-crypto context is present.
	case "checkSig":
		if realCrypto == nil {
			return true
		}
		var sig, pk interface{}
		if len(args) > 0 {
			sig = args[0]
		}
		if len(args) > 1 {
			pk = args[1]
		}
		return anfVerifyEcdsa(sig, pk, realCrypto.Sighash[:])
	case "checkMultiSig":
		if realCrypto == nil {
			return true
		}
		var sigs, pks interface{}
		if len(args) > 0 {
			sigs = args[0]
		}
		if len(args) > 1 {
			pks = args[1]
		}
		return anfVerifyMultiSig(sigs, pks, realCrypto.Sighash[:])
	case "checkPreimage":
		if realCrypto == nil {
			return true
		}
		var pre interface{}
		if len(args) > 0 {
			pre = args[0]
		}
		return anfVerifyPreimage(pre, realCrypto.Sighash[:])

	// Crypto — real hashes
	case "sha256":
		return anfHashFn("sha256", args[0])
	case "hash256":
		return anfHashFn("hash256", args[0])
	case "hash160":
		return anfHashFn("hash160", args[0])
	case "ripemd160":
		return anfHashFn("ripemd160", args[0])

	// Assert — skip
	case "assert":
		return nil

	// Byte operations
	case "num2bin":
		n := anfToBigInt(args[0])
		length := int(anfToBigInt(args[1]).Int64())
		return anfNum2binHex(n, length)

	case "bin2num":
		return anfBin2numBigInt(anfToString(args[0]))

	case "cat":
		return anfToString(args[0]) + anfToString(args[1])

	case "substr":
		h := anfToString(args[0])
		start := int(anfToBigInt(args[1]).Int64())
		length := int(anfToBigInt(args[2]).Int64())
		lo := start * 2
		hi := (start + length) * 2
		if lo > len(h) {
			lo = len(h)
		}
		if hi > len(h) {
			hi = len(h)
		}
		return h[lo:hi]

	case "reverseBytes":
		h := anfToString(args[0])
		pairs := make([]string, 0, len(h)/2)
		for i := 0; i+1 < len(h); i += 2 {
			pairs = append(pairs, h[i:i+2])
		}
		for i, j := 0, len(pairs)-1; i < j; i, j = i+1, j-1 {
			pairs[i], pairs[j] = pairs[j], pairs[i]
		}
		return strings.Join(pairs, "")

	case "len":
		h := anfToString(args[0])
		return big.NewInt(int64(len(h) / 2))

	// Math builtins
	case "abs":
		v := anfToBigInt(args[0])
		return new(big.Int).Abs(v)

	case "min":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		if a.Cmp(b) < 0 {
			return new(big.Int).Set(a)
		}
		return new(big.Int).Set(b)

	case "max":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		if a.Cmp(b) > 0 {
			return new(big.Int).Set(a)
		}
		return new(big.Int).Set(b)

	case "within":
		x := anfToBigInt(args[0])
		lo := anfToBigInt(args[1])
		hi := anfToBigInt(args[2])
		return x.Cmp(lo) >= 0 && x.Cmp(hi) < 0

	case "safediv":
		a := anfToBigInt(args[0])
		d := anfToBigInt(args[1])
		if d.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Quo(a, d)

	case "safemod":
		a := anfToBigInt(args[0])
		d := anfToBigInt(args[1])
		if d.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Rem(a, d)

	case "clamp":
		v := anfToBigInt(args[0])
		lo := anfToBigInt(args[1])
		hi := anfToBigInt(args[2])
		if v.Cmp(lo) < 0 {
			return new(big.Int).Set(lo)
		}
		if v.Cmp(hi) > 0 {
			return new(big.Int).Set(hi)
		}
		return new(big.Int).Set(v)

	case "sign":
		v := anfToBigInt(args[0])
		return big.NewInt(int64(v.Sign()))

	case "pow":
		base := anfToBigInt(args[0])
		exp := anfToBigInt(args[1])
		if exp.Sign() < 0 {
			return big.NewInt(0)
		}
		result := big.NewInt(1)
		for i := big.NewInt(0); i.Cmp(exp) < 0; i.Add(i, big.NewInt(1)) {
			result.Mul(result, base)
		}
		return result

	case "sqrt":
		v := anfToBigInt(args[0])
		if v.Sign() <= 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Sqrt(v)

	case "gcd":
		a := new(big.Int).Abs(anfToBigInt(args[0]))
		b := new(big.Int).Abs(anfToBigInt(args[1]))
		return new(big.Int).GCD(nil, nil, a, b)

	case "divmod":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		if b.Sign() == 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Quo(a, b)

	case "log2":
		v := anfToBigInt(args[0])
		if v.Sign() <= 0 {
			return big.NewInt(0)
		}
		return big.NewInt(int64(v.BitLen() - 1))

	case "bool":
		if anfIsTruthy(args[0]) {
			return big.NewInt(1)
		}
		return big.NewInt(0)

	case "mulDiv":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		c := anfToBigInt(args[2])
		prod := new(big.Int).Mul(a, b)
		return new(big.Int).Quo(prod, c)

	case "percentOf":
		a := anfToBigInt(args[0])
		b := anfToBigInt(args[1])
		prod := new(big.Int).Mul(a, b)
		return new(big.Int).Quo(prod, big.NewInt(10000))

	// Preimage intrinsics — return dummy values
	case "extractOutputHash", "extractAmount":
		return strings.Repeat("00", 32)

	// -------------------------------------------------------------------
	// Intent-covenant intrinsics (BSVM Phase 13).
	//
	// These three handlers mirror the TS reference AST interpreter in
	// `packages/runar-testing/src/interpreter/interpreter.ts`. They
	// replay the desugared ANF semantics (hash256+equals; hashOutputs+
	// substr+equals; locktime read) directly so contracts that use
	// `extractPrevOutputScript`, `requireOutputP2PKH`, or
	// `currentBlockHeight` can be exercised end-to-end via the Go ANF
	// interpreter without going through the on-chain Script VM.
	//
	// Witness bytes are sourced from the InterpreterFixture supplied to
	// ExecuteWithFixture / ExecuteStrictWithFixture. Failures (hash
	// mismatch, missing witness) panic with *IntentIntrinsicError which
	// runMethod recovers and returns as a typed Go error.
	// -------------------------------------------------------------------
	case "extractPrevOutputScript":
		// 2-arg form: extractPrevOutputScript(inputIndex_lit, expectedScriptHash)
		// 3-arg form: extractPrevOutputScript(inputIndex_lit, expectedPrefixHash, prefixLen_lit)
		if len(args) < 2 {
			return ""
		}
		idx := anfToBigInt(args[0])
		witnessName := fmt.Sprintf("_prevOutScript_%s", idx.String())
		if fixture == nil || fixture.witnessBytes == nil {
			panic(&IntentIntrinsicError{
				Intrinsic:      "extractPrevOutputScript",
				MethodName:     methodName,
				MissingWitness: true,
				Message: fmt.Sprintf(
					"extractPrevOutputScript(%s) requires witness bytes. Call InterpreterFixture.SetPrevOutScript(%s, bytes) before invoking the method.",
					idx.String(), idx.String(),
				),
			})
		}
		witness, ok := fixture.witnessBytes[witnessName]
		if !ok {
			panic(&IntentIntrinsicError{
				Intrinsic:      "extractPrevOutputScript",
				MethodName:     methodName,
				MissingWitness: true,
				Message: fmt.Sprintf(
					"extractPrevOutputScript(%s) requires witness bytes. Call InterpreterFixture.SetPrevOutScript(%s, bytes) before invoking the method.",
					idx.String(), idx.String(),
				),
			})
		}
		expectedHashHex := anfToString(args[1])
		expectedHash, _ := hex.DecodeString(expectedHashHex)
		var bytesToHash []byte
		if len(args) == 3 {
			prefixLen := int(anfToBigInt(args[2]).Int64())
			if prefixLen > len(witness) {
				prefixLen = len(witness)
			}
			bytesToHash = witness[:prefixLen]
		} else {
			bytesToHash = witness
		}
		s1 := sha256.Sum256(bytesToHash)
		s2 := sha256.Sum256(s1[:])
		if !bytesEqualSlice(s2[:], expectedHash) {
			panic(&IntentIntrinsicError{
				Intrinsic:  "extractPrevOutputScript",
				MethodName: methodName,
				Message: fmt.Sprintf(
					"extractPrevOutputScript(%s): hash256(witness) !== expectedHash",
					idx.String(),
				),
			})
		}
		return hex.EncodeToString(witness)

	case "requireOutputP2PKH":
		// requireOutputP2PKH(outputIndex_lit, pubkeyHash, amount): asserts
		// serialised-outputs witness hashes to extractOutputHash(preimage),
		// and that the 34-byte slice at idx*34 equals the canonical P2PKH
		// output bytes (LE-8 amount ‖ 1976a914 ‖ pkh ‖ 88ac).
		if len(args) < 3 {
			return nil
		}
		idx := anfToBigInt(args[0])
		pubkeyHashHex := anfToString(args[1])
		pubkeyHash, _ := hex.DecodeString(pubkeyHashHex)
		amount := anfToBigInt(args[2])
		if fixture == nil || fixture.witnessBytes == nil {
			panic(&IntentIntrinsicError{
				Intrinsic:      "requireOutputP2PKH",
				MethodName:     methodName,
				MissingWitness: true,
				Message: "requireOutputP2PKH requires serialised-outputs witness bytes. " +
					"Call InterpreterFixture.SetSerialisedOutputs(bytes) before invoking the method.",
			})
		}
		serialised, ok := fixture.witnessBytes["_serialisedOutputs"]
		if !ok {
			panic(&IntentIntrinsicError{
				Intrinsic:      "requireOutputP2PKH",
				MethodName:     methodName,
				MissingWitness: true,
				Message: "requireOutputP2PKH requires serialised-outputs witness bytes. " +
					"Call InterpreterFixture.SetSerialisedOutputs(bytes) before invoking the method.",
			})
		}
		// hash256(serialised) === extractOutputHash(preimage)
		s1 := sha256.Sum256(serialised)
		s2 := sha256.Sum256(s1[:])
		var expectedOutHash []byte
		if fixture.mockPreimageBytes != nil {
			expectedOutHash = fixture.mockPreimageBytes["outputHash"]
		}
		if expectedOutHash == nil {
			expectedOutHash = make([]byte, 32)
		}
		if !bytesEqualSlice(s2[:], expectedOutHash) {
			panic(&IntentIntrinsicError{
				Intrinsic:  "requireOutputP2PKH",
				MethodName: methodName,
				Message:    "requireOutputP2PKH: hash256(serialisedOutputs) !== preimage.hashOutputs",
			})
		}
		// Build expected P2PKH output: 8-byte LE amount ‖ 1976a914 ‖ pkh ‖ 88ac
		expected := make([]byte, 8+4+20+2)
		a := new(big.Int).Set(amount)
		mask := big.NewInt(0xff)
		for i := 0; i < 8; i++ {
			expected[i] = byte(new(big.Int).And(a, mask).Int64())
			a.Rsh(a, 8)
		}
		expected[8], expected[9], expected[10], expected[11] = 0x19, 0x76, 0xa9, 0x14
		if len(pubkeyHash) != 20 {
			panic(&IntentIntrinsicError{
				Intrinsic:  "requireOutputP2PKH",
				MethodName: methodName,
				Message:    fmt.Sprintf("requireOutputP2PKH(%s): pubkeyHash must be 20 bytes, got %d", idx.String(), len(pubkeyHash)),
			})
		}
		copy(expected[12:32], pubkeyHash)
		expected[32], expected[33] = 0x88, 0xac
		offset := int(new(big.Int).Mul(idx, big.NewInt(34)).Int64())
		hi := offset + 34
		if offset < 0 || offset > len(serialised) {
			offset = len(serialised)
		}
		if hi > len(serialised) {
			hi = len(serialised)
		}
		slice := serialised[offset:hi]
		if !bytesEqualSlice(slice, expected) {
			panic(&IntentIntrinsicError{
				Intrinsic:  "requireOutputP2PKH",
				MethodName: methodName,
				Message:    fmt.Sprintf("requireOutputP2PKH(%s): output bytes mismatch", idx.String()),
			})
		}
		return nil

	case "currentBlockHeight":
		// Source-level sugar for extractLocktime(this.txPreimage). The TS
		// reference returns _mockPreimage.locktime, defaulting to 0n.
		if fixture != nil && fixture.mockPreimage != nil {
			if v, ok := fixture.mockPreimage["locktime"]; ok && v != nil {
				return new(big.Int).Set(v)
			}
		}
		return big.NewInt(0)
	}

	return nil
}

// bytesEqualSlice is a small helper that mirrors bytes.Equal without
// pulling the `bytes` import just for this use site.
func bytesEqualSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Real ECDSA / preimage verification (used by ExecuteOnChainAuthoritative)
// ---------------------------------------------------------------------------

// anfToHexBytes converts an interface{} value to a raw byte slice. Accepts
// hex strings (even-length, lowercase or uppercase), []byte, and []interface{}
// of byte-sized integers. Returns nil on any malformed input — the caller
// treats nil as a verification failure rather than a Go-level error.
func anfToHexBytes(v interface{}) []byte {
	switch val := v.(type) {
	case string:
		if len(val)%2 != 0 {
			return nil
		}
		b, err := hex.DecodeString(val)
		if err != nil {
			return nil
		}
		return b
	case []byte:
		out := make([]byte, len(val))
		copy(out, val)
		return out
	case []interface{}:
		out := make([]byte, len(val))
		for i, item := range val {
			switch x := item.(type) {
			case float64:
				if x < 0 || x > 255 {
					return nil
				}
				out[i] = byte(x)
			case int:
				if x < 0 || x > 255 {
					return nil
				}
				out[i] = byte(x)
			case int64:
				if x < 0 || x > 255 {
					return nil
				}
				out[i] = byte(x)
			default:
				return nil
			}
		}
		return out
	}
	return nil
}

// anfVerifyEcdsa parses sigVal as DER (with optional trailing sighash byte
// stripped — Bitcoin convention) and pkVal as a SEC1 secp256k1 public key
// (compressed or uncompressed), then ECDSA-verifies against the supplied
// 32-byte sighash. Returns false on any parse error or signature mismatch.
//
// The digest passed to the ECDSA verify is the raw 32-byte sighash — this
// matches the on-chain OP_CHECKSIG semantic (no extra hashing) and the TS
// reference's behaviour, where signatures are produced by RFC 6979
// ECDSA-sign(sighash, priv) directly and the verify path lands on the same
// 32-byte scalar.
func anfVerifyEcdsa(sigVal, pkVal interface{}, sighash []byte) bool {
	sigBytes := anfToHexBytes(sigVal)
	pkBytes := anfToHexBytes(pkVal)
	if sigBytes == nil || pkBytes == nil {
		return false
	}
	// Bitcoin DER signatures may carry a trailing 1-byte sighash type
	// (e.g. 0x41 SIGHASH_ALL|FORKID). Strip it before parsing the DER body.
	if len(sigBytes) >= 2 && sigBytes[0] == 0x30 {
		declared := int(sigBytes[1]) + 2
		if len(sigBytes) == declared+1 {
			sigBytes = sigBytes[:declared]
		}
	}
	return ecdsaVerify(sigBytes, pkBytes, sighash)
}

// anfVerifyMultiSig iterates signatures left-to-right and consumes pubkeys
// greedily, mirroring Bitcoin's OP_CHECKMULTISIG. Returns true iff every
// signature finds a matching pubkey.
func anfVerifyMultiSig(sigsVal, pksVal interface{}, sighash []byte) bool {
	sigs, sigsOk := sigsVal.([]interface{})
	pks, pksOk := pksVal.([]interface{})
	if !sigsOk || !pksOk {
		return false
	}
	if len(sigs) > len(pks) {
		return false
	}
	pkIdx := 0
	for _, sig := range sigs {
		matched := false
		for pkIdx < len(pks) {
			ok := anfVerifyEcdsa(sig, pks[pkIdx], sighash)
			pkIdx++
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// anfVerifyPreimage replicates the on-chain BIP-143 / OP_PUSH_TX semantic:
// the supplied preimage's double-SHA-256 must equal the sighash the caller
// provided to ExecuteOnChainAuthoritative.
func anfVerifyPreimage(preimageVal interface{}, sighash []byte) bool {
	preBytes := anfToHexBytes(preimageVal)
	if preBytes == nil {
		return false
	}
	digest := Hash256(ByteString(preBytes))
	if len(digest) != len(sighash) {
		return false
	}
	for i := range sighash {
		if digest[i] != sighash[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

func anfHashFn(name string, input interface{}) string {
	h := anfToString(input)
	data, _ := hex.DecodeString(h)

	switch name {
	case "sha256":
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	case "hash256":
		first := sha256.Sum256(data)
		second := sha256.Sum256(first[:])
		return hex.EncodeToString(second[:])
	case "hash160":
		s := sha256.Sum256(data)
		r := ripemd160.New()
		r.Write(s[:])
		return hex.EncodeToString(r.Sum(nil))
	case "ripemd160":
		r := ripemd160.New()
		r.Write(data)
		return hex.EncodeToString(r.Sum(nil))
	}
	return ""
}

// ---------------------------------------------------------------------------
// Numeric helpers
// ---------------------------------------------------------------------------

// anfToBigInt converts an interface{} value to *big.Int.
// Handles *big.Int, float64, string (plain or "42n" format), json.Number, int64, int, bool.
func anfToBigInt(v interface{}) *big.Int {
	switch val := v.(type) {
	case *big.Int:
		return new(big.Int).Set(val)
	case int64:
		return big.NewInt(val)
	case int:
		return big.NewInt(int64(val))
	case float64:
		// JSON numbers arrive as float64
		return big.NewInt(int64(val))
	case bool:
		if val {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	case string:
		s := val
		// Handle "42n" bigint format
		if len(s) > 0 && s[len(s)-1] == 'n' {
			s = s[:len(s)-1]
		}
		n := new(big.Int)
		if _, ok := n.SetString(s, 10); ok {
			return n
		}
		return big.NewInt(0)
	}
	return big.NewInt(0)
}

func anfIsTruthy(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case *big.Int:
		return val.Sign() != 0
	case int64:
		return val != 0
	case int:
		return val != 0
	case float64:
		return val != 0
	case string:
		return val != "" && val != "0" && val != "false"
	}
	return false
}

func anfToString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// isHexString checks whether v is a string that looks like a hex-encoded byte string
// (even length, all hex chars). Returns false for numeric strings and booleans.
func isHexString(v interface{}) bool {
	s, ok := v.(string)
	if !ok || len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// anfToInt extracts an int64 from a JSON value (float64, string, etc.).
func anfToInt(v interface{}) int64 {
	switch val := v.(type) {
	case float64:
		return int64(val)
	case int64:
		return val
	case int:
		return int64(val)
	case string:
		n := new(big.Int)
		s := val
		if len(s) > 0 && s[len(s)-1] == 'n' {
			s = s[:len(s)-1]
		}
		if _, ok := n.SetString(s, 10); ok {
			return n.Int64()
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Byte encoding helpers
// ---------------------------------------------------------------------------

func anfNum2binHex(n *big.Int, byteLen int) string {
	if n.Sign() == 0 {
		return strings.Repeat("00", byteLen)
	}

	negative := n.Sign() < 0
	abs := new(big.Int).Abs(n)

	var bytes []byte
	for abs.Sign() > 0 {
		b := byte(new(big.Int).And(abs, big.NewInt(0xff)).Int64())
		bytes = append(bytes, b)
		abs.Rsh(abs, 8)
	}

	// Sign bit handling
	if len(bytes) > 0 {
		if negative {
			if bytes[len(bytes)-1]&0x80 == 0 {
				bytes[len(bytes)-1] |= 0x80
			} else {
				bytes = append(bytes, 0x80)
			}
		} else {
			if bytes[len(bytes)-1]&0x80 != 0 {
				bytes = append(bytes, 0x00)
			}
		}
	}

	// Pad or truncate
	for len(bytes) < byteLen {
		bytes = append(bytes, 0x00)
	}
	if len(bytes) > byteLen {
		bytes = bytes[:byteLen]
	}

	return hex.EncodeToString(bytes)
}

func anfBin2numBigInt(h string) *big.Int {
	if len(h) == 0 {
		return big.NewInt(0)
	}
	bytes := make([]byte, 0, len(h)/2)
	for i := 0; i+1 < len(h); i += 2 {
		b, err := hex.DecodeString(h[i : i+2])
		if err != nil {
			return big.NewInt(0)
		}
		bytes = append(bytes, b[0])
	}
	if len(bytes) == 0 {
		return big.NewInt(0)
	}

	negative := bytes[len(bytes)-1]&0x80 != 0
	if negative {
		bytes[len(bytes)-1] &= 0x7f
	}

	// Little-endian to big.Int
	result := big.NewInt(0)
	for i := len(bytes) - 1; i >= 0; i-- {
		result.Lsh(result, 8)
		result.Or(result, big.NewInt(int64(bytes[i])))
	}

	if negative {
		result.Neg(result)
	}
	return result
}

// ---------------------------------------------------------------------------
// ANF JSON helpers
// ---------------------------------------------------------------------------

// anfGetStringSlice extracts a []string from a JSON array ([]interface{}).
func anfGetStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, len(arr))
	for i, item := range arr {
		result[i], _ = item.(string)
	}
	return result
}

// anfGetBindings extracts []ANFBinding from a JSON array of binding objects.
func anfGetBindings(v interface{}) []ANFBinding {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	bindings := make([]ANFBinding, 0, len(arr))
	for _, item := range arr {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := obj["name"].(string)
		val, _ := obj["value"].(map[string]interface{})
		bindings = append(bindings, ANFBinding{
			Name:  name,
			Value: val,
		})
	}
	return bindings
}

// buildNamedArgs maps user-visible ABI params to their resolved argument values
// by name. This produces the named-args map that ComputeNewState expects.
func buildNamedArgs(userParams []ABIParam, resolvedArgs []interface{}) map[string]interface{} {
	named := make(map[string]interface{})
	for i, param := range userParams {
		if i < len(resolvedArgs) {
			named[param.Name] = resolvedArgs[i]
		}
	}
	return named
}
