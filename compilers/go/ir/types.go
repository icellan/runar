// Package ir defines the Go representation of Rúnar's A-Normal Form intermediate
// representation. These types mirror the canonical ANF IR JSON schema and are
// used to deserialise IR files produced by any conformant Rúnar compiler.
package ir

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// ---------------------------------------------------------------------------
// Program structure
// ---------------------------------------------------------------------------

// ANFProgram is the top-level IR container.
type ANFProgram struct {
	ContractName string        `json:"contractName"`
	Properties   []ANFProperty `json:"properties"`
	Methods      []ANFMethod   `json:"methods"`
	// ParentClass is the base class the source contract extends
	// ("SmartContract" | "StatefulSmartContract" | "UnsafeSmartContract").
	// It is an in-memory carrier ONLY (json:"-") so it never appears in the
	// emitted ANF IR JSON that the conformance suite compares cross-tier.
	// The artifact assembler copies it to the top-level artifact field so
	// SDKs can gate the issue-#42/#44 terminal sighash subscript trim on the
	// authoritative parent class (a StatefulSmartContract with zero mutable
	// fields still needs the trim even though stateFields is empty).
	ParentClass string `json:"-"`
}

// ANFSyntheticArrayLevel is one level of the synthetic FixedArray chain
// attached by the expand-fixed-arrays pass to each scalar leaf property
// that came from an expanded FixedArray declaration. Mirrors the TS
// `__syntheticArrayChain` field on PropertyNode.
type ANFSyntheticArrayLevel struct {
	Base   string `json:"base"`
	Index  int    `json:"index"`
	Length int    `json:"length"`
}

// ANFProperty describes a contract-level property (constructor parameter).
type ANFProperty struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Readonly     bool        `json:"readonly"`
	InitialValue interface{} `json:"initialValue,omitempty"` // string | number | bool
	// SyntheticArrayChain is populated for scalar leaves that came out
	// of the expand-fixed-arrays pass; nil otherwise. The iterative
	// regrouper in the assembler consumes one level per pass until the
	// chain is empty, collapsing synthetic siblings back into logical
	// FixedArray entries on the ABI / state-field list.
	SyntheticArrayChain []ANFSyntheticArrayLevel `json:"syntheticArrayChain,omitempty"`
}

// ANFMethod is a single contract method.
type ANFMethod struct {
	Name     string       `json:"name"`
	Params   []ANFParam   `json:"params"`
	Body     []ANFBinding `json:"body"`
	IsPublic bool         `json:"isPublic"`

	// SigHashType is the non-default BIP-143 sighash mode a `@sighash`
	// directive declared for this (public) method (issue #123), e.g. 0x43 for
	// SINGLE|FORKID. Nil = default ALL|FORKID (0x41). Carried in-memory only
	// (json:"-") so it never appears in the emitted ANF IR JSON compared
	// cross-tier — the codegen-relevant flag rides on each check_preimage
	// node's sighashFlag instead. The artifact assembler copies it to
	// ABIMethod.SigHashType so the SDK builds a matching preimage.
	SigHashType *int `json:"-"`
}

// ANFParam describes a method parameter.
type ANFParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ---------------------------------------------------------------------------
// Source location (shared across IR and codegen packages)
// ---------------------------------------------------------------------------

// SourceLocation records a position in a source file. Used for debug info
// (source maps) and diagnostics.
type SourceLocation struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// ---------------------------------------------------------------------------
// Bindings — the core of the ANF representation
// ---------------------------------------------------------------------------

// ANFBinding is a single let-binding: `let <Name> = <Value>`.
// Names follow the pattern t0, t1, ... and are scoped per method.
type ANFBinding struct {
	Name      string          `json:"name"`
	Value     ANFValue        `json:"value"`
	SourceLoc *SourceLocation `json:"sourceLoc,omitempty"`
}

// ---------------------------------------------------------------------------
// ANF value types (discriminated on Kind)
// ---------------------------------------------------------------------------

// ANFValue uses a flat struct with a Kind discriminator. Only the fields
// relevant to the specific Kind are populated. This approach avoids the need
// for interface-based dispatch while remaining straightforward to deserialise
// from JSON.
type ANFValue struct {
	Kind string `json:"kind"`

	// load_param, load_prop, update_prop
	Name string `json:"name,omitempty"`

	// load_const — the raw JSON value is decoded separately
	RawValue json.RawMessage `json:"value,omitempty"`

	// Decoded constant value (populated by decodeConstValue)
	ConstString *string   `json:"-"`
	ConstBigInt *big.Int  `json:"-"`
	ConstBool   *bool     `json:"-"`
	ConstInt    *int64    `json:"-"` // small integers from JSON numbers

	// bin_op
	Op         string `json:"op,omitempty"`
	Left       string `json:"left,omitempty"`
	Right      string `json:"right,omitempty"`
	ResultType string `json:"result_type,omitempty"` // operand type hint: "bytes" for byte-typed equality

	// unary_op
	Operand string `json:"operand,omitempty"`

	// call
	Func string   `json:"func,omitempty"`
	Args []string `json:"args,omitempty"`

	// method_call
	Object string `json:"object,omitempty"`
	Method string `json:"method,omitempty"`

	// if
	Cond string       `json:"cond,omitempty"`
	Then []ANFBinding `json:"then,omitempty"`
	Else []ANFBinding `json:"else,omitempty"`
	// Ordered named result slots both arms leave (Results[0] deepest). Entries
	// name a branch-merged local or an arm-written contract property; stack
	// lowering tells the two apart from the contract's property list, so the
	// wire format stays a plain array of strings. Absent (not empty) when the
	// `if` carries at most one result — see the TypeScript reference in
	// packages/runar-compiler/src/ir/anf-ir.ts for the full contract.
	Results []string `json:"results,omitempty"`

	// loop
	Count   int    `json:"count,omitempty"`
	IterVar string `json:"iterVar,omitempty"`
	// loop body reuses Then field? No — we use a separate Body field.
	Body []ANFBinding `json:"body,omitempty"`
	// loop iterator start value and step direction (issue #121). The loop is
	// unrolled Count times; on iteration i (0-based) the iterator variable
	// holds Start + i*Step. Zero-start counting-up loops carry Start=0, Step=1,
	// which reproduces the historical i = 0..Count-1 lowering byte-for-byte.
	// Countdown loops carry Step=-1. StartRaw is the raw JSON form (a bare
	// number for int64-range starts, else a decimal `Nn` string) preserved for
	// byte-identical round-tripping; Start is the decoded value.
	StartRaw json.RawMessage `json:"start,omitempty"`
	Step     int             `json:"step,omitempty"`
	Start    *big.Int        `json:"-"`

	// assert, update_prop (value ref), check_preimage
	ValueRef string `json:"-"` // populated from RawValue for assert / update_prop / check_preimage

	// check_preimage, deserialize_state
	Preimage string `json:"preimage,omitempty"`

	// check_preimage — issue #123: the BIP-143 sighash flag the on-chain
	// OP_PUSH_TX binding appends to the derived signature (so the node
	// re-derives the tx sighash under this flag). 0 = default ALL|FORKID
	// (0x41), byte-identical to the pinned cross-tier binding blob. Only set
	// for a method that declares a non-default @sighash mode, keeping golden
	// ANF unchanged for every existing contract. The json tag drives --ir
	// deserialization; emission is handled by MarshalJSON.
	SighashFlag int `json:"sighashFlag,omitempty"`

	// add_output
	Satoshis    string   `json:"satoshis,omitempty"`
	StateValues []string `json:"stateValues,omitempty"`

	// add_raw_output
	ScriptBytes string `json:"scriptBytes,omitempty"`

	// array_literal
	Elements []string `json:"elements,omitempty"`

	// raw_script — opaque opcode-byte span with declared stack arity.
	Bytes    string `json:"bytes,omitempty"`
	InArity  int    `json:"in_arity,omitempty"`
	OutArity int    `json:"out_arity,omitempty"`

	// assert (auto-injected stateful-continuation marker).
	// True only on the compiler-emitted
	// `hash256(continuationOutputs) === extractOutputHash(txPreimage)`
	// assert. Off-chain SDK interpreters use this to skip the equality
	// check without resorting to structural / taint heuristics that
	// misfire on developer covenant asserts whose IR shape is identical.
	// Custom MarshalJSON elides this when false to keep fold-OFF goldens
	// stable for developer asserts.
	IsAutoInjectedStateCheck bool `json:"isAutoInjectedStateCheck,omitempty"`
}

// MarshalJSON emits only the fields relevant to v.Kind so the byte-level
// output matches the canonical TypeScript ANF JSON shape (anf-ir.ts).
//
// The flat-struct layout of ANFValue does not map cleanly onto JSON tags
// because each variant has its own set of required fields. Using
// `omitempty` everywhere would silently elide fields that TS emits as
// explicit empties (e.g. `"else": []` on an if without else, or
// `"preimage": ""` on an add_output), breaking byte-identical conformance
// against the golden files.
func (v ANFValue) MarshalJSON() ([]byte, error) {
	out := make(map[string]interface{}, 4)
	out["kind"] = v.Kind

	switch v.Kind {
	case "load_param", "load_prop":
		out["name"] = v.Name
	case "load_const":
		if len(v.RawValue) > 0 {
			out["value"] = v.RawValue
		} else {
			out["value"] = nil
		}
	case "bin_op":
		out["op"] = v.Op
		out["left"] = v.Left
		out["right"] = v.Right
		if v.ResultType != "" {
			out["result_type"] = v.ResultType
		}
	case "unary_op":
		out["op"] = v.Op
		out["operand"] = v.Operand
		if v.ResultType != "" {
			out["result_type"] = v.ResultType
		}
	case "call":
		out["func"] = v.Func
		if v.Args == nil {
			out["args"] = []string{}
		} else {
			out["args"] = v.Args
		}
	case "method_call":
		out["object"] = v.Object
		out["method"] = v.Method
		if v.Args == nil {
			out["args"] = []string{}
		} else {
			out["args"] = v.Args
		}
	case "if":
		out["cond"] = v.Cond
		if v.Then == nil {
			out["then"] = []ANFBinding{}
		} else {
			out["then"] = v.Then
		}
		if v.Else == nil {
			out["else"] = []ANFBinding{}
		} else {
			out["else"] = v.Else
		}
		if len(v.Results) > 0 {
			out["results"] = v.Results
		}
	case "loop":
		out["count"] = v.Count
		out["iterVar"] = v.IterVar
		if v.Body == nil {
			out["body"] = []ANFBinding{}
		} else {
			out["body"] = v.Body
		}
		// Issue #121: emit the iterator start value and step direction, matching
		// the TypeScript ANF JSON. StartRaw preserves the exact numeric/string
		// encoding (bare number for int64-range starts, `Nn` string otherwise).
		if len(v.StartRaw) > 0 {
			out["start"] = v.StartRaw
		} else if v.Start != nil {
			out["start"] = BigIntToRawJSON(v.Start)
		} else {
			out["start"] = 0
		}
		if v.Step != 0 {
			out["step"] = v.Step
		} else {
			out["step"] = 1
		}
	case "assert":
		// Prefer the decoded ValueRef when populated by DecodeConstants;
		// otherwise fall back to the raw JSON value for pre-decode round-trips.
		if v.ValueRef != "" {
			out["value"] = v.ValueRef
		} else if len(v.RawValue) > 0 {
			out["value"] = v.RawValue
		} else {
			out["value"] = ""
		}
		if v.IsAutoInjectedStateCheck {
			out["isAutoInjectedStateCheck"] = true
		}
	case "update_prop":
		out["name"] = v.Name
		if v.ValueRef != "" {
			out["value"] = v.ValueRef
		} else if len(v.RawValue) > 0 {
			out["value"] = v.RawValue
		} else {
			out["value"] = ""
		}
	case "get_state_script":
		// kind only
	case "check_preimage", "deserialize_state":
		out["preimage"] = v.Preimage
		// Issue #123: emit the non-default sighash flag only when set, so the
		// golden ANF for every existing (default ALL|FORKID) contract is
		// byte-identical.
		if v.Kind == "check_preimage" && v.SighashFlag != 0 {
			out["sighashFlag"] = v.SighashFlag
		}
	case "add_output":
		out["preimage"] = v.Preimage
		out["satoshis"] = v.Satoshis
		if v.StateValues == nil {
			out["stateValues"] = []string{}
		} else {
			out["stateValues"] = v.StateValues
		}
	case "add_raw_output":
		out["satoshis"] = v.Satoshis
		out["scriptBytes"] = v.ScriptBytes
	case "add_data_output":
		// Wire shape identical to add_raw_output; distinguished only by
		// position in the continuation-hash concatenation.
		out["satoshis"] = v.Satoshis
		out["scriptBytes"] = v.ScriptBytes
	case "array_literal":
		if v.Elements == nil {
			out["elements"] = []string{}
		} else {
			out["elements"] = v.Elements
		}
	case "raw_script":
		// Opaque opcode-byte span — emit bytes + arities explicitly so
		// in_arity 0 / out_arity 0 survive (omitempty would drop them).
		out["bytes"] = v.Bytes
		out["in_arity"] = v.InArity
		out["out_arity"] = v.OutArity
	default:
		// Fall back to the struct-tag shape for any unknown kind so we
		// don't silently drop fields while debugging new variants.
		type anfValueAlias ANFValue
		return json.Marshal(anfValueAlias(v))
	}

	return json.Marshal(out)
}

// DecodeConstants walks the program and decodes the RawValue fields in
// load_const bindings into their typed Go representations, and extracts
// the value reference string for assert/update_prop kinds.
func DecodeConstants(program *ANFProgram) error {
	for mi := range program.Methods {
		if err := decodeBindings(program.Methods[mi].Body); err != nil {
			return fmt.Errorf("method %s: %w", program.Methods[mi].Name, err)
		}
	}
	return nil
}

func decodeBindings(bindings []ANFBinding) error {
	for i := range bindings {
		v := &bindings[i].Value
		if err := decodeValue(v); err != nil {
			return fmt.Errorf("binding %s: %w", bindings[i].Name, err)
		}
	}
	return nil
}

func decodeValue(v *ANFValue) error {
	switch v.Kind {
	case "load_const":
		return decodeConstValue(v)
	case "assert":
		// The "value" field is a string reference
		if len(v.RawValue) > 0 {
			var s string
			if err := json.Unmarshal(v.RawValue, &s); err != nil {
				return fmt.Errorf("assert value: %w", err)
			}
			v.ValueRef = s
		}
	case "update_prop":
		// The "value" field is a string reference
		if len(v.RawValue) > 0 {
			var s string
			if err := json.Unmarshal(v.RawValue, &s); err != nil {
				return fmt.Errorf("update_prop value: %w", err)
			}
			v.ValueRef = s
		}
	case "if":
		if err := decodeBindings(v.Then); err != nil {
			return fmt.Errorf("if/then: %w", err)
		}
		if err := decodeBindings(v.Else); err != nil {
			return fmt.Errorf("if/else: %w", err)
		}
	case "loop":
		// Issue #121: decode the iterator start value (bare number or `Nn`
		// string) and default a missing step to +1 (older payloads without
		// start/step describe zero-start counting-up loops).
		if len(v.StartRaw) > 0 {
			bi, err := decodeBigIntFromRaw(v.StartRaw)
			if err != nil {
				return fmt.Errorf("loop/start: %w", err)
			}
			v.Start = bi
		} else {
			v.Start = big.NewInt(0)
		}
		if v.Step == 0 {
			v.Step = 1
		}
		if err := decodeBindings(v.Body); err != nil {
			return fmt.Errorf("loop/body: %w", err)
		}
	case "add_output":
		// satoshis and stateValues are decoded directly from JSON tags; nothing extra needed.
	}
	return nil
}

func decodeConstValue(v *ANFValue) error {
	if len(v.RawValue) == 0 {
		return fmt.Errorf("load_const missing value")
	}

	raw := v.RawValue

	// Try boolean
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		// Check it's actually true/false, not a number
		s := string(raw)
		if s == "true" || s == "false" {
			v.ConstBool = &b
			return nil
		}
	}

	// Try string. Strings in the load_const value can be either:
	//   1. A reference (e.g. "@ref:tN" or "@this") — these flow through as
	//      ConstString and downstream codegen treats them specially.
	//   2. A hex-encoded ByteString literal.
	//   3. A decimal-string-encoded BigInt — the canonical encoding for
	//      values that exceed int64 range. Cross-tier IR producers (TS,
	//      Python) emit oversize bigints as quoted decimal strings to
	//      sidestep JSON-number precision loss; Go must distinguish those
	//      from hex-encoded bytestrings or it will silently push the ASCII
	//      digits as a literal byte string.
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		// Distinguish a decimal-encoded BigInt from a hex bytestring:
		// look-ahead refs ("@..." / "@ref:..." / "@this") flow through
		// as ConstString; an all-ASCII-digit string (with optional `-`
		// sign and `n` suffix) is a BigInt literal; anything else is
		// treated as a hex-encoded ByteString.
		if isDecimalBigIntLiteral(str) {
			decimalText := str
			if len(decimalText) > 0 && decimalText[len(decimalText)-1] == 'n' {
				decimalText = decimalText[:len(decimalText)-1]
			}
			bi := new(big.Int)
			if _, ok := bi.SetString(decimalText, 10); ok {
				v.ConstBigInt = bi
				if bi.IsInt64() {
					i := bi.Int64()
					v.ConstInt = &i
				}
				return nil
			}
		}
		v.ConstString = &str
		return nil
	}

	// Try number (JSON numbers can be integers or floats)
	var num json.Number
	if err := json.Unmarshal(raw, &num); err == nil {
		// Try as int64 first
		if i, err := num.Int64(); err == nil {
			v.ConstInt = &i
			bi := big.NewInt(i)
			v.ConstBigInt = bi
			return nil
		}
		// Try as big.Int
		bi := new(big.Int)
		if _, ok := bi.SetString(num.String(), 10); ok {
			v.ConstBigInt = bi
			return nil
		}
	}

	return fmt.Errorf("unable to decode constant value: %s", string(raw))
}

// isDecimalBigIntLiteral reports whether `s` is a JS-style decimal BigInt
// literal: optional leading `-`, one or more ASCII digits, and a REQUIRED
// trailing `n` marker (matching the TS canonical IR encoding for oversize
// bigints, e.g. "115792089237316195...n"). The trailing `n` is the
// discriminator that separates a decimal-encoded BigInt from a hex-encoded
// ByteString literal (which never carries the suffix), so a hex string
// like "3030" is not mis-decoded as the integer 3030.
func isDecimalBigIntLiteral(s string) bool {
	if len(s) < 2 || s[len(s)-1] != 'n' {
		return false
	}
	start := 0
	if s[0] == '-' {
		start = 1
	}
	body := s[start : len(s)-1]
	if len(body) == 0 {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// jsMaxSafeInteger is Number.MAX_SAFE_INTEGER (2^53 - 1) — the largest integer
// a bare JSON number survives, because every JSON consumer that decodes into a
// JS number (or into Go's interface{}, which is float64) is an IEEE-754 double.
var jsMaxSafeInteger = big.NewInt(9007199254740991)

// IsJSSafeInteger reports whether val round-trips through a bare JSON number
// without loss. int64 is NOT the boundary that matters: `9007199254740993`
// fits int64 but decodes as `9007199254740992` in every double-backed reader.
func IsJSSafeInteger(val *big.Int) bool {
	return val.CmpAbs(jsMaxSafeInteger) <= 0
}

// BigIntToRawJSON encodes a big.Int into the canonical Rúnar IR JSON form: a
// bare JSON number for JS-safe-integer values, else a quoted decimal string
// with the JS BigInt `n` suffix. The suffix is also the discriminator that
// separates a decimal-encoded BigInt from a hex-encoded ByteString literal
// (which never carries it). Byte-identical to the TypeScript ANF JSON, whose
// reviver collapses safe-integer `Nn` strings back to plain numbers.
func BigIntToRawJSON(val *big.Int) json.RawMessage {
	var raw json.RawMessage
	if IsJSSafeInteger(val) {
		raw, _ = json.Marshal(val.Int64())
	} else {
		raw, _ = json.Marshal(val.String() + "n")
	}
	return raw
}

// decodeBigIntFromRaw decodes a loop iterator start value from its raw JSON
// form — a bare number or a decimal `Nn` string (issue #121).
func decodeBigIntFromRaw(raw json.RawMessage) (*big.Int, error) {
	var num json.Number
	if err := json.Unmarshal(raw, &num); err == nil {
		bi := new(big.Int)
		if _, ok := bi.SetString(num.String(), 10); ok {
			return bi, nil
		}
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		text := str
		if len(text) > 0 && text[len(text)-1] == 'n' {
			text = text[:len(text)-1]
		}
		bi := new(big.Int)
		if _, ok := bi.SetString(text, 10); ok {
			return bi, nil
		}
	}
	return nil, fmt.Errorf("unable to decode loop start value: %s", string(raw))
}

// MergedLocalTempPrefix is the name prefix for the temporaries ANF lowering
// appends to BOTH arms of an if-statement that merges two or more locals.
//
// An `if` carries one value, so post-branch references to a merged local can
// only be rewired by aliasing when there is exactly ONE of them. For two or
// more, both arms instead end with an identical K-binding block — K copies
// into `__merge$0..K-1`, then K rebinds of the locals from those temps — which
// leaves the merged values on top in the same canonical order whichever branch
// runs. Stack lowering recognises that trailing block by this prefix, trims
// each arm down to the K results, and adopts them by name.
//
// The prefix is part of the ANF wire format: all seven compilers emit and
// recognise the same block.
const MergedLocalTempPrefix = "__merge$"
