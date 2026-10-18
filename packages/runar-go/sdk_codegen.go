package runar

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------------
// GenerateGo — produce a typed Go wrapper from a compiled RunarArtifact
// ---------------------------------------------------------------------------

// GenerateGo generates a typed Go wrapper source file from a RunarArtifact.
// The generated code wraps RunarContract and exposes typed methods for each
// public contract method, with appropriate options types for terminal vs
// state-mutating methods.
func GenerateGo(artifact *RunarArtifact) string {
	ctx := buildCodegenContext(artifact)
	return renderMustache(goWrapperTemplate, ctx)
}

// ---------------------------------------------------------------------------
// Type mapping
// ---------------------------------------------------------------------------

var goTypeMap = map[string]string{
	"bigint":         "*big.Int",
	"boolean":        "bool",
	"Sig":            "string",
	"PubKey":         "string",
	"ByteString":     "string",
	"Addr":           "string",
	"Ripemd160":      "string",
	"Sha256":         "string",
	"Point":          "string",
	"SigHashPreimage": "string",
}

func mapTypeToGo(abiType string) string {
	if t, ok := goTypeMap[abiType]; ok {
		return t
	}
	return "interface{}"
}

// ---------------------------------------------------------------------------
// Name conversion utilities
// ---------------------------------------------------------------------------

// toPascalCase converts camelCase to PascalCase: "releaseBySeller" -> "ReleaseBySeller"
func toPascalCase(name string) string {
	if len(name) == 0 {
		return name
	}
	runes := []rune(name)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// toSnakeCase converts camelCase to snake_case: "releaseBySeller" -> "release_by_seller"
func toSnakeCase(name string) string {
	var result []rune
	runes := []rune(name)
	for i, r := range runes {
		if unicode.IsUpper(r) {
			// Insert underscore before uppercase letter (but not at the start)
			if i > 0 {
				// Check if previous char is lowercase or next char is lowercase
				// to handle sequences like "PKH" -> "pkh" vs "changePKH" -> "change_pkh"
				prev := runes[i-1]
				if unicode.IsLower(prev) || (i+1 < len(runes) && unicode.IsLower(runes[i+1])) {
					result = append(result, '_')
				}
			}
			result = append(result, unicode.ToLower(r))
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

// Go reserved method names on the generated wrapper struct.
var goReservedNames = map[string]bool{
	"Connect":           true,
	"Deploy":            true,
	"Contract":          true,
	"GetLockingScript":  true,
	"AttachInscription": true,
}

// safeGoMethodName generates a safe method name, avoiding collisions with
// wrapper struct methods. If a collision is detected, the name is prefixed
// with "Call".
func safeGoMethodName(name string) string {
	pascal := toPascalCase(name)
	if goReservedNames[pascal] {
		return "Call" + pascal
	}
	return pascal
}

// ---------------------------------------------------------------------------
// Param classification
// ---------------------------------------------------------------------------

type classifiedParam struct {
	name    string
	abiType string
	goType  string
	hidden  bool
}

// classifyParams separates method params into user-visible and hidden
// (auto-computed by the SDK).
//
// Hidden params:
//   - Sig: auto-computed from the connected signer (two-pass signing)
//   - SigHashPreimage: auto-computed for stateful contracts
//   - _changePKH, _changeAmount, _newAmount: auto-injected by SDK for stateful contracts
//   - _prevOutScript_<i>, _serialisedOutputs: intent-intrinsic witnesses, set
//     via SetPrevOutScript / SetSerialisedOutputs
//
// Of these, Sig params are included in the args array as nil (the SDK
// auto-computes them), while the rest are entirely SDK-internal and excluded
// from the args array (isSdkSuppliedParam, shared with PrepareCall).
func classifyParams(params []ABIParam, isStateful bool) []classifiedParam {
	result := make([]classifiedParam, len(params))
	for i, p := range params {
		hidden := p.Type == "Sig" || isSdkSuppliedParam(p.Name, p.Type, isStateful)
		result[i] = classifiedParam{
			name:    p.Name,
			abiType: p.Type,
			goType:  mapTypeToGo(p.Type),
			hidden:  hidden,
		}
	}
	return result
}

// getUserParams returns only the user-visible params for a method.
func getUserParams(params []ABIParam, isStateful bool) []classifiedParam {
	classified := classifyParams(params, isStateful)
	var result []classifiedParam
	for _, p := range classified {
		if !p.hidden {
			result = append(result, p)
		}
	}
	return result
}

// getSdkArgParams returns params that match the SDK's args array: all params
// except the ones the SDK handles entirely internally (isSdkSuppliedParam —
// the same predicate PrepareCall's arity check uses).
// Sig params ARE included (passed as nil for auto-computation by the SDK).
func getSdkArgParams(params []ABIParam, isStateful bool) []classifiedParam {
	classified := classifyParams(params, isStateful)
	var result []classifiedParam
	for _, p := range classified {
		if !isSdkSuppliedParam(p.name, p.abiType, isStateful) {
			result = append(result, p)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Terminal detection
// ---------------------------------------------------------------------------

// isTerminalMethod determines if a method is terminal (no state continuation
// output). For stateless contracts, all methods are terminal. For stateful
// contracts, falls back to checking for the absence of _changePKH in params.
func isTerminalMethod(method ABIMethod, isStateful bool) bool {
	if !isStateful {
		return true
	}
	// N-038: a SIGHASH_SINGLE method continues the contract without a
	// _changePKH param (the change output is not committed), so for it the
	// ABI's isTerminal flag decides.
	if method.SigHashType != nil && (*method.SigHashType&0x1f) == 0x03 {
		return method.IsTerminal != nil && *method.IsTerminal
	}
	// Fallback: check for absence of _changePKH param
	for _, p := range method.Params {
		if p.Name == "_changePKH" {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Artifact analysis
// ---------------------------------------------------------------------------

func isStatefulArtifact(artifact *RunarArtifact) bool {
	return len(artifact.StateFields) > 0
}

func getPublicMethods(artifact *RunarArtifact) []ABIMethod {
	var result []ABIMethod
	for _, m := range artifact.ABI.Methods {
		if m.IsPublic {
			result = append(result, m)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Codegen context builder
// ---------------------------------------------------------------------------

// codegenParam holds the template context for a single parameter.
type codegenParam struct {
	Name    string
	Type    string
	AbiType string
	IsLast  bool
}

// codegenSigParam holds the template context for a Sig parameter.
type codegenSigParam struct {
	Name     string
	ArgIndex int
	IsLast   bool
}

// codegenMethod holds the template context for a single method.
type codegenMethod struct {
	OriginalName       string
	Name               string
	CapitalizedName    string
	IsTerminal         bool
	IsStatefulMethod   bool
	HasSigParams       bool
	HasUserParams      bool
	UserParams         []codegenParam
	SdkArgsExpr        string
	SigParams          []codegenSigParam
	SigEntriesExpr     string
	HasPrepareUserParams bool
	PrepareUserParams  []codegenParam
}

// buildCodegenContext transforms a RunarArtifact into the template context map
// consumed by the Mustache template.
func buildCodegenContext(artifact *RunarArtifact) map[string]interface{} {
	isStateful := isStatefulArtifact(artifact)
	publicMethods := getPublicMethods(artifact)

	// Constructor params
	ctorParams := artifact.ABI.Constructor.Params
	constructorParams := make([]map[string]interface{}, len(ctorParams))
	for i, p := range ctorParams {
		constructorParams[i] = map[string]interface{}{
			"name":   toPascalCase(p.Name),
			"type":   mapTypeToGo(p.Type),
			"isLast": i == len(ctorParams)-1,
		}
	}

	// Check if any params use *big.Int
	hasBigIntParams := false
	for _, p := range ctorParams {
		if p.Type == "bigint" {
			hasBigIntParams = true
			break
		}
	}

	// Build constructor args expression
	ctorArgParts := make([]string, len(constructorParams))
	for i, cp := range constructorParams {
		ctorArgParts[i] = cp["name"].(string)
	}
	constructorArgsExpr := strings.Join(ctorArgParts, ", ")

	// Methods
	hasStatefulMethods := false
	hasTerminalMethods := false
	if isStateful {
		for _, m := range publicMethods {
			if !isTerminalMethod(m, isStateful) {
				hasStatefulMethods = true
			} else {
				hasTerminalMethods = true
			}
		}
	} else {
		hasTerminalMethods = len(publicMethods) > 0
	}

	methods := make([]map[string]interface{}, 0, len(publicMethods))
	for _, method := range publicMethods {
		userParamsRaw := getUserParams(method.Params, isStateful)
		sdkArgsRaw := getSdkArgParams(method.Params, isStateful)
		terminal := isTerminalMethod(method, isStateful)
		methodName := safeGoMethodName(method.Name)

		// User params for template
		userParams := make([]map[string]interface{}, len(userParamsRaw))
		for i, p := range userParamsRaw {
			goName := toPascalCase(p.name)
			userParams[i] = map[string]interface{}{
				"name":   goName,
				"type":   p.goType,
				"isLast": i == len(userParamsRaw)-1,
			}
			if p.abiType == "bigint" {
				hasBigIntParams = true
			}
		}

		// SDK args expression
		sdkArgParts := make([]string, len(sdkArgsRaw))
		for i, p := range sdkArgsRaw {
			if p.hidden {
				sdkArgParts[i] = "nil"
			} else {
				sdkArgParts[i] = toPascalCase(p.name)
			}
		}
		sdkArgsExpr := strings.Join(sdkArgParts, ", ")

		// Sig params (for prepare/finalize)
		var sigParams []map[string]interface{}
		for _, sp := range sdkArgsRaw {
			if sp.abiType != "Sig" {
				continue
			}
			// Find the arg index in the sdk args array
			idx := -1
			for j, a := range sdkArgsRaw {
				if a.name == sp.name {
					idx = j
					break
				}
			}
			sigParams = append(sigParams, map[string]interface{}{
				"name":     toPascalCase(sp.name),
				"argIndex": idx,
			})
		}
		// Set isLast on sig params
		for i := range sigParams {
			sigParams[i]["isLast"] = i == len(sigParams)-1
		}

		// Sig entries expression for FinalizeCall
		sigEntryParts := make([]string, len(sigParams))
		for i, sp := range sigParams {
			sigEntryParts[i] = fmt.Sprintf("%d: %s", sp["argIndex"], sp["name"])
		}
		sigEntriesExpr := strings.Join(sigEntryParts, ", ")

		// Prepare user params (user params minus Sig)
		var prepareUserParams []map[string]interface{}
		for _, up := range userParamsRaw {
			if up.abiType == "Sig" {
				continue
			}
			prepareUserParams = append(prepareUserParams, map[string]interface{}{
				"name": toPascalCase(up.name),
				"type": up.goType,
			})
		}
		// Set isLast on prepare user params
		for i := range prepareUserParams {
			prepareUserParams[i]["isLast"] = i == len(prepareUserParams)-1
		}

		// capitalizedName for Go is the same as methodName (already PascalCase)
		capitalizedName := methodName

		m := map[string]interface{}{
			"originalName":         method.Name,
			"name":                 methodName,
			"capitalizedName":      capitalizedName,
			"isTerminal":           terminal,
			"isStatefulMethod":     !terminal && isStateful,
			"hasSigParams":         len(sigParams) > 0,
			"hasUserParams":        len(userParamsRaw) > 0,
			"userParams":           userParams,
			"sdkArgsExpr":          sdkArgsExpr,
			"sigParams":            sigParams,
			"sigEntriesExpr":       sigEntriesExpr,
			"hasPrepareUserParams": len(prepareUserParams) > 0,
			"prepareUserParams":    prepareUserParams,
		}
		methods = append(methods, m)
	}

	return map[string]interface{}{
		"contractName":        artifact.ContractName,
		"isStateful":          isStateful,
		"hasStatefulMethods":  hasStatefulMethods,
		"hasTerminalMethods":  hasTerminalMethods,
		"hasConstructorParams": len(ctorParams) > 0,
		"hasBigIntParams":     hasBigIntParams,
		"constructorParams":   constructorParams,
		"constructorArgsExpr": constructorArgsExpr,
		"methods":             methods,
	}
}

// ---------------------------------------------------------------------------
// Minimal Mustache renderer
// ---------------------------------------------------------------------------
// Supports: {{var}}, {{#section}}...{{/section}}, {{^section}}...{{/section}}
// No HTML escaping, no partials, no lambdas.
//
// The template is rendered in a single left-to-right pass. A section's body
// is rendered against a context STACK: entering an array item or map pushes
// it, and every lookup walks the stack from the innermost context outwards,
// so {{#isTerminal}} inside {{#methods}} resolves against the current method
// first and falls back to the root. Go's RE2 engine does not support
// backreferences, so the matching close tag is found by scanning tags with a
// depth counter rather than with a single regex.

// tagRegex matches {{key}}, {{#key}}, {{^key}} and {{/key}}.
var tagRegex = regexp.MustCompile(`\{\{([#^/]?)(\w+)\}\}`)

func renderMustache(template string, context map[string]interface{}) string {
	return renderSection(template, []map[string]interface{}{context})
}

// lookupContext resolves key against the context stack, innermost first.
func lookupContext(stack []map[string]interface{}, key string) (interface{}, bool) {
	for i := len(stack) - 1; i >= 0; i-- {
		if v, ok := stack[i][key]; ok {
			return v, true
		}
	}
	return nil, false
}

// findSectionClose returns the [start, end) offsets of the {{/key}} tag that
// closes a section of the given key whose body starts at from, honouring
// nested sections of the same key. Returns -1, -1 if it is unclosed.
func findSectionClose(template string, from int, key string) (int, int) {
	depth := 0
	for _, m := range tagRegex.FindAllStringSubmatchIndex(template[from:], -1) {
		if template[from+m[4]:from+m[5]] != key {
			continue
		}
		switch template[from+m[2] : from+m[3]] {
		case "#", "^":
			depth++
		case "/":
			if depth == 0 {
				return from + m[0], from + m[1]
			}
			depth--
		}
	}
	return -1, -1
}

func renderSection(template string, stack []map[string]interface{}) string {
	var out strings.Builder
	pos := 0
	for pos < len(template) {
		m := tagRegex.FindStringSubmatchIndex(template[pos:])
		if m == nil {
			out.WriteString(template[pos:])
			break
		}
		tagStart, tagEnd := pos+m[0], pos+m[1]
		sigil := template[pos+m[2] : pos+m[3]]
		key := template[pos+m[4] : pos+m[5]]
		out.WriteString(template[pos:tagStart])

		switch sigil {
		case "":
			// Variable interpolation.
			if value, exists := lookupContext(stack, key); exists && value != nil {
				out.WriteString(fmt.Sprintf("%v", value))
			}
			pos = tagEnd
		case "#", "^":
			closeStart, closeEnd := findSectionClose(template, tagEnd, key)
			if closeStart < 0 {
				// Unclosed section: emit the tag literally.
				out.WriteString(template[tagStart:tagEnd])
				pos = tagEnd
				continue
			}
			body := template[tagEnd:closeStart]
			value, exists := lookupContext(stack, key)
			if sigil == "^" {
				// Inverted section: render if falsy/empty
				if !exists || isFalsy(value) {
					out.WriteString(renderSection(body, stack))
				}
			} else if exists && !isFalsy(value) {
				if arr, ok := toSliceOfMaps(value); ok {
					// Array: iterate, each item on top of the stack
					for _, item := range arr {
						out.WriteString(renderSection(body, append(stack[:len(stack):len(stack)], item)))
					}
				} else if obj, ok := value.(map[string]interface{}); ok {
					// Object (map): push onto the stack
					out.WriteString(renderSection(body, append(stack[:len(stack):len(stack)], obj)))
				} else {
					// Truthy scalar: render body with current context
					out.WriteString(renderSection(body, stack))
				}
			}
			pos = closeEnd
		default:
			// Stray close tag: emit literally.
			out.WriteString(template[tagStart:tagEnd])
			pos = tagEnd
		}
	}
	return out.String()
}

// isFalsy returns true if the value should be considered falsy for Mustache
// section rendering.
func isFalsy(value interface{}) bool {
	if value == nil {
		return true
	}
	switch v := value.(type) {
	case bool:
		return !v
	case string:
		return v == ""
	case int:
		return v == 0
	case int64:
		return v == 0
	case float64:
		return v == 0
	case []map[string]interface{}:
		return len(v) == 0
	case []interface{}:
		return len(v) == 0
	}
	return false
}

// toSliceOfMaps attempts to convert value into a []map[string]interface{}.
// It handles both typed slices and []interface{} containing maps.
func toSliceOfMaps(value interface{}) ([]map[string]interface{}, bool) {
	switch v := value.(type) {
	case []map[string]interface{}:
		return v, true
	case []interface{}:
		result := make([]map[string]interface{}, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				result = append(result, m)
			} else {
				return nil, false
			}
		}
		return result, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// Go wrapper template (embedded from codegen/templates/wrapper.go.mustache)
// ---------------------------------------------------------------------------

const goWrapperTemplate = `// Generated by: runar codegen
// Source: {{contractName}}
// Do not edit manually.

package main

import (
{{#hasBigIntParams}}
	"math/big"
{{/hasBigIntParams}}

	runar "github.com/icellan/runar/packages/runar-go"
)

{{#hasTerminalMethods}}
// TerminalOutput specifies an output with either an address or raw script hex.
type TerminalOutput struct {
	Satoshis  int64
	Address   string
	ScriptHex string
}

func resolveTerminalOutputs(outputs []TerminalOutput) []runar.TerminalOutput {
	resolved := make([]runar.TerminalOutput, len(outputs))
	for i, o := range outputs {
		scriptHex := o.ScriptHex
		if scriptHex == "" {
			scriptHex = runar.BuildP2PKHScript(o.Address)
		}
		resolved[i] = runar.TerminalOutput{ScriptHex: scriptHex, Satoshis: o.Satoshis}
	}
	return resolved
}

{{/hasTerminalMethods}}
{{#hasStatefulMethods}}
// {{contractName}}StatefulCallOptions configures a state-mutating method call.
type {{contractName}}StatefulCallOptions struct {
	Satoshis      int64
	ChangeAddress string
	ChangePubKey  string
	NewState      map[string]interface{}
	Outputs       []runar.OutputSpec
}

func (o *{{contractName}}StatefulCallOptions) toCallOptions() *runar.CallOptions {
	if o == nil {
		return nil
	}
	return &runar.CallOptions{
		Satoshis:      o.Satoshis,
		ChangeAddress: o.ChangeAddress,
		ChangePubKey:  o.ChangePubKey,
		NewState:      o.NewState,
		Outputs:       o.Outputs,
	}
}

{{/hasStatefulMethods}}
// {{contractName}}Contract is a typed wrapper for the {{contractName}} contract.
type {{contractName}}Contract struct {
	inner *runar.RunarContract
}

// New{{contractName}}Contract creates a new {{contractName}}Contract instance.
func New{{contractName}}Contract(artifact *runar.RunarArtifact{{#hasConstructorParams}}, {{/hasConstructorParams}}{{#constructorParams}}{{name}} {{type}}{{^isLast}}, {{/isLast}}{{/constructorParams}}) *{{contractName}}Contract {
	return &{{contractName}}Contract{
		inner: runar.NewRunarContract(artifact, []interface{}{ {{constructorArgsExpr}} }),
	}
}

// {{contractName}}ContractFromTxId reconnects to an existing contract UTXO.
func {{contractName}}ContractFromTxId(artifact *runar.RunarArtifact, txid string, outputIndex int, provider runar.Provider) (*{{contractName}}Contract, error) {
	inner, err := runar.FromTxId(artifact, txid, outputIndex, provider)
	if err != nil {
		return nil, err
	}
	return &{{contractName}}Contract{inner: inner}, nil
}

// {{contractName}}ContractFromUtxo reconnects to an existing contract from a known UTXO.
func {{contractName}}ContractFromUtxo(artifact *runar.RunarArtifact, utxo runar.UTXO) (*{{contractName}}Contract, error) {
	inner, err := runar.FromUtxo(artifact, utxo)
	if err != nil {
		return nil, err
	}
	return &{{contractName}}Contract{inner: inner}, nil
}

// AttachInscription attaches a 1sat ordinals inscription to the contract. It returns
// an error when the envelope would break the contract's own SIZE(_codePart) pin.
func (c *{{contractName}}Contract) AttachInscription(insc *runar.Inscription) error {
	_, err := c.inner.WithInscription(insc)
	return err
}

// Connect stores a provider and signer for implicit use.
func (c *{{contractName}}Contract) Connect(provider runar.Provider, signer runar.Signer) {
	c.inner.Connect(provider, signer)
}

// Deploy deploys the contract on-chain.
func (c *{{contractName}}Contract) Deploy(provider runar.Provider, signer runar.Signer, options runar.DeployOptions) (string, *runar.TransactionData, error) {
	return c.inner.Deploy(provider, signer, options)
}

// GetLockingScript returns the full locking script hex.
func (c *{{contractName}}Contract) GetLockingScript() string {
	return c.inner.GetLockingScript()
}

// Contract returns the underlying RunarContract.
func (c *{{contractName}}Contract) Contract() *runar.RunarContract {
	return c.inner
}

{{#methods}}
// {{name}} calls the {{originalName}} method on the contract.
func (c *{{contractName}}Contract) {{name}}({{#userParams}}{{name}} {{type}}{{^isLast}}, {{/isLast}}{{/userParams}}{{#hasUserParams}}, {{/hasUserParams}}provider runar.Provider, signer runar.Signer{{#isStatefulMethod}}, options *{{contractName}}StatefulCallOptions{{/isStatefulMethod}}{{#isTerminal}}, outputs []TerminalOutput{{/isTerminal}}) (string, *runar.TransactionData, error) {
{{#isTerminal}}
	var opts *runar.CallOptions
	if outputs != nil {
		resolved := resolveTerminalOutputs(outputs)
		opts = &runar.CallOptions{TerminalOutputs: resolved}
	}
	return c.inner.Call("{{originalName}}", []interface{}{ {{sdkArgsExpr}} }, provider, signer, opts)
{{/isTerminal}}
{{#isStatefulMethod}}
	return c.inner.Call("{{originalName}}", []interface{}{ {{sdkArgsExpr}} }, provider, signer, options.toCallOptions())
{{/isStatefulMethod}}
}

{{#hasSigParams}}
// Prepare{{capitalizedName}} builds the transaction without signing (for external signers).
func (c *{{contractName}}Contract) Prepare{{capitalizedName}}({{#prepareUserParams}}{{name}} {{type}}{{^isLast}}, {{/isLast}}{{/prepareUserParams}}{{#hasPrepareUserParams}}, {{/hasPrepareUserParams}}provider runar.Provider, signer runar.Signer{{#isStatefulMethod}}, options *{{contractName}}StatefulCallOptions{{/isStatefulMethod}}{{#isTerminal}}, outputs []TerminalOutput{{/isTerminal}}) (*runar.PreparedCall, error) {
{{#isTerminal}}
	var opts *runar.CallOptions
	if outputs != nil {
		resolved := resolveTerminalOutputs(outputs)
		opts = &runar.CallOptions{TerminalOutputs: resolved}
	}
	return c.inner.PrepareCall("{{originalName}}", []interface{}{ {{sdkArgsExpr}} }, provider, signer, opts)
{{/isTerminal}}
{{#isStatefulMethod}}
	return c.inner.PrepareCall("{{originalName}}", []interface{}{ {{sdkArgsExpr}} }, provider, signer, options.toCallOptions())
{{/isStatefulMethod}}
}

// Finalize{{capitalizedName}} completes a prepared call with external signatures.
// A nil provider falls back to the one stored by Connect.
func (c *{{contractName}}Contract) Finalize{{capitalizedName}}(prepared *runar.PreparedCall{{#sigParams}}, {{name}} string{{/sigParams}}, provider runar.Provider) (string, *runar.TransactionData, error) {
	return c.inner.FinalizeCall(prepared, map[int]string{ {{sigEntriesExpr}} }, provider)
}

{{/hasSigParams}}
{{/methods}}
`
