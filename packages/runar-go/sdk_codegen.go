package runar

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// openTagRegex matches Mustache section open tags: {{#key}} or {{^key}}
var openTagRegex = regexp.MustCompile(`\{\{([#^])(\w+)\}\}`)

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
	"Connect":          true,
	"Deploy":           true,
	"Contract":         true,
	"GetLockingScript": true,
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
//
// Of these, Sig params are included in the args array as nil (the SDK
// auto-computes them), while SigHashPreimage/_changePKH/_changeAmount/_newAmount
// are entirely SDK-internal and excluded from the args array.
func classifyParams(params []ABIParam, isStateful bool) []classifiedParam {
	result := make([]classifiedParam, len(params))
	for i, p := range params {
		hidden := p.Type == "Sig" ||
			(isStateful && (p.Type == "SigHashPreimage" ||
				p.Name == "_changePKH" ||
				p.Name == "_changeAmount" ||
				p.Name == "_newAmount"))
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
// except the ones the SDK handles entirely internally (SigHashPreimage,
// _changePKH, _changeAmount, _newAmount) for stateful contracts.
// Sig params ARE included (passed as nil for auto-computation by the SDK).
func getSdkArgParams(params []ABIParam, isStateful bool) []classifiedParam {
	classified := classifyParams(params, isStateful)
	var result []classifiedParam
	for _, p := range classified {
		if !isStateful {
			result = append(result, p)
			continue
		}
		if p.abiType != "SigHashPreimage" &&
			p.name != "_changePKH" &&
			p.name != "_changeAmount" &&
			p.name != "_newAmount" {
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
// Go's RE2 engine does not support backreferences, so section matching is
// done with manual string scanning rather than a single regex.

// varRegex matches variable interpolation tags.
var varRegex = regexp.MustCompile(`\{\{(\w+)\}\}`)

func renderMustache(template string, context map[string]interface{}) string {
	return renderSection(template, context)
}

// findInnermostSection finds the innermost {{#key}}/{{^key}}...{{/key}} section
// in the template. Returns the start/end offsets in the template string,
// the section type ("#" or "^"), the key name, and the body content.
// Returns start=-1 if no section is found.
func findInnermostSection(template string) (start, end int, sectionType, key, body string) {
	// Find all open tags and pick the last one whose matching close tag
	// appears before any other open tag. This gives us an innermost section.
	matches := openTagRegex.FindAllStringSubmatchIndex(template, -1)
	if len(matches) == 0 {
		return -1, 0, "", "", ""
	}

	// Iterate open tags from last to first — the last open tag without a
	// nested open tag before its close is innermost.
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		openStart := m[0]
		openEnd := m[1]
		st := template[m[2]:m[3]]  // "#" or "^"
		k := template[m[4]:m[5]]   // key name

		closeTag := "{{/" + k + "}}"
		closeIdx := strings.Index(template[openEnd:], closeTag)
		if closeIdx < 0 {
			continue
		}
		closeStart := openEnd + closeIdx
		closeEnd := closeStart + len(closeTag)

		// Check that there's no other open tag between openEnd and closeStart
		// that would make this NOT the innermost section.
		nested := false
		for j := i + 1; j < len(matches); j++ {
			if matches[j][0] >= openEnd && matches[j][0] < closeStart {
				nested = true
				break
			}
		}
		if nested {
			continue
		}

		return openStart, closeEnd, st, k, template[openEnd:closeStart]
	}
	return -1, 0, "", "", ""
}

func renderSection(template string, context map[string]interface{}) string {
	result := template

	// Repeatedly process sections from innermost out
	for {
		start, end, sectionType, key, body := findInnermostSection(result)
		if start < 0 {
			break
		}

		var replacement string
		value, exists := context[key]

		if sectionType == "^" {
			// Inverted section: render if falsy/empty
			if !exists || isFalsy(value) {
				replacement = renderSection(body, context)
			}
		} else {
			// Normal section
			if exists && !isFalsy(value) {
				// Array: iterate
				if arr, ok := toSliceOfMaps(value); ok {
					var parts []string
					for _, item := range arr {
						merged := mergeContexts(context, item)
						parts = append(parts, renderSection(body, merged))
					}
					replacement = strings.Join(parts, "")
				} else if m, ok := value.(map[string]interface{}); ok {
					// Object (map): merge into context
					merged := mergeContexts(context, m)
					replacement = renderSection(body, merged)
				} else {
					// Truthy scalar: render body with current context
					replacement = renderSection(body, context)
				}
			}
		}

		result = result[:start] + replacement + result[end:]
	}

	// Replace variables: {{key}}
	result = varRegex.ReplaceAllStringFunc(result, func(match string) string {
		sub := varRegex.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		key := sub[1]
		value, exists := context[key]
		if !exists || value == nil {
			return ""
		}
		return fmt.Sprintf("%v", value)
	})

	return result
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

// mergeContexts creates a new context map with all entries from parent,
// overridden by entries from child.
func mergeContexts(parent, child map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{}, len(parent)+len(child))
	for k, v := range parent {
		merged[k] = v
	}
	for k, v := range child {
		merged[k] = v
	}
	return merged
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
func (c *{{contractName}}Contract) Finalize{{capitalizedName}}(prepared *runar.PreparedCall{{#sigParams}}, {{name}} string{{/sigParams}}) (string, *runar.TransactionData, error) {
	return c.inner.FinalizeCall(prepared, map[int]string{ {{sigEntriesExpr}} })
}

{{/hasSigParams}}
{{/methods}}
`
