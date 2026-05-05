//go:build ignore

// ANF interpreter parity driver — Go SDK.
//
// Spec: ../PROTOCOL.md
//
// Reads a single JSON input file, invokes the Go SDK's
// ComputeNewStateAndDataOutputs (lenient) or ExecuteStrict (strict) ANF
// interpreter entry point, and prints a single JSON output object on stdout.
//
// Invocation:
//
//	driver <input.json>                  # lenient (default)
//	driver --mode=strict <input.json>    # strict
//	driver --mode=on-chain <input.json>  # strict + real-crypto
//
// Strict mode emits {error: "AssertionFailureError", methodName, bindingName}
// on the first falsy `assert(...)` predicate; otherwise the same
// {state, dataOutputs} envelope as lenient. On-chain mode behaves like
// strict and additionally verifies `checkSig`/`checkMultiSig`/`checkPreimage`
// against the 32-byte `sighash` field carried in the input JSON.
//
// Bigints travel as "42n"-suffixed strings on the wire. The driver decodes
// them to *big.Int when reading currentState/args/constructorArgs and
// re-encodes back to "Xn" strings when writing state and dataOutputs satoshis.
//
// Run as either:
//
//	go run conformance/anf-interpreter/drivers/go/driver.go <input.json>
//	go build -o anf-driver-go conformance/anf-interpreter/drivers/go/driver.go && ./anf-driver-go <input.json>

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	runar "github.com/icellan/runar/packages/runar-go"
)

var bigintRe = regexp.MustCompile(`^-?\d+n$`)

// decodeBigints walks the value tree and converts "Xn"-suffixed strings into
// *big.Int. Maps and slices are walked in place.
func decodeBigints(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		if bigintRe.MatchString(val) {
			n := new(big.Int)
			if _, ok := n.SetString(val[:len(val)-1], 10); ok {
				return n
			}
		}
		return val
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, item := range val {
			out[i] = decodeBigints(item)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, item := range val {
			out[k] = decodeBigints(item)
		}
		return out
	}
	return v
}

// encodeBigints walks the value tree and converts integer-shaped values back
// into "Xn"-suffixed strings. *big.Int, int*, uint*, and JSON-derived float64
// integers all become bigint-encoded strings. Booleans and non-integer floats
// pass through unchanged.
func encodeBigints(v interface{}) interface{} {
	switch val := v.(type) {
	case *big.Int:
		return val.String() + "n"
	case bool:
		return val
	case int:
		return fmt.Sprintf("%dn", val)
	case int8:
		return fmt.Sprintf("%dn", val)
	case int16:
		return fmt.Sprintf("%dn", val)
	case int32:
		return fmt.Sprintf("%dn", val)
	case int64:
		return fmt.Sprintf("%dn", val)
	case uint:
		return fmt.Sprintf("%dn", val)
	case uint8:
		return fmt.Sprintf("%dn", val)
	case uint16:
		return fmt.Sprintf("%dn", val)
	case uint32:
		return fmt.Sprintf("%dn", val)
	case uint64:
		return fmt.Sprintf("%dn", val)
	case float64:
		// JSON unmarshalling yields float64 for plain numbers; bigints arrive
		// already wrapped as *big.Int via decodeBigints, so any float we see
		// in the result must come from the interpreter itself producing an
		// untyped numeric value. Treat integer-valued floats as bigints.
		if val == float64(int64(val)) {
			return fmt.Sprintf("%dn", int64(val))
		}
		return val
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, item := range val {
			out[i] = encodeBigints(item)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, item := range val {
			out[k] = encodeBigints(item)
		}
		return out
	}
	return v
}

// resolveAnfPath returns the path to the ANF IR. The protocol spec uses an
// `anfPath` field; the inputs checked into this repo currently use the
// shorter `case` form (test name under conformance/tests/<case>/expected-ir.json).
// Accept either so this driver works against both shapes.
func resolveAnfPath(input map[string]interface{}, inputFile string) (string, error) {
	if anfPath, ok := input["anfPath"].(string); ok && anfPath != "" {
		abs, err := filepath.Abs(anfPath)
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	caseName, ok := input["case"].(string)
	if !ok || caseName == "" {
		return "", fmt.Errorf("input JSON missing both 'anfPath' and 'case' fields")
	}
	// inputFile = .../conformance/anf-interpreter/inputs/<file>.json
	// → .../conformance/tests/<case>/expected-ir.json
	absInput, err := filepath.Abs(inputFile)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(absInput)
	// Walk up to the conformance/ directory.
	conformanceRoot := ""
	for cur := dir; cur != "/" && cur != "."; cur = filepath.Dir(cur) {
		if filepath.Base(cur) == "conformance" {
			conformanceRoot = cur
			break
		}
	}
	if conformanceRoot == "" {
		return "", fmt.Errorf("could not locate conformance/ directory walking up from %s", dir)
	}
	return filepath.Join(conformanceRoot, "tests", caseName, "expected-ir.json"), nil
}

func toMap(v interface{}) map[string]interface{} {
	if v == nil {
		return map[string]interface{}{}
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

func toSlice(v interface{}) []interface{} {
	if v == nil {
		return []interface{}{}
	}
	if s, ok := v.([]interface{}); ok {
		return s
	}
	return []interface{}{}
}

// mode discriminates the three interpreter entry points the driver routes to.
type mode int

const (
	modeLenient mode = iota
	modeStrict
	modeOnChain
)

func run() error {
	// Parse flags: optional --mode=strict / --mode=on-chain (or
	// --mode=lenient, the default). Anything else is the input file. Order
	// is irrelevant.
	m := modeLenient
	var inputFile string
	for _, a := range os.Args[1:] {
		switch {
		case a == "--mode=strict":
			m = modeStrict
		case a == "--mode=lenient":
			m = modeLenient
		case a == "--mode=on-chain":
			m = modeOnChain
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown flag: %s", a)
		default:
			if inputFile != "" {
				return fmt.Errorf("usage: driver [--mode=strict|--mode=on-chain] <input-json-file>")
			}
			inputFile = a
		}
	}
	if inputFile == "" {
		return fmt.Errorf("usage: driver [--mode=strict|--mode=on-chain] <input-json-file>")
	}

	rawData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(rawData, &raw); err != nil {
		return fmt.Errorf("parse input JSON: %w", err)
	}

	methodName, _ := raw["methodName"].(string)
	if methodName == "" {
		return fmt.Errorf("input JSON missing 'methodName'")
	}

	currentState := toMap(decodeBigints(toMap(raw["currentState"])))
	args := toMap(decodeBigints(toMap(raw["args"])))
	constructorArgs := toSlice(decodeBigints(toSlice(raw["constructorArgs"])))

	anfPath, err := resolveAnfPath(raw, inputFile)
	if err != nil {
		return err
	}
	anfData, err := os.ReadFile(anfPath)
	if err != nil {
		return fmt.Errorf("read ANF IR at %s: %w", anfPath, err)
	}

	var anf runar.ANFProgram
	if err := json.Unmarshal(anfData, &anf); err != nil {
		return fmt.Errorf("parse ANF IR: %w", err)
	}

	var (
		state       map[string]interface{}
		dataOutputs []runar.ContractOutput
		rawOutputs  []runar.ContractOutput
		interpErr   error
	)
	switch m {
	case modeOnChain:
		sighashHex, _ := raw["sighash"].(string)
		if sighashHex == "" {
			return fmt.Errorf("on-chain mode requires 'sighash' field in input JSON")
		}
		ctx, err := runar.NewRealCryptoCtxFromHex(sighashHex)
		if err != nil {
			return fmt.Errorf("invalid sighash: %w", err)
		}
		state, dataOutputs, rawOutputs, interpErr = runar.ExecuteOnChainAuthoritative(
			&anf, methodName, currentState, args, constructorArgs, ctx,
		)
	case modeStrict:
		state, dataOutputs, rawOutputs, interpErr = runar.ExecuteStrict(
			&anf, methodName, currentState, args, constructorArgs,
		)
	default:
		state, dataOutputs, rawOutputs, interpErr = runar.ComputeNewStateAndDataOutputs(
			&anf, methodName, currentState, args, constructorArgs,
		)
	}
	if interpErr != nil {
		// Strict / on-chain AssertionFailure: emit the standard envelope so
		// the cross-tier parity test can byte-compare. All other errors are
		// real driver bugs (missing IR, malformed input, …) and surface via
		// the non-zero exit + stderr message.
		var af *runar.AssertionFailureError
		if (m == modeStrict || m == modeOnChain) && errors.As(interpErr, &af) {
			result := map[string]interface{}{
				"error":       "AssertionFailureError",
				"methodName":  af.MethodName,
				"bindingName": af.BindingName,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			return enc.Encode(result)
		}
		return fmt.Errorf("interpreter: %w", interpErr)
	}

	encodedState := encodeBigints(state).(map[string]interface{})

	encodedOutputs := make([]map[string]interface{}, 0, len(dataOutputs))
	for _, out := range dataOutputs {
		encodedOutputs = append(encodedOutputs, map[string]interface{}{
			"satoshis": fmt.Sprintf("%dn", out.Satoshis),
			"script":   out.Script,
		})
	}

	encodedRawOutputs := make([]map[string]interface{}, 0, len(rawOutputs))
	for _, out := range rawOutputs {
		encodedRawOutputs = append(encodedRawOutputs, map[string]interface{}{
			"satoshis": fmt.Sprintf("%dn", out.Satoshis),
			"script":   out.Script,
		})
	}

	result := map[string]interface{}{
		"state":       encodedState,
		"dataOutputs": encodedOutputs,
		"rawOutputs":  encodedRawOutputs,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		// Spec: never print partial output on stderr-error paths.
		fmt.Fprintln(os.Stderr, "driver error:", strings.TrimSpace(err.Error()))
		os.Exit(1)
	}
}
