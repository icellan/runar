package runar

import "fmt"

// ---------------------------------------------------------------------------
// SDK-typed errors + DoS-bound constants
// ---------------------------------------------------------------------------

// MaxScriptBytes mirrors InputLimits.MAX_SCRIPT_BYTES (4 MiB) from the TS
// schema package. Any locking script larger than this is rejected at SDK
// entry points (Deploy / Call / Provider.GetUtxos) BEFORE any signing or
// broadcast work is performed. Largest legitimate script measured is
// p384-wallet at ~1.87 MB; 4 MiB gives ~2× headroom.
const MaxScriptBytes = 4 * 1024 * 1024

// ScriptSizeExceededError is returned when a script exceeds MaxScriptBytes
// at a public SDK entry point. Distinct typed error so callers can
// distinguish DoS-bound rejection from generic decode / network errors.
type ScriptSizeExceededError struct {
	Limit   int
	Actual  int
	Context string
}

func (e *ScriptSizeExceededError) Error() string {
	return fmt.Sprintf(
		"script exceeds MAX_SCRIPT_BYTES (limit=%d, actual=%d, context=%s)",
		e.Limit, e.Actual, e.Context,
	)
}

// assertScriptHexUnderLimit returns ScriptSizeExceededError if the hex-encoded
// script exceeds limit (in bytes). Returns nil for empty / under-limit scripts.
func assertScriptHexUnderLimit(scriptHex string, limit int, context string) error {
	// hex string is 2 chars per byte; tolerate odd-length defensively
	actualBytes := (len(scriptHex) + 1) / 2
	if actualBytes > limit {
		return &ScriptSizeExceededError{Limit: limit, Actual: actualBytes, Context: context}
	}
	return nil
}

// WitnessValueMissingError is returned when a method call requires a
// caller-supplied intent-intrinsic witness value (auto-injected
// `_prevOutScript_<i>` or `_serialisedOutputs`) that has not been set on the
// RunarContract.
//
// Auto-injected witness params come from the compiler when a contract method
// uses `extractPrevOutputScript(i)` or `requireOutputP2PKH(...)`. The caller
// must supply concrete bytes for each via SetPrevOutScript / SetSerialisedOutputs
// before invoking Call / PrepareCall.
type WitnessValueMissingError struct {
	ParamName    string
	MethodName   string
	ContractName string
}

func (e *WitnessValueMissingError) Error() string {
	return fmt.Sprintf(
		"witness value missing for auto-injected param '%s' on %s.%s — call SetPrevOutScript(i, bytes) or SetSerialisedOutputs(bytes) before invoking the method",
		e.ParamName, e.ContractName, e.MethodName,
	)
}
