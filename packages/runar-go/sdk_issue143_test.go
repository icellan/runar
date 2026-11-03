package runar

import "testing"

// Issue #143: ExtractConstructorArgs mis-read every slot that followed a
// repeated constructor reference.
//
// A param referenced N times in the contract body emits N constructor slots.
// Every occurrence's encoded width shifts the offsets of everything after it,
// so the extractor must account for ALL occurrences — not just the first per
// param. Regression for a bug where slots were deduplicated by ParamIndex
// BEFORE the offset walk, mis-reading every later slot whenever an earlier
// repeated value encoded wider than its 1-byte template placeholder.
//
// Template: ab <00> 7c <00> 7c <00> ac
//
//	offset 1: alpha (paramIndex 0)
//	offset 3: alpha again (paramIndex 0 — second reference)
//	offset 5: beta  (paramIndex 1)
//
// Resolved with alpha = 500 (scriptnum push `02f401`, 3 bytes) and
// beta = 7 (OP_7, 1 byte):
//
//	ab 02f401 7c 02f401 7c 57 ac
func TestExtractConstructorArgs_RepeatedSlotReferences_Issue143(t *testing.T) {
	artifact := makeArtifact("ab"+"00"+"7c"+"00"+"7c"+"00"+"ac", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{
			{Name: "alpha", Type: "bigint"},
			{Name: "beta", Type: "bigint"},
		}},
	}, func(a *RunarArtifact) {
		a.ConstructorSlots = []ConstructorSlot{
			{ParamIndex: 0, ByteOffset: 1},
			{ParamIndex: 0, ByteOffset: 3},
			{ParamIndex: 1, ByteOffset: 5},
		}
	})

	t.Run("reads slots AFTER a repeated wide value at the correct offsets", func(t *testing.T) {
		resolved := "ab" + "02f401" + "7c" + "02f401" + "7c" + "57" + "ac"
		args := mustExtractConstructorArgs(t, artifact, resolved)
		if got := args["alpha"]; got != int64(500) {
			t.Errorf("alpha = %v (%T), want int64(500)", got, got)
		}
		// Before the fix the second alpha occurrence's +2 byte shift was
		// dropped, so beta was read from inside the second alpha push and
		// decoded as 124 instead of 7.
		if got := args["beta"]; got != int64(7) {
			t.Errorf("beta = %v (%T), want int64(7)", got, got)
		}
	})

	t.Run("still extracts correctly when the repeated value fits its placeholder width", func(t *testing.T) {
		// alpha = 5 → OP_5 (1 byte, same width as the placeholder: zero shift).
		resolved := "ab" + "55" + "7c" + "55" + "7c" + "57" + "ac"
		args := mustExtractConstructorArgs(t, artifact, resolved)
		if got := args["alpha"]; got != int64(5) {
			t.Errorf("alpha = %v (%T), want int64(5)", got, got)
		}
		if got := args["beta"]; got != int64(7) {
			t.Errorf("beta = %v (%T), want int64(7)", got, got)
		}
	})
}
