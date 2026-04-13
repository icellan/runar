// Public Bitcoin Script execution helper, promoted from the test-only
// buildAndExecute helper in script_correctness_test.go so that test code
// in OTHER packages (notably packages/runar-go/bn254witness) can drive
// end-to-end script tests through the same go-sdk interpreter path.
//
// This file is NOT a _test.go file because non-test packages cannot import
// symbols defined in test files.
package codegen

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
)

// BuildAndExecuteOps emits a Bitcoin Script from a flat slice of StackOps
// (treated as the locking script with an empty unlocking script) and
// executes it through the go-sdk interpreter with Genesis + Chronicle +
// ForkID flags enabled.
//
// This mirrors the test-only buildAndExecute helper in
// script_correctness_test.go (which now wraps this function), and is the
// supported way for external tests — including the bn254witness package's
// end-to-end Groth16 verifier validation — to run codegen output through
// the same script VM the production deployment uses.
//
// Returns nil if the script succeeds, or a wrapped error otherwise.
func BuildAndExecuteOps(ops []StackOp) error {
	method := StackMethod{Name: "test", Ops: ops}
	result, err := Emit([]StackMethod{method})
	if err != nil {
		return fmt.Errorf("emit: %w", err)
	}

	lockScript, err := script.NewFromHex(result.ScriptHex)
	if err != nil {
		return fmt.Errorf("invalid locking script hex: %w", err)
	}

	// Empty unlocking script — all data is in the locking script.
	unlockScript := &script.Script{}

	eng := interpreter.NewEngine()
	return eng.Execute(
		interpreter.WithScripts(lockScript, unlockScript),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
}
