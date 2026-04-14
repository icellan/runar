package helpers

import (
	"fmt"
	"strings"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// BuildGroth16WALockingScript generates the Bitcoin Script hex for a
// witness-assisted Groth16 verifier with the given VK config. The locking
// script has no constructor slots — the VK is baked into the script at
// emit time. Use this with the runar-go SDK or raw TX helpers to protect
// a UTXO.
//
// This produces only the verifier body (no method-dispatch framing), since
// Emit() wraps single-method programs with no preamble.
func BuildGroth16WALockingScript(config codegen.Groth16Config) (string, error) {
	var ops []codegen.StackOp
	codegen.EmitGroth16VerifierWitnessAssisted(func(op codegen.StackOp) {
		ops = append(ops, op)
	}, config)

	method := codegen.StackMethod{Name: "groth16wa", Ops: ops}
	result, err := codegen.Emit([]codegen.StackMethod{method})
	if err != nil {
		return "", fmt.Errorf("emit groth16 WA locking script: %w", err)
	}
	return result.ScriptHex, nil
}

// BuildGroth16WAUnlockingScript serializes a witness bundle as the
// unlocking script hex. Witness values are pushed in the same order the
// verifier consumes them (matching bn254witness.Witness.ToStackOps). We do
// NOT route this through codegen.Emit because Emit() assumes a method body
// and may inject dispatch logic; the unlocking script should be pure push
// data only.
func BuildGroth16WAUnlockingScript(w *bn254witness.Witness) (string, error) {
	ops := w.ToStackOps()
	var sb strings.Builder
	for i, op := range ops {
		if op.Op != "push" {
			return "", fmt.Errorf("witness op %d is %q, expected push", i, op.Op)
		}
		if op.Value.Kind != "bigint" {
			return "", fmt.Errorf("witness op %d push kind %q, expected bigint", i, op.Value.Kind)
		}
		if op.Value.BigInt == nil {
			return "", fmt.Errorf("witness op %d has nil BigInt", i)
		}
		sb.WriteString(EncodePushBigInt(op.Value.BigInt))
	}
	return sb.String(), nil
}

// WitnessPushCount is a small helper for tests that need to log / reason
// about the number of witness values being pushed.
func WitnessPushCount(w *bn254witness.Witness) int {
	return len(w.ToStackOps())
}
