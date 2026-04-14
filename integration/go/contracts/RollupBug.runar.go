package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// RollupBug — minimal reproduction of the bsv-evm RUNAR-OPSPLIT-BUG.md report.
//
// Triggers `mandatory-script-verify-flag-failed (Invalid OP_SPLIT range)`
// on regtest with the smallest known shape that reproduces the bug:
//
//   - StatefulSmartContract (state continuation forces variable-length
//     state deserialization on every spend).
//   - One ByteString mutable state field (var-length state path).
//   - One Point readonly field (so we have a curve point to multiply).
//   - One method calling runar.Bn254G1ScalarMulP, the codegen op known
//     to interact badly with stateful state continuation.
//
// All other features (multiple state fields, dual-mode if/else, large
// readonly tail, multi-arg methods) are unnecessary — strip them and the
// bug still reproduces. The trigger is purely the combination
// (stateful + Bn254G1ScalarMulP).
type RollupBug struct {
	runar.StatefulSmartContract

	State runar.ByteString
}

// Bug repro: stateful contract with a ByteString state field whose
// compiled script is large enough to push the BIP-143 scriptCode varint
// over the 0xfd (3-byte) threshold into 0xfe (5-byte) territory.
//
// The deserialize_state codegen at compilers/go/codegen/stack.go only
// emits varint stripping for 1-byte (length < 0xfd) and 3-byte
// (0xfd + 2 bytes LE) BIP-143 scriptCode varints. For scripts where
// scriptCode > 65,535 bytes the varint becomes 5 bytes (0xfe + 4 LE),
// the wrong branch is taken, two stale varint bytes corrupt subsequent
// state extraction, and eventually OP_SPLIT receives an out-of-range
// position from a misinterpreted script byte. Bug surfaces as
// `mandatory-script-verify-flag-failed (Invalid OP_SPLIT range)` on
// regtest.
//
// EcMulGen produces ~423 KB of locking script — the smallest single
// op that reliably pushes scriptCode past the 65,535-byte threshold.
func (c *RollupBug) AdvanceState(newState runar.ByteString, scalar runar.Bigint) {
	prepared := runar.EcMulGen(scalar)
	_ = prepared
	c.State = newState
}
