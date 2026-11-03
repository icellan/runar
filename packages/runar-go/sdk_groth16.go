package runar

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// Groth16WAContract — SDK wrapper for witness-assisted Groth16 verifier
// contracts produced by the `runarc groth16-wa` compiler backend (Phase 6).
//
// The Rúnar artifact emitted by Groth16 WA compilation is shaped differently
// from a normal Rúnar contract:
//
//   - One constructor arg, the owner public key (F-233). The verifying key
//     and public inputs are baked into the script at compile time; the owner
//     is spliced in at deploy, and every spend must carry the owner's
//     signature over the spending transaction (`<ownerPubKey>
//     OP_CHECKSIGVERIFY` opens the script). Without it a valid spend's
//     witness, once public, could be replayed into a tx paying anyone.
//   - No standard ABI-encoded method args — the "verify" method's unlock is
//     a RAW witness bundle: gradients, final-exp witnesses, proof points,
//     prepared inputs, all pushed in the order EmitGroth16VerifierWitnessAssisted
//     consumes them. This does not fit the runar.CallOptions model.
//
// This wrapper reuses RunarContract internally for deploy + UTXO tracking,
// but intercepts the spend path: callers pass a `*bn254witness.Witness`
// directly, and the wrapper serializes it as a raw push-only unlock script.
// ---------------------------------------------------------------------------

// Groth16WAContract is a thin wrapper around RunarContract specialized for
// witness-assisted Groth16 verifier artifacts produced by the `runarc
// groth16-wa` compiler backend. Downstream consumers (e.g. bsv-evm) use
// this instead of the generic RunarContract.Call path because the Groth16
// unlock script is a raw witness bundle, not an ABI-encoded arg list.
type Groth16WAContract struct {
	artifact *RunarArtifact
	contract *RunarContract
}

// NewGroth16WAContract wraps a RunarArtifact produced by `runarc groth16-wa`
// (or compiler.CompileGroth16WA) in a Groth16WAContract.
//
// Panics if the artifact is nil or does not have a Groth16WA metadata
// field. The metadata is how we distinguish Groth16 WA artifacts from
// normal Rúnar contracts at runtime — a Groth16 WA artifact ALWAYS has
// it, and a normal contract artifact NEVER does.
func NewGroth16WAContract(artifact *RunarArtifact) *Groth16WAContract {
	if artifact == nil {
		panic("NewGroth16WAContract: nil artifact")
	}
	if artifact.Groth16WA == nil {
		panic("NewGroth16WAContract: artifact has no Groth16WA metadata; was it produced by `runarc groth16-wa`?")
	}
	// The owner public key is not known until Deploy (F-233). Until then
	// every constructor slot holds an empty push, i.e. the template's own
	// OP_0 placeholder, so LockingScript() before Deploy is the template.
	// N-073: the empty-push placeholders are internal template values, not
	// user input, so the fixed-width constructor-arg check is skipped.
	inner := newRunarContract(artifact, groth16WAPlaceholderArgs(artifact), false)
	return &Groth16WAContract{
		artifact: artifact,
		contract: inner,
	}
}

// Artifact returns the underlying RunarArtifact. Useful for callers that
// need to inspect the baked-in script hex or the Groth16WA metadata
// directly (e.g., to re-serialize it as JSON).
func (g *Groth16WAContract) Artifact() *RunarArtifact {
	return g.artifact
}

// NumPubInputs returns the number of public inputs the baked-in Groth16
// verifying key expects. Exposed so callers can sanity-check this against
// their proof fixture before attempting a spend.
func (g *Groth16WAContract) NumPubInputs() int {
	return g.artifact.Groth16WA.NumPubInputs
}

// VKDigest returns the SHA-256 hex digest of the source VK JSON file
// used to compile this artifact. This is a pure reproducibility marker:
// two artifacts with the same VKDigest were produced from byte-identical
// VK files. It is NOT a cryptographic commitment to the VK semantics —
// do not use it as a key for anything load-bearing.
func (g *Groth16WAContract) VKDigest() string {
	return g.artifact.Groth16WA.VKDigest
}

// CurrentUTXO returns the contract's currently tracked UTXO, or nil if
// the contract has not been deployed yet or has already been spent.
func (g *Groth16WAContract) CurrentUTXO() *UTXO {
	return g.contract.GetCurrentUtxo()
}

// SetCurrentUTXO updates the contract's tracked UTXO. Use this to
// reconnect a Groth16WAContract to a previously-deployed UTXO (e.g.,
// when reloading state from disk).
func (g *Groth16WAContract) SetCurrentUTXO(u *UTXO) {
	g.contract.SetCurrentUtxo(u)
}

// LockingScript returns the locking script hex that will be (or was)
// deployed to chain. For Groth16 WA artifacts this is the entire
// verifier script with the VK baked in; it is usually ~500–700 KB.
func (g *Groth16WAContract) LockingScript() string {
	return g.contract.GetLockingScript()
}

// Deploy deploys the Groth16 verifier locking script bound to
// ownerPubKeyHex and returns the deploy txid and TransactionData.
//
// ownerPubKeyHex (a compressed secp256k1 public key, 66 hex chars) is
// spliced into the artifact's ownerPubKey constructor slot; every later
// spend must be signed by its private key (F-233). It is REQUIRED: an empty
// or malformed key is an error, as is an artifact with no owner slot (one
// compiled before F-233), because such an output is spendable by anyone who
// observes a valid witness. Recompile it with the current `runarc
// groth16-wa`.
//
// The deploy itself is a standard P2PKH-funded TX with the verifier locking
// script as output 0, delegated to RunarContract.Deploy.
func (g *Groth16WAContract) Deploy(
	provider Provider,
	signer Signer,
	ownerPubKeyHex string,
	opts DeployOptions,
) (string, *TransactionData, error) {
	params := g.artifact.ABI.Constructor.Params
	slots := g.artifact.ConstructorSlots
	if len(params) != 1 || params[0].Type != "PubKey" || len(slots) != 1 || slots[0].ParamIndex != 0 {
		return "", nil, fmt.Errorf("Groth16WAContract.Deploy: artifact %q has no owner-pubkey constructor slot, so its output would be spendable by anyone who sees a valid witness; recompile it with the current `runarc groth16-wa`", g.artifact.ContractName)
	}
	if ownerPubKeyHex == "" {
		return "", nil, fmt.Errorf("Groth16WAContract.Deploy: owner public key is required: the standalone Groth16 verifier binds every spend to this key's signature")
	}
	if err := validateGroth16WAOwnerPubKey(ownerPubKeyHex); err != nil {
		return "", nil, fmt.Errorf("Groth16WAContract.Deploy: %w", err)
	}

	inner := NewRunarContract(g.artifact, []interface{}{strings.ToLower(ownerPubKeyHex)})
	inner.provider = g.contract.provider
	inner.signer = g.contract.signer
	g.contract = inner
	return g.contract.Deploy(provider, signer, opts)
}

// Connect stores a provider and signer so subsequent Deploy /
// CallWithWitness calls can omit them. Mirrors RunarContract.Connect.
func (g *Groth16WAContract) Connect(provider Provider, signer Signer) {
	g.contract.Connect(provider, signer)
}

// CallWithWitness spends the contract's current UTXO by supplying a
// witness bundle for a specific (proof, public inputs) pair. The witness
// is serialized as a raw stack-push sequence (no method selector, no
// standard ABI framing) matching the order the on-chain verifier script
// consumes — see bn254witness.Witness.ToStackOps for the exact layout.
//
// Destination semantics:
//   - If changeAddress is non-empty, the spend creates a single P2PKH
//     output to changeAddress with (contract UTXO value - fee).
//   - If outputScriptHex is non-empty, the spend creates a single output
//     to that locking script. changeAddress is ignored.
//   - Exactly one of changeAddress / outputScriptHex must be provided.
//
// Provider / signer semantics: if either argument is nil, the value
// stored via Connect() is used. Both are required. The signer must hold
// the owner key the output was deployed to (F-233): the unlock is the
// witness followed by the signer's SIGHASH_ALL|FORKID signature over the
// spend, which is what stops an observer replaying the witness into a
// transaction of their own.
//
// If the witness is valid for the baked-in VK the node accepts the
// spend. Any tampering — flipping a proof byte, corrupting a gradient,
// mangling a final-exp witness — causes an on-chain OP_VERIFY /
// OP_EQUALVERIFY to fail and the node rejects the spend.
//
// After a successful broadcast the contract's current UTXO is cleared
// (the verifier is stateless: once verified there is nothing to
// continue).
//
// Returns the spend txid and the parsed TransactionData.
func (g *Groth16WAContract) CallWithWitness(
	provider Provider,
	signer Signer,
	w *bn254witness.Witness,
	changeAddress string,
	outputScriptHex string,
) (string, *TransactionData, error) {
	// Fall back to Connect()-stored defaults.
	if provider == nil {
		provider = g.contract.provider
	}
	if signer == nil {
		signer = g.contract.signer
	}
	if provider == nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: no provider available; pass one explicitly or call Connect() first")
	}
	if signer == nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: no signer available; the spend must be signed by the owner key the verifier was deployed to — pass one explicitly or call Connect() first")
	}
	if w == nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: nil witness")
	}
	utxo := g.contract.GetCurrentUtxo()
	if utxo == nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: contract has no current UTXO; deploy first or call SetCurrentUTXO")
	}
	if changeAddress == "" && outputScriptHex == "" {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: either changeAddress or outputScriptHex must be provided")
	}
	if changeAddress != "" && outputScriptHex != "" {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: only one of changeAddress or outputScriptHex may be provided")
	}

	// 1. Serialize the witness as a raw push-only unlocking script. The
	//    owner signature is pushed after it (on top of the stack, consumed
	//    first by the script's leading OP_CHECKSIGVERIFY).
	witnessHex, err := serializeWitnessToUnlock(w)
	if err != nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: serialize witness: %w", err)
	}

	// 2. Resolve destination script.
	destScriptHex := outputScriptHex
	if destScriptHex == "" {
		destScriptHex = BuildP2PKHScript(changeAddress)
	}

	// 3. Estimate fee. The spend TX consists of:
	//    - 1 input referencing the ~500 KB contract UTXO (input script is
	//      the witness unlocking hex).
	//    - 1 output with destScriptHex.
	//    Use the provider's fee rate (sat/KB) and the actual tx byte size.
	feeRate, err := provider.GetFeeRate()
	if err != nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: get fee rate: %w", err)
	}

	// Build the spend TX with a placeholder output value and a 72-byte
	// placeholder signature (the DER maximum plus the sighash byte) so the
	// size estimate covers the real signature. We'll refine after this
	// dry-run build.
	dummySigHex := strings.Repeat("00", 72)
	spendTx, err := buildGroth16WASpendTx(utxo, witnessHex+EncodePushData(dummySigHex), destScriptHex, utxo.Satoshis)
	if err != nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: build spend tx: %w", err)
	}

	// Compute fee from the built tx size and adjust the output value.
	// (txHex length / 2 = size in bytes; feeRate is sat/KB.)
	txSize := int64(len(spendTx.Hex()) / 2)
	fee := (txSize*feeRate + 999) / 1000
	// Add a small safety margin so the rebuilt tx (same size modulo
	// VarInt edge cases) never underpays and gets rejected.
	fee += 64
	if fee < 256 {
		fee = 256
	}

	outputSats := utxo.Satoshis - fee
	if outputSats < 546 {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: contract UTXO (%d sats) too small to cover fee (%d sats) and dust minimum", utxo.Satoshis, fee)
	}

	// 4. Rebuild with the real output value, then sign. The signature
	//    commits to the final outputs, so it must come after the rebuild;
	//    the unlocking script is not part of the BIP-143 preimage, so the
	//    placeholder signature present while signing does not matter.
	spendTx, err = buildGroth16WASpendTx(utxo, witnessHex+EncodePushData(dummySigHex), destScriptHex, outputSats)
	if err != nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: rebuild spend tx: %w", err)
	}
	sigHex, err := signer.Sign(spendTx.Hex(), 0, utxo.Script, utxo.Satoshis, nil)
	if err != nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: sign spend: %w", err)
	}
	unlockingHex := witnessHex + EncodePushData(sigHex)
	unlockScript, err := sdkscript.NewFromHex(unlockingHex)
	if err != nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: parse signed unlocking script: %w", err)
	}
	spendTx.Inputs[0].UnlockingScript = unlockScript

	// 5. Broadcast.
	txid, err := provider.Broadcast(spendTx)
	if err != nil {
		return "", nil, fmt.Errorf("Groth16WAContract.CallWithWitness: broadcast: %w", err)
	}

	// 6. Clear the contract's tracked UTXO: the verifier is stateless and
	//    this UTXO is now spent. Keep the contract wrapper alive so the
	//    caller can inspect Artifact() / NumPubInputs() afterwards.
	g.contract.SetCurrentUtxo(nil)

	// 7. Best-effort fetch of the broadcast tx for the caller. On some
	//    providers (regtest nodes without -txindex, WOC staging) this
	//    may fail with "not found"; fall back to a synthesized
	//    TransactionData built from what we know.
	txData, txErr := provider.GetTransaction(txid)
	if txErr != nil || txData == nil {
		txData = &TransactionData{
			Txid:    txid,
			Version: 1,
			Inputs: []TxInput{{
				Txid:        utxo.Txid,
				OutputIndex: utxo.OutputIndex,
				Script:      unlockingHex,
				Sequence:    0xffffffff,
			}},
			Outputs: []TxOutput{{
				Satoshis: outputSats,
				Script:   destScriptHex,
			}},
			Raw: spendTx.Hex(),
		}
	}

	return txid, txData, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// groth16WAPlaceholderArgs returns one empty push per constructor param, so
// the code script built before Deploy is the artifact template itself.
func groth16WAPlaceholderArgs(artifact *RunarArtifact) []interface{} {
	args := make([]interface{}, len(artifact.ABI.Constructor.Params))
	for i := range args {
		args[i] = []byte{}
	}
	return args
}

// validateGroth16WAOwnerPubKey requires a compressed secp256k1 public key
// that is a real curve point. A key that is not one makes the output
// unspendable, which is a silent fund lock rather than a safe default.
func validateGroth16WAOwnerPubKey(pubKeyHex string) error {
	raw, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("owner public key is not hex: %w", err)
	}
	if len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
		return fmt.Errorf("owner public key must be a 33-byte compressed secp256k1 key (66 hex chars, 02/03 prefix), got %d bytes", len(raw))
	}
	// ParsePubKey does not range-check a compressed key's x; x >= p is a
	// non-canonical encoding, not the key the owner signs with.
	if new(big.Int).SetBytes(raw[1:]).Cmp(ec.S256().Params().P) >= 0 {
		return fmt.Errorf("owner public key is not a canonical compressed encoding (x >= p)")
	}
	if _, err := ec.ParsePubKey(raw); err != nil {
		return fmt.Errorf("owner public key is not a valid secp256k1 point: %w", err)
	}
	return nil
}

// serializeWitnessToUnlock converts a witness bundle to the raw unlocking
// script hex expected by the on-chain verifier. Every op emitted by
// Witness.ToStackOps is a "push" of a bigint (that is the invariant the
// witness package promises); we delegate the actual push encoding to
// codegen.EncodePushBigInt so the SDK and codegen agree on the bytes
// produced for a given bigint (specifically the OP_0 / OP_1..OP_16 /
// OP_1NEGATE special cases plus minimal little-endian sign-magnitude
// encoding for everything else — BSV's MINIMALDATA rule rejects scripts
// that miss any of these).
func serializeWitnessToUnlock(w *bn254witness.Witness) (string, error) {
	if w == nil {
		return "", fmt.Errorf("nil witness")
	}
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
		hexStr, _ := codegen.EncodePushBigInt(op.Value.BigInt)
		sb.WriteString(hexStr)
	}
	return sb.String(), nil
}

// encodeScriptNumberBig is retained for backwards compatibility with any
// downstream caller that links the SDK and depends on this symbol. It
// now delegates to codegen.EncodePushBigInt — see serializeWitnessToUnlock
// for the rationale.
func encodeScriptNumberBig(n *big.Int) string {
	hexStr, _ := codegen.EncodePushBigInt(n)
	return hexStr
}

// SerializeGroth16WAWitnessForTests exposes serializeWitnessToUnlock under a
// public name so out-of-package debug helpers can inspect the exact unlock
// hex the SDK produces. Production callers should rely on CallOptions
// .Groth16WAWitness instead.
func SerializeGroth16WAWitnessForTests(w *bn254witness.Witness) string {
	hexStr, err := serializeWitnessToUnlock(w)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}
	return hexStr
}

var _ = hex.EncodeToString // keep import for legacy callers

// buildGroth16WASpendTx builds a Bitcoin transaction spending the
// contract UTXO with the given unlocking script and creating a single
// output with the given destination script + satoshis.
//
// It does not sign: the verifier opens with `<ownerPubKey>
// OP_CHECKSIGVERIFY` (F-233), so CallWithWitness signs the returned
// transaction and replaces the unlocking script's trailing signature push.
func buildGroth16WASpendTx(utxo *UTXO, unlockingScriptHex string, destScriptHex string, outputSats int64) (*transaction.Transaction, error) {
	lockScript, err := sdkscript.NewFromHex(utxo.Script)
	if err != nil {
		return nil, fmt.Errorf("parse contract locking script: %w", err)
	}
	tx := transaction.NewTransaction()
	tx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       txidToChainHash(utxo.Txid),
		SourceTxOutIndex: uint32(utxo.OutputIndex),
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, &transaction.TransactionOutput{
		Satoshis:      uint64(utxo.Satoshis),
		LockingScript: lockScript,
	})

	destScript, err := sdkscript.NewFromHex(destScriptHex)
	if err != nil {
		return nil, fmt.Errorf("parse destination script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(outputSats),
		LockingScript: destScript,
	})

	unlockScript, err := sdkscript.NewFromHex(unlockingScriptHex)
	if err != nil {
		return nil, fmt.Errorf("parse unlocking script: %w", err)
	}
	tx.Inputs[0].UnlockingScript = unlockScript
	return tx, nil
}
