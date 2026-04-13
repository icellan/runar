package runar

import (
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// SDK types for deploying and interacting with compiled Runar contracts on BSV
// ---------------------------------------------------------------------------

// UTXO represents an unspent transaction output.
type UTXO struct {
	Txid        string `json:"txid"`
	OutputIndex int    `json:"outputIndex"`
	Satoshis    int64  `json:"satoshis"`
	Script      string `json:"script"` // hex-encoded locking script
}

// TransactionData represents a parsed Bitcoin transaction (data shape for getTransaction return).
type TransactionData struct {
	Txid     string     `json:"txid"`
	Version  int        `json:"version"`
	Inputs   []TxInput  `json:"inputs"`
	Outputs  []TxOutput `json:"outputs"`
	Locktime int        `json:"locktime"`
	Raw      string     `json:"raw,omitempty"`
}

// TxInput represents a transaction input.
type TxInput struct {
	Txid        string `json:"txid"`
	OutputIndex int    `json:"outputIndex"`
	Script      string `json:"script"`   // hex-encoded scriptSig
	Sequence    uint32 `json:"sequence"`
}

// TxOutput represents a transaction output.
type TxOutput struct {
	Satoshis int64  `json:"satoshis"`
	Script   string `json:"script"` // hex-encoded locking script
}

// DeployOptions specifies options for deploying a contract.
type DeployOptions struct {
	Satoshis      int64  `json:"satoshis"`
	ChangeAddress string `json:"changeAddress,omitempty"`
}

// CallOptions specifies options for calling a contract method.
type CallOptions struct {
	Satoshis      int64                  `json:"satoshis,omitempty"`
	ChangeAddress string                 `json:"changeAddress,omitempty"`
	ChangePubKey  string                 `json:"changePubKey,omitempty"` // Override public key for change output (hex-encoded). Defaults to signer's pubkey.
	NewState      map[string]interface{} `json:"newState,omitempty"`

	// Multiple continuation outputs for multi-output methods (e.g., transfer).
	// Each entry specifies the satoshis and state for one output UTXO.
	// When provided, replaces the single continuation output from NewState.
	Outputs []OutputSpec `json:"outputs,omitempty"`

	// Additional contract UTXOs to include as inputs (e.g., for merge, swap,
	// or any multi-input spending pattern). Each UTXO's unlocking script uses
	// the same method and args as the primary call, with OP_PUSH_TX and Sig
	// auto-computed per input.
	AdditionalContractInputs []*UTXO `json:"additionalContractInputs,omitempty"`

	// Per-input args for additional contract inputs. When provided,
	// AdditionalContractInputArgs[i] overrides args for AdditionalContractInputs[i].
	// Sig params (nil) are still auto-computed per input.
	AdditionalContractInputArgs [][]interface{} `json:"additionalContractInputArgs,omitempty"`

	// Terminal outputs for methods that verify exact output structure via
	// extractOutputHash(). When set, the transaction is built with ONLY
	// the contract UTXO as input (no funding inputs, no change output).
	// The fee comes from the contract balance. The contract is considered
	// fully spent after this call (currentUtxo becomes nil).
	TerminalOutputs []TerminalOutput `json:"terminalOutputs,omitempty"`

	// Additional funding UTXOs to include as P2PKH inputs for terminal
	// method calls. Enables terminal methods to receive additional funds
	// when the contract's own balance is insufficient for outputs + fees.
	FundingUtxos []UTXO `json:"fundingUtxos,omitempty"`

	// Groth16WAWitness is the prover-supplied witness bundle for a Mode 3
	// stateful contract whose method begins with a call to
	// runar.AssertGroth16WitnessAssisted. When set, the SDK splices the
	// witness's stack pushes into the unlocking script ON TOP of the
	// regular ABI argument pushes (i.e., immediately before the method
	// selector), so the verifier preamble in the locking script consumes
	// them before the method body sees its declared parameters.
	//
	// nil for normal Rúnar contract calls. The witness is generated
	// off-chain via bn254witness.GenerateWitness from a real Groth16
	// proof + the same VK that was baked into the contract at compile
	// time via CompileOptions.Groth16WAVKey.
	Groth16WAWitness *bn254witness.Witness `json:"-"`
}

// TerminalOutput specifies an exact output for a terminal method call.
type TerminalOutput struct {
	ScriptHex string `json:"scriptHex"`
	Satoshis  int64  `json:"satoshis"`
}

// OutputSpec specifies a single continuation output for multi-output calls.
type OutputSpec struct {
	Satoshis int64                  `json:"satoshis"`
	State    map[string]interface{} `json:"state"`
}

// PreparedCall holds all data from a prepared (but not yet signed) method call.
// Public fields are for external signer coordination. Internal fields (lowercase)
// are consumed by FinalizeCall().
type PreparedCall struct {
	// Public: callers use these to coordinate external signing
	Sighash     string `json:"sighash"`     // 64-char hex — BIP-143 hash external signers sign
	Preimage    string `json:"preimage"`    // hex — full BIP-143 preimage
	OpPushTxSig string `json:"opPushTxSig"` // hex — OP_PUSH_TX DER sig (empty if not needed)
	TxHex       string `json:"txHex"`       // hex — built TX (for backward compat / JSON serialization)
	SigIndices  []int  `json:"sigIndices"`  // which user-visible arg positions need external Sig values

	// Internal — consumed by FinalizeCall()
	methodName        string
	resolvedArgs      []interface{}
	methodSelectorHex string
	isStateful        bool
	isTerminal        bool
	needsOpPushTx     bool
	methodNeedsChange bool
	changePKHHex      string
	changeAmount      int64
	methodNeedsNewAmount bool
	newAmount         int64
	preimageIndex     int
	contractUtxo      UTXO
	newLockingScript  string
	newSatoshis       int64
	hasMultiOutput    bool
	contractOutputs   []ContractOutput
	codeSepIdx        int // adjusted OP_CODESEPARATOR byte offset, -1 if none

	// Mode 3: pre-encoded witness-assisted Groth16 prover bundle hex,
	// spliced into the unlock script BEFORE the stateful prefix so the
	// witness items end up at the deepest stack positions (with q at
	// the bottom). FinalizeCall must replay the same splice when it
	// rebuilds the primary unlock from this PreparedCall, otherwise
	// the witness ends up missing and the verifier preamble fails.
	groth16WAWitnessHex string
}

// ---------------------------------------------------------------------------
// Artifact types (compiled contract output)
// ---------------------------------------------------------------------------

// Groth16WAMeta records metadata about a witness-assisted Groth16 verifier
// artifact produced by the `runarc groth16-wa` compiler backend. Downstream
// consumers can sanity-check NumPubInputs and VKDigest to confirm which VK
// was baked into the script without having to re-derive anything from the
// raw script bytes.
type Groth16WAMeta struct {
	// NumPubInputs is the number of public inputs the Groth16 circuit
	// was parameterised with. Matches `vk.numPubInputs` from the input
	// VK JSON.
	NumPubInputs int `json:"numPubInputs"`

	// VKDigest is the SHA-256 hex of the RAW bytes of the source VK JSON
	// file (not a canonical form). It is a pure reproducibility marker:
	// if two artifacts share a VKDigest, they were compiled from
	// byte-identical VK files. It is NOT a cryptographic commitment to
	// the VK semantics and should not be used for anything load-bearing.
	VKDigest string `json:"vkDigest"`
}

// RunarArtifact is the compiled output of a Runar compiler.
type RunarArtifact struct {
	Version                string             `json:"version"`
	CompilerVersion        string             `json:"compilerVersion"`
	ContractName           string             `json:"contractName"`
	ABI                    ABI                `json:"abi"`
	Script                 string             `json:"script"`
	ASM                    string             `json:"asm"`
	StateFields            []StateField       `json:"stateFields,omitempty"`
	ConstructorSlots       []ConstructorSlot  `json:"constructorSlots,omitempty"`
	CodeSepIndexSlots      []CodeSepIndexSlot `json:"codeSepIndexSlots,omitempty"`
	BuildTimestamp         string             `json:"buildTimestamp"`
	CodeSeparatorIndex     *int               `json:"codeSeparatorIndex,omitempty"`
	CodeSeparatorIndices   []int              `json:"codeSeparatorIndices,omitempty"`
	ANF                    *ANFProgram        `json:"anf,omitempty"`

	// Groth16WA is populated only for artifacts produced by the
	// `runarc groth16-wa` backend. Nil for normal Rúnar contract
	// compilations.
	Groth16WA *Groth16WAMeta `json:"groth16WA,omitempty"`
}

// ABI describes the contract's public interface.
type ABI struct {
	Constructor ABIConstructor `json:"constructor"`
	Methods     []ABIMethod    `json:"methods"`
}

// ABIConstructor describes the constructor parameters.
type ABIConstructor struct {
	Params []ABIParam `json:"params"`
}

// ABIMethod describes a contract method.
type ABIMethod struct {
	Name       string     `json:"name"`
	Params     []ABIParam `json:"params"`
	IsPublic   bool       `json:"isPublic"`
	IsTerminal *bool      `json:"isTerminal,omitempty"`
}

// ABIParam describes a single parameter.
type ABIParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// StateField describes a state field in a stateful contract.
type StateField struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Index        int         `json:"index"`
	InitialValue interface{} `json:"initialValue,omitempty"`
}

// ConstructorSlot describes where a constructor parameter placeholder
// resides in the compiled script (byte offset of the OP_0 placeholder).
type ConstructorSlot struct {
	ParamIndex int `json:"paramIndex"`
	ByteOffset int `json:"byteOffset"`
}

// CodeSepIndexSlot describes where a codeSeparatorIndex placeholder (OP_0)
// resides in the template script. The SDK substitutes these at deployment
// time with the adjusted codeSeparatorIndex value that accounts for
// constructor arg expansion.
type CodeSepIndexSlot struct {
	ByteOffset   int `json:"byteOffset"`
	CodeSepIndex int `json:"codeSepIndex"`
}
