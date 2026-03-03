package runar

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

// Transaction represents a parsed Bitcoin transaction.
type Transaction struct {
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

// OutputSpec describes one continuation output for multi-output methods.
type OutputSpec struct {
	Satoshis int64                  `json:"satoshis"`
	State    map[string]interface{} `json:"state"`
}

// CallOutput describes a single output in the call transaction.
type CallOutput struct {
	LockingScript string `json:"lockingScript"`
	Satoshis      int64  `json:"satoshis"`
}

// CallOptions specifies options for calling a contract method.
type CallOptions struct {
	Satoshis      int64                  `json:"satoshis,omitempty"`
	ChangeAddress string                 `json:"changeAddress,omitempty"`
	NewState      map[string]interface{} `json:"newState,omitempty"`
	// For multi-output methods: specify multiple continuation outputs.
	Outputs []OutputSpec `json:"outputs,omitempty"`
	// After a multi-output call, which output index to track as the
	// contract's continuation UTXO. Default: last output.
	ContinuationOutputIndex int `json:"continuationOutputIndex,omitempty"`
}

// ---------------------------------------------------------------------------
// Artifact types (compiled contract output)
// ---------------------------------------------------------------------------

// RunarArtifact is the compiled output of a Runar compiler.
type RunarArtifact struct {
	Version          string            `json:"version"`
	CompilerVersion  string            `json:"compilerVersion"`
	ContractName     string            `json:"contractName"`
	ABI              ABI               `json:"abi"`
	Script           string            `json:"script"`
	ASM              string            `json:"asm"`
	StateFields      []StateField      `json:"stateFields,omitempty"`
	ConstructorSlots []ConstructorSlot `json:"constructorSlots,omitempty"`
	BuildTimestamp   string            `json:"buildTimestamp"`
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
	Name     string     `json:"name"`
	Params   []ABIParam `json:"params"`
	IsPublic bool       `json:"isPublic"`
}

// ABIParam describes a single parameter.
type ABIParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// StateField describes a state field in a stateful contract.
type StateField struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Index int    `json:"index"`
}

// ConstructorSlot describes where a constructor parameter placeholder
// resides in the compiled script (byte offset of the OP_0 placeholder).
type ConstructorSlot struct {
	ParamIndex int `json:"paramIndex"`
	ByteOffset int `json:"byteOffset"`
}
