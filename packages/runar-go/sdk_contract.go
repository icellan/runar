package runar

import (
	"fmt"
	"sort"
)

// ---------------------------------------------------------------------------
// RunarContract — main contract runtime wrapper
// ---------------------------------------------------------------------------

// RunarContract is a runtime wrapper for a compiled Runar contract. It handles
// deployment, method invocation, state tracking, and script construction.
type RunarContract struct {
	Artifact        *RunarArtifact
	constructorArgs []interface{}
	state           map[string]interface{}
	codeScript      string // stored code portion from on-chain script (for reconnected contracts)
	currentUtxo     *UTXO
	provider        Provider
	signer          Signer
}

// NewRunarContract creates a new contract instance from a compiled artifact
// and constructor arguments.
func NewRunarContract(artifact *RunarArtifact, constructorArgs []interface{}) *RunarContract {
	expected := len(artifact.ABI.Constructor.Params)
	if len(constructorArgs) != expected {
		panic(fmt.Sprintf(
			"RunarContract: expected %d constructor args for %s, got %d",
			expected, artifact.ContractName, len(constructorArgs),
		))
	}

	c := &RunarContract{
		Artifact:        artifact,
		constructorArgs: constructorArgs,
		state:           make(map[string]interface{}),
	}

	// Initialize state from constructor args for stateful contracts.
	// State fields are matched to constructor args by their declaration
	// index, not by name, since the constructor param name may differ
	// from the state field name (e.g., "initialHash" → "rollingHash").
	if len(artifact.StateFields) > 0 {
		for _, field := range artifact.StateFields {
			if field.Index < len(constructorArgs) {
				c.state[field.Name] = constructorArgs[field.Index]
			}
		}
	}

	return c
}

// Connect stores a provider and signer on this contract so they don't need
// to be passed to every Deploy() and Call() invocation.
func (c *RunarContract) Connect(provider Provider, signer Signer) {
	c.provider = provider
	c.signer = signer
}

// Deploy deploys the contract by creating a UTXO with the locking script.
// If provider or signer is nil, falls back to the ones stored via Connect().
func (c *RunarContract) Deploy(
	provider Provider,
	signer Signer,
	options DeployOptions,
) (string, *Transaction, error) {
	if provider == nil {
		provider = c.provider
	}
	if signer == nil {
		signer = c.signer
	}
	if provider == nil || signer == nil {
		return "", nil, fmt.Errorf("RunarContract.Deploy: no provider/signer available. Call Connect() or pass them explicitly")
	}
	address, err := signer.GetAddress()
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Deploy: getting address: %w", err)
	}

	changeAddress := options.ChangeAddress
	if changeAddress == "" {
		changeAddress = address
	}
	lockingScript := c.GetLockingScript()

	// Fetch fee rate and funding UTXOs
	feeRate, err := provider.GetFeeRate()
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Deploy: getting fee rate: %w", err)
	}
	allUtxos, err := provider.GetUtxos(address)
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Deploy: getting UTXOs: %w", err)
	}
	if len(allUtxos) == 0 {
		return "", nil, fmt.Errorf("RunarContract.Deploy: no UTXOs found for address %s", address)
	}
	utxos := SelectUtxos(allUtxos, options.Satoshis, len(lockingScript)/2, feeRate)

	// Build the deploy transaction
	changeScript := BuildP2PKHScript(changeAddress)
	txHex, inputCount, err := BuildDeployTransaction(
		lockingScript,
		utxos,
		options.Satoshis,
		changeAddress,
		changeScript,
		feeRate,
	)
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Deploy: %w", err)
	}

	// Sign all inputs
	signedTx := txHex
	for i := 0; i < inputCount; i++ {
		utxo := utxos[i]
		sig, err := signer.Sign(signedTx, i, utxo.Script, utxo.Satoshis, nil)
		if err != nil {
			return "", nil, fmt.Errorf("RunarContract.Deploy: signing input %d: %w", i, err)
		}
		pubKey, err := signer.GetPublicKey()
		if err != nil {
			return "", nil, fmt.Errorf("RunarContract.Deploy: getting public key: %w", err)
		}
		// Build P2PKH unlocking script: <sig> <pubkey>
		unlockScript := EncodePushData(sig) + EncodePushData(pubKey)
		signedTx = InsertUnlockingScript(signedTx, i, unlockScript)
	}

	// Broadcast
	txid, err := provider.Broadcast(signedTx)
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Deploy: broadcasting: %w", err)
	}

	// Track the deployed UTXO
	c.currentUtxo = &UTXO{
		Txid:        txid,
		OutputIndex: 0,
		Satoshis:    options.Satoshis,
		Script:      lockingScript,
	}

	tx, err := provider.GetTransaction(txid)
	if err != nil {
		// Fallback: construct a minimal transaction from what we know
		tx = &Transaction{
			Txid:    txid,
			Version: 1,
			Outputs: []TxOutput{{Satoshis: options.Satoshis, Script: lockingScript}},
			Raw:     signedTx,
		}
	}

	return txid, tx, nil
}

// Call invokes a public method on the contract (spends the UTXO).
// For stateful contracts, a new UTXO is created with the updated state.
func (c *RunarContract) Call(
	methodName string,
	args []interface{},
	provider Provider,
	signer Signer,
	options *CallOptions,
) (string, *Transaction, error) {
	if provider == nil {
		provider = c.provider
	}
	if signer == nil {
		signer = c.signer
	}
	if provider == nil || signer == nil {
		return "", nil, fmt.Errorf("RunarContract.Call: no provider/signer available. Call Connect() or pass them explicitly")
	}
	// Validate method exists
	method := c.findMethod(methodName)
	if method == nil {
		return "", nil, fmt.Errorf(
			"RunarContract.call: method '%s' not found in %s",
			methodName, c.Artifact.ContractName,
		)
	}
	if len(method.Params) != len(args) {
		return "", nil, fmt.Errorf(
			"RunarContract.call: method '%s' expects %d args, got %d",
			methodName, len(method.Params), len(args),
		)
	}

	if c.currentUtxo == nil {
		return "", nil, fmt.Errorf(
			"RunarContract.call: contract is not deployed. Call Deploy() or FromTxId() first.",
		)
	}

	address, err := signer.GetAddress()
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Call: getting address: %w", err)
	}

	changeAddress := ""
	if options != nil && options.ChangeAddress != "" {
		changeAddress = options.ChangeAddress
	}
	if changeAddress == "" {
		changeAddress = address
	}

	unlockingScript := c.BuildUnlockingScript(methodName, args)

	// Determine if this is a stateful call
	isStateful := len(c.Artifact.StateFields) > 0

	newLockingScript := ""
	newSatoshis := int64(0)

	if isStateful {
		newSatoshis = c.currentUtxo.Satoshis
		if options != nil && options.Satoshis > 0 {
			newSatoshis = options.Satoshis
		}
		// Apply new state values before building the continuation output
		if options != nil && options.NewState != nil {
			for k, v := range options.NewState {
				c.state[k] = v
			}
		}
		newLockingScript = c.GetLockingScript()
	}

	changeScript := BuildP2PKHScript(changeAddress)

	// Fetch fee rate and additional funding UTXOs if needed
	feeRate, err := provider.GetFeeRate()
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Call: getting fee rate: %w", err)
	}
	additionalUtxos, err := provider.GetUtxos(address)
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Call: getting UTXOs: %w", err)
	}

	txHex, inputCount := BuildCallTransaction(
		*c.currentUtxo,
		unlockingScript,
		newLockingScript,
		newSatoshis,
		changeAddress,
		changeScript,
		additionalUtxos,
		feeRate,
	)

	// Sign additional inputs (input 0 already has the unlocking script)
	signedTx := txHex
	for i := 1; i < inputCount; i++ {
		if i-1 < len(additionalUtxos) {
			utxo := additionalUtxos[i-1]
			sig, err := signer.Sign(signedTx, i, utxo.Script, utxo.Satoshis, nil)
			if err != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: signing input %d: %w", i, err)
			}
			pubKey, err := signer.GetPublicKey()
			if err != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: getting public key: %w", err)
			}
			unlockScript := EncodePushData(sig) + EncodePushData(pubKey)
			signedTx = InsertUnlockingScript(signedTx, i, unlockScript)
		}
	}

	// Broadcast
	txid, err := provider.Broadcast(signedTx)
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Call: broadcasting: %w", err)
	}

	// Update tracked UTXO for stateful contracts
	if isStateful && newLockingScript != "" {
		c.currentUtxo = &UTXO{
			Txid:        txid,
			OutputIndex: 0,
			Satoshis:    newSatoshis,
			Script:      newLockingScript,
		}
	} else {
		c.currentUtxo = nil
	}

	tx, err := provider.GetTransaction(txid)
	if err != nil {
		tx = &Transaction{
			Txid:    txid,
			Version: 1,
			Raw:     signedTx,
		}
	}

	return txid, tx, nil
}

// FromTxId reconnects to an existing deployed contract from its deployment
// transaction.
func FromTxId(
	artifact *RunarArtifact,
	txid string,
	outputIndex int,
	provider Provider,
) (*RunarContract, error) {
	tx, err := provider.GetTransaction(txid)
	if err != nil {
		return nil, fmt.Errorf("RunarContract.FromTxId: %w", err)
	}

	if outputIndex >= len(tx.Outputs) {
		return nil, fmt.Errorf(
			"RunarContract.FromTxId: output index %d out of range (tx has %d outputs)",
			outputIndex, len(tx.Outputs),
		)
	}

	output := tx.Outputs[outputIndex]

	// Create dummy constructor args (we'll store the on-chain code script directly)
	dummyArgs := make([]interface{}, len(artifact.ABI.Constructor.Params))
	for i := range dummyArgs {
		dummyArgs[i] = int64(0)
	}

	contract := NewRunarContract(artifact, dummyArgs)

	// Store the code portion of the on-chain script.
	// Use opcode-aware walking to find the real OP_RETURN (not a 0x6a
	// byte inside push data).
	if len(artifact.StateFields) > 0 {
		// Stateful: code is everything before the last OP_RETURN
		lastOpReturn := FindLastOpReturn(output.Script)
		if lastOpReturn != -1 {
			contract.codeScript = output.Script[:lastOpReturn]
		} else {
			contract.codeScript = output.Script
		}
	} else {
		// Stateless: the full on-chain script IS the code
		contract.codeScript = output.Script
	}

	// Set the current UTXO
	contract.currentUtxo = &UTXO{
		Txid:        txid,
		OutputIndex: outputIndex,
		Satoshis:    output.Satoshis,
		Script:      output.Script,
	}

	// Extract state if this is a stateful contract
	if len(artifact.StateFields) > 0 {
		state := ExtractStateFromScript(artifact, output.Script)
		if state != nil {
			contract.state = state
		}
	}

	return contract, nil
}

// GetLockingScript returns the full locking script hex for the contract.
// For stateful contracts this includes the code followed by OP_RETURN and
// the serialized state fields.
func (c *RunarContract) GetLockingScript() string {
	// Use stored code script from chain if available (reconnected contract)
	script := c.codeScript
	if script == "" {
		script = c.buildCodeScript()
	}

	// Append state section for stateful contracts
	if len(c.Artifact.StateFields) > 0 {
		stateHex := SerializeState(c.Artifact.StateFields, c.state)
		if len(stateHex) > 0 {
			script += "6a" // OP_RETURN
			script += stateHex
		}
	}

	return script
}

// BuildUnlockingScript builds the unlocking script for a method call.
// The unlocking script pushes the method arguments onto the stack in order,
// followed by a method selector (the method index as a Script number) if
// the contract has multiple public methods.
func (c *RunarContract) BuildUnlockingScript(methodName string, args []interface{}) string {
	script := ""

	// Push each argument
	for _, arg := range args {
		script += encodeArg(arg)
	}

	// If there are multiple public methods, push the method selector
	publicMethods := c.getPublicMethods()
	if len(publicMethods) > 1 {
		methodIndex := -1
		for i, m := range publicMethods {
			if m.Name == methodName {
				methodIndex = i
				break
			}
		}
		if methodIndex < 0 {
			panic(fmt.Sprintf(
				"buildUnlockingScript: public method '%s' not found", methodName,
			))
		}
		script += encodeScriptNumber(int64(methodIndex))
	}

	return script
}

// GetState returns a copy of the current contract state.
func (c *RunarContract) GetState() map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range c.state {
		result[k] = v
	}
	return result
}

// SetState updates state values directly (for stateful contracts).
func (c *RunarContract) SetState(newState map[string]interface{}) {
	for k, v := range newState {
		c.state[k] = v
	}
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

func (c *RunarContract) buildCodeScript() string {
	script := c.Artifact.Script

	if len(c.Artifact.ConstructorSlots) > 0 {
		// Sort by byteOffset descending so splicing doesn't shift later offsets
		slots := make([]ConstructorSlot, len(c.Artifact.ConstructorSlots))
		copy(slots, c.Artifact.ConstructorSlots)
		sort.Slice(slots, func(i, j int) bool {
			return slots[i].ByteOffset > slots[j].ByteOffset
		})

		for _, slot := range slots {
			encoded := encodeArg(c.constructorArgs[slot.ParamIndex])
			hexOffset := slot.ByteOffset * 2
			// Replace the 1-byte OP_0 placeholder (2 hex chars) with the encoded arg
			script = script[:hexOffset] + encoded + script[hexOffset+2:]
		}
	} else {
		// Backward compatibility: old artifacts without constructorSlots
		for _, arg := range c.constructorArgs {
			script += encodeArg(arg)
		}
	}

	return script
}

func (c *RunarContract) findMethod(name string) *ABIMethod {
	for i := range c.Artifact.ABI.Methods {
		m := &c.Artifact.ABI.Methods[i]
		if m.Name == name && m.IsPublic {
			return m
		}
	}
	return nil
}

func (c *RunarContract) getPublicMethods() []ABIMethod {
	var result []ABIMethod
	for _, m := range c.Artifact.ABI.Methods {
		if m.IsPublic {
			result = append(result, m)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Argument encoding
// ---------------------------------------------------------------------------

// encodeArg encodes an argument value as a Bitcoin Script push data element.
func encodeArg(value interface{}) string {
	switch v := value.(type) {
	case int64:
		return encodeScriptNumber(v)
	case int:
		return encodeScriptNumber(int64(v))
	case int32:
		return encodeScriptNumber(int64(v))
	case bool:
		if v {
			return "51" // OP_TRUE
		}
		return "00" // OP_FALSE
	case string:
		// Assume hex-encoded data
		return EncodePushData(v)
	default:
		return EncodePushData(fmt.Sprintf("%v", v))
	}
}

// encodeScriptNumber encodes an integer as a Bitcoin Script opcode or push data.
// This is the contract encoding (uses OP_0, OP_1..16, OP_1NEGATE for small values),
// different from the state encoding which always uses push-data.
func encodeScriptNumber(n int64) string {
	if n == 0 {
		return "00" // OP_0
	}
	if n >= 1 && n <= 16 {
		// OP_1 through OP_16
		return fmt.Sprintf("%02x", 0x50+n)
	}
	if n == -1 {
		return "4f" // OP_1NEGATE
	}

	negative := n < 0
	absVal := n
	if negative {
		absVal = -absVal
	}

	var bytes []byte
	uval := uint64(absVal)
	for uval > 0 {
		bytes = append(bytes, byte(uval&0xff))
		uval >>= 8
	}

	if bytes[len(bytes)-1]&0x80 != 0 {
		if negative {
			bytes = append(bytes, 0x80)
		} else {
			bytes = append(bytes, 0x00)
		}
	} else if negative {
		bytes[len(bytes)-1] |= 0x80
	}

	hex := bytesToHex(bytes)
	return EncodePushData(hex)
}

