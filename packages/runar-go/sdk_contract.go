package runar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"golang.org/x/crypto/ripemd160"
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
	// Properties with InitialValue use their default; others are matched
	// to constructor args by their declaration index, since the constructor
	// param name may differ from the state field name (e.g., "initialHash" → "rollingHash").
	if len(artifact.StateFields) > 0 {
		for _, field := range artifact.StateFields {
			if field.InitialValue != nil {
				// Property has a compile-time default value.
				// Revive BigInt strings ("0n") that occur when artifacts
				// are loaded via standard JSON parsing (without a custom reviver).
				c.state[field.Name] = reviveJSONValue(field.InitialValue, field.Type)
			} else if field.Index < len(constructorArgs) {
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
) (string, *TransactionData, error) {
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
	deployTx, inputCount, err := BuildDeployTransaction(
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
	for i := 0; i < inputCount; i++ {
		utxo := utxos[i]
		sig, err := signer.Sign(deployTx.Hex(), i, utxo.Script, utxo.Satoshis, nil)
		if err != nil {
			return "", nil, fmt.Errorf("RunarContract.Deploy: signing input %d: %w", i, err)
		}
		pubKey, err := signer.GetPublicKey()
		if err != nil {
			return "", nil, fmt.Errorf("RunarContract.Deploy: getting public key: %w", err)
		}
		// Build P2PKH unlocking script: <sig> <pubkey>
		unlockScriptHex := EncodePushData(sig) + EncodePushData(pubKey)
		unlockLS, _ := sdkscript.NewFromHex(unlockScriptHex)
		deployTx.Inputs[i].UnlockingScript = unlockLS
	}

	// Broadcast
	txid, err := provider.Broadcast(deployTx)
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
		tx = &TransactionData{
			Txid:    txid,
			Version: 1,
			Outputs: []TxOutput{{Satoshis: options.Satoshis, Script: lockingScript}},
			Raw:     deployTx.Hex(),
		}
	}

	return txid, tx, nil
}

// Call invokes a public method on the contract (spends the UTXO).
// For stateful contracts, a new UTXO is created with the updated state.
// Delegates to PrepareCall() + sign + FinalizeCall().
func (c *RunarContract) Call(
	methodName string,
	args []interface{},
	provider Provider,
	signer Signer,
	options *CallOptions,
) (string, *TransactionData, error) {
	if provider == nil {
		provider = c.provider
	}
	if signer == nil {
		signer = c.signer
	}
	if provider == nil || signer == nil {
		return "", nil, fmt.Errorf("RunarContract.Call: no provider/signer available. Call Connect() or pass them explicitly")
	}

	prepared, err := c.PrepareCall(methodName, args, provider, signer, options)
	if err != nil {
		return "", nil, err
	}

	signatures := make(map[int]string)
	for _, idx := range prepared.SigIndices {
		// In stateful contracts, user checkSig executes AFTER OP_CODESEPARATOR
		// (checkPreimage is auto-injected at method entry), so use trimmed script.
		// In stateless contracts, user checkSig executes BEFORE OP_CODESEPARATOR,
		// so use the full locking script.
		subscript := prepared.contractUtxo.Script
		if prepared.isStateful && prepared.codeSepIdx >= 0 {
			subscript = subscript[(prepared.codeSepIdx+1)*2:]
		}
		sig, sigErr := signer.Sign(prepared.TxHex, 0, subscript, prepared.contractUtxo.Satoshis, nil)
		if sigErr != nil {
			return "", nil, fmt.Errorf("RunarContract.Call: signing Sig param %d: %w", idx, sigErr)
		}
		signatures[idx] = sig
	}

	return c.FinalizeCall(prepared, signatures, provider)
}

// PrepareCall builds the transaction for a method call without signing the
// primary contract input's Sig params. Returns a PreparedCall containing the
// BIP-143 sighash that external signers need, plus opaque internals for
// FinalizeCall().
//
// P2PKH funding inputs and additional contract inputs ARE signed with the
// provided signer. Only the primary contract input's Sig params are left
// as 72-byte placeholders.
func (c *RunarContract) PrepareCall(
	methodName string,
	args []interface{},
	provider Provider,
	signer Signer,
	options *CallOptions,
) (*PreparedCall, error) {
	if provider == nil {
		provider = c.provider
	}
	if signer == nil {
		signer = c.signer
	}
	if provider == nil || signer == nil {
		return nil, fmt.Errorf("RunarContract.PrepareCall: no provider/signer available. Call Connect() or pass them explicitly")
	}

	// Validate method exists
	method := c.findMethod(methodName)
	if method == nil {
		return nil, fmt.Errorf(
			"RunarContract.PrepareCall: method '%s' not found in %s",
			methodName, c.Artifact.ContractName,
		)
	}

	isStateful := len(c.Artifact.StateFields) > 0
	methodNeedsChange := false
	methodNeedsNewAmount := false
	for _, p := range method.Params {
		if p.Name == "_changePKH" {
			methodNeedsChange = true
		}
		if p.Name == "_newAmount" {
			methodNeedsNewAmount = true
		}
	}
	var userParams []ABIParam
	if isStateful {
		for _, p := range method.Params {
			if p.Type != "SigHashPreimage" && p.Name != "_changePKH" && p.Name != "_changeAmount" && p.Name != "_newAmount" {
				userParams = append(userParams, p)
			}
		}
	} else {
		userParams = method.Params
	}
	if len(userParams) != len(args) {
		return nil, fmt.Errorf(
			"RunarContract.PrepareCall: method '%s' expects %d args, got %d",
			methodName, len(userParams), len(args),
		)
	}

	if c.currentUtxo == nil {
		return nil, fmt.Errorf(
			"RunarContract.PrepareCall: contract is not deployed. Call Deploy() or FromTxId() first.",
		)
	}

	contractUtxo := *c.currentUtxo

	address, err := signer.GetAddress()
	if err != nil {
		return nil, fmt.Errorf("RunarContract.PrepareCall: getting address: %w", err)
	}

	changeAddress := ""
	if options != nil && options.ChangeAddress != "" {
		changeAddress = options.ChangeAddress
	}
	if changeAddress == "" {
		changeAddress = address
	}

	// Detect auto-compute params (user passed nil)
	resolvedArgs := make([]interface{}, len(args))
	copy(resolvedArgs, args)
	var sigIndices []int
	var prevoutsIndices []int
	preimageIndex := -1
	for i, param := range userParams {
		if param.Type == "Sig" && args[i] == nil {
			sigIndices = append(sigIndices, i)
			resolvedArgs[i] = strings.Repeat("00", 72)
		}
		if param.Type == "PubKey" && args[i] == nil {
			pubKey, pkErr := signer.GetPublicKey()
			if pkErr != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall: getting public key for PubKey param: %w", pkErr)
			}
			resolvedArgs[i] = pubKey
		}
		if param.Type == "SigHashPreimage" && args[i] == nil {
			preimageIndex = i
			resolvedArgs[i] = strings.Repeat("00", 181)
		}
		if param.Type == "ByteString" && args[i] == nil {
			prevoutsIndices = append(prevoutsIndices, i)
			nExtra := 0
			if options != nil {
				nExtra = len(options.AdditionalContractInputs)
			}
			estimatedInputs := 1 + nExtra + 1
			resolvedArgs[i] = strings.Repeat("00", 36*estimatedInputs)
		}
	}

	needsOpPushTx := preimageIndex >= 0 || isStateful

	// Compute method selector (needed for both terminal and non-terminal)
	methodSelectorHex := ""
	methodIndex := 0
	if isStateful {
		publicMethods := c.getPublicMethods()
		if len(publicMethods) > 1 {
			for i, m := range publicMethods {
				if m.Name == methodName {
					methodIndex = i
					methodSelectorHex = encodeScriptNumber(int64(i))
					break
				}
			}
		}
	}

	// Compute change PKH for stateful methods that need it
	changePKHHex := ""
	if isStateful && methodNeedsChange {
		changePubKeyHex := ""
		if options != nil && options.ChangePubKey != "" {
			changePubKeyHex = options.ChangePubKey
		} else {
			pk, pkErr := signer.GetPublicKey()
			if pkErr != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall: getting public key for change PKH: %w", pkErr)
			}
			changePubKeyHex = pk
		}
		pubKeyBytes, decErr := hex.DecodeString(changePubKeyHex)
		if decErr != nil {
			return nil, fmt.Errorf("RunarContract.PrepareCall: decoding change pubkey hex: %w", decErr)
		}
		h := sha256.Sum256(pubKeyBytes)
		r := ripemd160.New()
		r.Write(h[:])
		changePKHHex = hex.EncodeToString(r.Sum(nil))
	}

	// -------------------------------------------------------------------
	// Terminal method path
	// -------------------------------------------------------------------
	if options != nil && len(options.TerminalOutputs) > 0 {
		return c.prepareCallTerminal(
			methodName, resolvedArgs, signer, options,
			isStateful, needsOpPushTx, methodNeedsChange,
			sigIndices, prevoutsIndices, preimageIndex,
			methodSelectorHex, changePKHHex, contractUtxo,
		)
	}

	// -------------------------------------------------------------------
	// Non-terminal path
	// -------------------------------------------------------------------

	// Collect additional contract inputs (e.g., for merge)
	var extraContractUtxos []*UTXO
	if options != nil {
		extraContractUtxos = options.AdditionalContractInputs
	}

	// Build contract outputs
	var contractOutputs []ContractOutput
	hasMultiOutput := options != nil && len(options.Outputs) > 0

	newLockingScript := ""
	newSatoshis := int64(0)

	if isStateful && hasMultiOutput {
		codeScript := c.codeScript
		if codeScript == "" {
			codeScript = c.buildCodeScript()
		}
		for _, out := range options.Outputs {
			stateHex := SerializeState(c.Artifact.StateFields, out.State)
			contractOutputs = append(contractOutputs, ContractOutput{
				Script:   codeScript + "6a" + stateHex,
				Satoshis: out.Satoshis,
			})
		}
	} else if isStateful {
		newSatoshis = c.currentUtxo.Satoshis
		if options != nil && options.Satoshis > 0 {
			newSatoshis = options.Satoshis
		}
		if options != nil && options.NewState != nil {
			// Explicit newState takes priority (backward compat)
			for k, v := range options.NewState {
				c.state[k] = v
			}
		} else if methodNeedsChange && c.Artifact.ANF != nil {
			// Auto-compute new state from ANF IR
			namedArgs := buildNamedArgs(userParams, resolvedArgs)
			computed, err := ComputeNewState(c.Artifact.ANF, methodName, c.state, namedArgs)
			if err == nil {
				for k, v := range computed {
					c.state[k] = v
				}
			}
		}
		newLockingScript = c.GetLockingScript()
	}

	// Fetch fee rate and funding UTXOs
	feeRate, feeErr := provider.GetFeeRate()
	if feeErr != nil {
		return nil, fmt.Errorf("RunarContract.PrepareCall: getting fee rate: %w", feeErr)
	}
	changeScript := BuildP2PKHScript(changeAddress)
	allFundingUtxos, err := provider.GetUtxos(address)
	if err != nil {
		return nil, fmt.Errorf("RunarContract.PrepareCall: getting UTXOs: %w", err)
	}
	var additionalUtxos []UTXO
	for _, u := range allFundingUtxos {
		if !(u.Txid == c.currentUtxo.Txid && u.OutputIndex == c.currentUtxo.OutputIndex) {
			additionalUtxos = append(additionalUtxos, u)
		}
	}

	// Initial unlocking script (with placeholders)
	var unlockingScript string
	if needsOpPushTx || isStateful {
		unlockingScript = c.buildStatefulPrefix(strings.Repeat("00", 72), methodNeedsChange) +
			c.BuildUnlockingScript(methodName, resolvedArgs)
	} else {
		unlockingScript = c.BuildUnlockingScript(methodName, resolvedArgs)
	}

	// Resolve per-input args for additional contract inputs
	extraResolvedArgs := make([][]interface{}, len(extraContractUtxos))
	for i := range extraContractUtxos {
		if options != nil && i < len(options.AdditionalContractInputArgs) && options.AdditionalContractInputArgs[i] != nil {
			perInputArgs := options.AdditionalContractInputArgs[i]
			resolved := make([]interface{}, len(perInputArgs))
			copy(resolved, perInputArgs)
			for j, param := range userParams {
				if j >= len(resolved) {
					break
				}
				if param.Type == "Sig" && resolved[j] == nil {
					resolved[j] = strings.Repeat("00", 72)
				}
				if param.Type == "PubKey" && resolved[j] == nil {
					pubKey, pkErr := signer.GetPublicKey()
					if pkErr != nil {
						return nil, fmt.Errorf("RunarContract.PrepareCall: getting public key for PubKey param (extra input %d): %w", i, pkErr)
					}
					resolved[j] = pubKey
				}
				if param.Type == "SigHashPreimage" && resolved[j] == nil {
					resolved[j] = strings.Repeat("00", 181)
				}
				if param.Type == "ByteString" && resolved[j] == nil {
					nExtra := len(options.AdditionalContractInputs)
					estimatedInputs := 1 + nExtra + 1
					resolved[j] = strings.Repeat("00", 36*estimatedInputs)
				}
			}
			extraResolvedArgs[i] = resolved
		} else {
			extraResolvedArgs[i] = resolvedArgs
		}
	}

	// Build placeholder unlocking scripts for additional contract inputs
	extraUnlockPlaceholders := make([]string, len(extraContractUtxos))
	for i := range extraContractUtxos {
		extraUnlockPlaceholders[i] = c.buildStatefulPrefix(strings.Repeat("00", 72), methodNeedsChange) +
			c.BuildUnlockingScript(methodName, extraResolvedArgs[i])
	}

	// Build the BuildCallOptions
	buildOpts := &BuildCallOptions{}
	if len(contractOutputs) > 0 {
		buildOpts.ContractOutputs = contractOutputs
	}
	if len(extraContractUtxos) > 0 {
		buildOpts.AdditionalContractInputs = make([]AdditionalContractInput, len(extraContractUtxos))
		for i, utxo := range extraContractUtxos {
			buildOpts.AdditionalContractInputs[i] = AdditionalContractInput{
				Utxo:            *utxo,
				UnlockingScript: extraUnlockPlaceholders[i],
			}
		}
	}

	callTx, inputCount, changeAmount := BuildCallTransaction(
		contractUtxo,
		unlockingScript,
		newLockingScript,
		newSatoshis,
		changeAddress,
		changeScript,
		additionalUtxos,
		feeRate,
		buildOpts,
	)

	// Sign P2PKH funding inputs (after contract inputs)
	signedTx := callTx.Hex()
	p2pkhStartIdx := 1 + len(extraContractUtxos)
	for i := p2pkhStartIdx; i < inputCount; i++ {
		utxoIdx := i - p2pkhStartIdx
		if utxoIdx < len(additionalUtxos) {
			utxo := additionalUtxos[utxoIdx]
			sig, signErr := signer.Sign(signedTx, i, utxo.Script, utxo.Satoshis, nil)
			if signErr != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall: signing input %d: %w", i, signErr)
			}
			pubKey, pkErr := signer.GetPublicKey()
			if pkErr != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall: getting public key: %w", pkErr)
			}
			unlockScript := EncodePushData(sig) + EncodePushData(pubKey)
			signedTx = InsertUnlockingScript(signedTx, i, unlockScript)
		}
	}

	finalOpPushTxSig := ""
	finalPreimage := ""
	codeSepIdx := c.getCodeSepIndex(methodIndex)

	if isStateful {
		// Helper: build a stateful unlock. For inputIdx==0 (primary), keeps
		// placeholder Sig params. For inputIdx>0 (extra), signs with signer.
		buildStatefulUnlock := func(tx string, inputIdx int, subscript string, sats int64, baseArgs []interface{}, txChangeAmount int64) (unlock string, opSigHex string, preimageHex string, retErr error) {
			opSig, preimage, ptxErr := ComputeOpPushTxWithCodeSep(tx, inputIdx, subscript, sats, codeSepIdx)
			if ptxErr != nil {
				return "", "", "", fmt.Errorf("OP_PUSH_TX for input %d: %w", inputIdx, ptxErr)
			}
			inputArgs := make([]interface{}, len(baseArgs))
			copy(inputArgs, baseArgs)
			// Only sign Sig params for extra inputs, not the primary
			if inputIdx > 0 {
				// In stateful contracts, user checkSig is AFTER OP_CODESEPARATOR — trim.
				sigSubscript := subscript
				if codeSepIdx >= 0 {
					sigSubscript = subscript[(codeSepIdx+1)*2:]
				}
				for _, idx := range sigIndices {
					realSig, sigErr := signer.Sign(tx, inputIdx, sigSubscript, sats, nil)
					if sigErr != nil {
						return "", "", "", fmt.Errorf("auto-signing Sig param %d for input %d: %w", idx, inputIdx, sigErr)
					}
					inputArgs[idx] = realSig
				}
			}
			if len(prevoutsIndices) > 0 {
				allPrevoutsHex := extractAllPrevouts(tx)
				for _, idx := range prevoutsIndices {
					inputArgs[idx] = allPrevoutsHex
				}
			}
			argsHex := ""
			for _, arg := range inputArgs {
				argsHex += encodeArg(arg)
			}
			changeHex := ""
			if methodNeedsChange && changePKHHex != "" {
				changeHex = EncodePushData(changePKHHex) + encodeArg(txChangeAmount)
			}
			newAmountHex := ""
			if methodNeedsNewAmount {
				newAmountHex = encodeArg(newSatoshis)
			}
			opSigHexStr := hex.EncodeToString(opSig)
			preimageHexStr := hex.EncodeToString(preimage)
			unlockStr := c.buildStatefulPrefix(opSigHexStr, methodNeedsChange) +
				argsHex +
				changeHex +
				newAmountHex +
				EncodePushData(preimageHexStr) +
				methodSelectorHex
			return unlockStr, opSigHexStr, preimageHexStr, nil
		}

		// First pass: build unlocking scripts with current tx layout
		input0Unlock, _, _, err := buildStatefulUnlock(signedTx, 0, contractUtxo.Script, contractUtxo.Satoshis, resolvedArgs, changeAmount)
		if err != nil {
			return nil, fmt.Errorf("RunarContract.PrepareCall: %w", err)
		}
		extraUnlocks := make([]string, len(extraContractUtxos))
		for i, mu := range extraContractUtxos {
			extraUnlocks[i], _, _, err = buildStatefulUnlock(signedTx, i+1, mu.Script, mu.Satoshis, extraResolvedArgs[i], changeAmount)
			if err != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall: %w", err)
			}
		}

		// Rebuild TX with real unlocking scripts (sizes may differ from placeholders)
		rebuildOpts := &BuildCallOptions{}
		if len(contractOutputs) > 0 {
			rebuildOpts.ContractOutputs = contractOutputs
		}
		if len(extraContractUtxos) > 0 {
			rebuildOpts.AdditionalContractInputs = make([]AdditionalContractInput, len(extraContractUtxos))
			for i, utxo := range extraContractUtxos {
				rebuildOpts.AdditionalContractInputs[i] = AdditionalContractInput{
					Utxo:            *utxo,
					UnlockingScript: extraUnlocks[i],
				}
			}
		}
		rebuildTx, rebuildCount, rebuildChange := BuildCallTransaction(
			contractUtxo,
			input0Unlock,
			newLockingScript,
			newSatoshis,
			changeAddress,
			changeScript,
			additionalUtxos,
			feeRate,
			rebuildOpts,
		)
		inputCount = rebuildCount
		changeAmount = rebuildChange
		signedTx = rebuildTx.Hex()

		// Second pass: recompute with final tx (preimage changes with unlock size)
		finalInput0Unlock, opSig, preim, err := buildStatefulUnlock(signedTx, 0, contractUtxo.Script, contractUtxo.Satoshis, resolvedArgs, changeAmount)
		if err != nil {
			return nil, fmt.Errorf("RunarContract.PrepareCall: %w", err)
		}
		finalOpPushTxSig = opSig
		finalPreimage = preim
		signedTx = InsertUnlockingScript(signedTx, 0, finalInput0Unlock)

		for i, mu := range extraContractUtxos {
			finalMergeUnlock, _, _, mergeErr := buildStatefulUnlock(signedTx, i+1, mu.Script, mu.Satoshis, extraResolvedArgs[i], changeAmount)
			if mergeErr != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall: %w", mergeErr)
			}
			signedTx = InsertUnlockingScript(signedTx, i+1, finalMergeUnlock)
		}

		// Re-sign P2PKH funding inputs (outputs changed after rebuild)
		for i := p2pkhStartIdx; i < inputCount; i++ {
			utxoIdx := i - p2pkhStartIdx
			if utxoIdx < len(additionalUtxos) {
				utxo := additionalUtxos[utxoIdx]
				sig, signErr := signer.Sign(signedTx, i, utxo.Script, utxo.Satoshis, nil)
				if signErr != nil {
					return nil, fmt.Errorf("RunarContract.PrepareCall: re-signing input %d: %w", i, signErr)
				}
				pubKey, pkErr := signer.GetPublicKey()
				if pkErr != nil {
					return nil, fmt.Errorf("RunarContract.PrepareCall: getting public key: %w", pkErr)
				}
				unlockScript := EncodePushData(sig) + EncodePushData(pubKey)
				signedTx = InsertUnlockingScript(signedTx, i, unlockScript)
			}
		}

		// Update resolvedArgs with real prevouts so FinalizeCall can
		// rebuild the primary unlock with correct allPrevouts values.
		if len(prevoutsIndices) > 0 {
			allPrevoutsHex := extractAllPrevouts(signedTx)
			for _, idx := range prevoutsIndices {
				resolvedArgs[idx] = allPrevoutsHex
			}
		}
	} else if needsOpPushTx || len(sigIndices) > 0 {
		// Stateless: keep placeholder sigs, compute OP_PUSH_TX
		if needsOpPushTx {
			opPushTxSig, preimage, ptxErr := ComputeOpPushTxWithCodeSep(signedTx, 0,
				contractUtxo.Script, contractUtxo.Satoshis, codeSepIdx)
			if ptxErr != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall: OP_PUSH_TX: %w", ptxErr)
			}
			finalOpPushTxSig = hex.EncodeToString(opPushTxSig)
			resolvedArgs[preimageIndex] = hex.EncodeToString(preimage)
		}
		// Don't sign Sig params — keep placeholders
		realUnlockingScript := c.BuildUnlockingScript(methodName, resolvedArgs)
		if needsOpPushTx && finalOpPushTxSig != "" {
			realUnlockingScript = c.buildStatefulPrefix(finalOpPushTxSig, false) + realUnlockingScript
			tmpTx := InsertUnlockingScript(signedTx, 0, realUnlockingScript)
			finalSig, finalPre, ptxErr := ComputeOpPushTxWithCodeSep(tmpTx, 0,
				contractUtxo.Script, contractUtxo.Satoshis, codeSepIdx)
			if ptxErr != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall: OP_PUSH_TX for rebuild: %w", ptxErr)
			}
			resolvedArgs[preimageIndex] = hex.EncodeToString(finalPre)
			finalOpPushTxSig = hex.EncodeToString(finalSig)
			finalPreimage = hex.EncodeToString(finalPre)
			realUnlockingScript = c.buildStatefulPrefix(finalOpPushTxSig, false) +
				c.BuildUnlockingScript(methodName, resolvedArgs)
		}
		signedTx = InsertUnlockingScript(signedTx, 0, realUnlockingScript)
		if finalPreimage == "" && needsOpPushTx {
			if s, ok := resolvedArgs[preimageIndex].(string); ok {
				finalPreimage = s
			}
		}
	}

	// Compute sighash from preimage
	sighash := ""
	if finalPreimage != "" {
		preimageBytes, decErr := hex.DecodeString(finalPreimage)
		if decErr == nil {
			h := sha256.Sum256(preimageBytes)
			sighash = hex.EncodeToString(h[:])
		}
	}

	return &PreparedCall{
		Sighash:           sighash,
		Preimage:          finalPreimage,
		OpPushTxSig:       finalOpPushTxSig,
		TxHex:             signedTx,
		SigIndices:        sigIndices,
		methodName:        methodName,
		resolvedArgs:      resolvedArgs,
		methodSelectorHex: methodSelectorHex,
		isStateful:        isStateful,
		isTerminal:        false,
		needsOpPushTx:     needsOpPushTx,
		methodNeedsChange: methodNeedsChange,
		changePKHHex:      changePKHHex,
		changeAmount:      changeAmount,
		methodNeedsNewAmount: methodNeedsNewAmount,
		newAmount:         newSatoshis,
		preimageIndex:     preimageIndex,
		contractUtxo:      contractUtxo,
		newLockingScript:  newLockingScript,
		newSatoshis:       newSatoshis,
		hasMultiOutput:    hasMultiOutput,
		contractOutputs:   contractOutputs,
		codeSepIdx:        codeSepIdx,
	}, nil
}

// FinalizeCall completes a prepared call by injecting external signatures and
// broadcasting. The signatures map keys must be from prepared.SigIndices.
func (c *RunarContract) FinalizeCall(
	prepared *PreparedCall,
	signatures map[int]string,
	provider Provider,
) (string, *TransactionData, error) {
	if provider == nil {
		provider = c.provider
	}
	if provider == nil {
		return "", nil, fmt.Errorf("RunarContract.FinalizeCall: no provider available")
	}

	// Replace placeholder sigs with real signatures
	resolvedArgs := make([]interface{}, len(prepared.resolvedArgs))
	copy(resolvedArgs, prepared.resolvedArgs)
	for _, idx := range prepared.SigIndices {
		if sig, ok := signatures[idx]; ok {
			resolvedArgs[idx] = sig
		}
	}

	// Assemble the primary unlocking script
	var primaryUnlock string
	if prepared.isStateful {
		argsHex := ""
		for _, arg := range resolvedArgs {
			argsHex += encodeArg(arg)
		}
		changeHex := ""
		if prepared.methodNeedsChange && prepared.changePKHHex != "" {
			changeHex = EncodePushData(prepared.changePKHHex) + encodeArg(prepared.changeAmount)
		}
		newAmountHex := ""
		if prepared.methodNeedsNewAmount {
			newAmountHex = encodeArg(prepared.newAmount)
		}
		primaryUnlock = c.buildStatefulPrefix(prepared.OpPushTxSig, prepared.methodNeedsChange) +
			argsHex +
			changeHex +
			newAmountHex +
			EncodePushData(prepared.Preimage) +
			prepared.methodSelectorHex
	} else if prepared.needsOpPushTx {
		if prepared.preimageIndex >= 0 {
			resolvedArgs[prepared.preimageIndex] = prepared.Preimage
		}
		primaryUnlock = c.buildStatefulPrefix(prepared.OpPushTxSig, false) +
			c.BuildUnlockingScript(prepared.methodName, resolvedArgs)
	} else {
		primaryUnlock = c.BuildUnlockingScript(prepared.methodName, resolvedArgs)
	}

	finalTxHex := InsertUnlockingScript(prepared.TxHex, 0, primaryUnlock)

	// Parse final hex to Transaction for broadcast
	finalTx, parseErr := transaction.NewTransactionFromHex(finalTxHex)
	if parseErr != nil {
		return "", nil, fmt.Errorf("RunarContract.FinalizeCall: parsing tx: %w", parseErr)
	}

	// Broadcast
	txid, err := provider.Broadcast(finalTx)
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.FinalizeCall: broadcasting: %w", err)
	}

	// Update tracked UTXO
	if prepared.isStateful && prepared.hasMultiOutput && len(prepared.contractOutputs) > 0 {
		c.currentUtxo = &UTXO{
			Txid:        txid,
			OutputIndex: 0,
			Satoshis:    prepared.contractOutputs[0].Satoshis,
			Script:      prepared.contractOutputs[0].Script,
		}
	} else if prepared.isStateful && prepared.newLockingScript != "" {
		c.currentUtxo = &UTXO{
			Txid:        txid,
			OutputIndex: 0,
			Satoshis:    prepared.newSatoshis,
			Script:      prepared.newLockingScript,
		}
	} else if prepared.isTerminal {
		c.currentUtxo = nil
	} else {
		c.currentUtxo = nil
	}

	tx, err := provider.GetTransaction(txid)
	if err != nil {
		tx = &TransactionData{
			Txid:    txid,
			Version: 1,
			Raw:     finalTxHex,
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

// GetCurrentUtxo returns the current tracked UTXO, or nil if the contract
// has not been deployed or has been spent (stateless).
func (c *RunarContract) GetCurrentUtxo() *UTXO {
	if c.currentUtxo == nil {
		return nil
	}
	copy := *c.currentUtxo
	return &copy
}

// SetState updates state values directly (for stateful contracts).
func (c *RunarContract) SetState(newState map[string]interface{}) {
	for k, v := range newState {
		c.state[k] = v
	}
}

// SetCurrentUtxo updates the contract's tracked UTXO (e.g., after a raw spend).
func (c *RunarContract) SetCurrentUtxo(utxo *UTXO) {
	c.currentUtxo = utxo
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
	} else if len(c.Artifact.StateFields) == 0 {
		// Backward compatibility: old stateless artifacts without constructorSlots.
		// For stateful contracts, constructor args initialize the state section
		// (after OP_RETURN), not the code portion.
		for _, arg := range c.constructorArgs {
			script += encodeArg(arg)
		}
	}

	return script
}

// getCodePartHex returns the code portion of the locking script (without state).
func (c *RunarContract) getCodePartHex() string {
	if c.codeScript != "" {
		return c.codeScript
	}
	return c.buildCodeScript()
}

// adjustCodeSepOffset adjusts a code separator byte offset from the base
// (template) script to the constructor-arg-substituted script.
func (c *RunarContract) adjustCodeSepOffset(baseOffset int) int {
	if len(c.Artifact.ConstructorSlots) == 0 {
		return baseOffset
	}
	shift := 0
	for _, slot := range c.Artifact.ConstructorSlots {
		if slot.ByteOffset < baseOffset {
			encoded := encodeArg(c.constructorArgs[slot.ParamIndex])
			shift += len(encoded)/2 - 1 // encoded bytes minus the 1-byte OP_0 placeholder
		}
	}
	return baseOffset + shift
}

// getCodeSepIndex returns the adjusted code separator byte offset for a
// given method index, or -1 if no OP_CODESEPARATOR is present.
func (c *RunarContract) getCodeSepIndex(methodIndex int) int {
	if c.Artifact.CodeSeparatorIndices != nil && methodIndex >= 0 && methodIndex < len(c.Artifact.CodeSeparatorIndices) {
		return c.adjustCodeSepOffset(c.Artifact.CodeSeparatorIndices[methodIndex])
	}
	if c.Artifact.CodeSeparatorIndex != nil {
		return c.adjustCodeSepOffset(*c.Artifact.CodeSeparatorIndex)
	}
	return -1
}

// hasCodeSeparator returns true if the artifact has OP_CODESEPARATOR support.
func (c *RunarContract) hasCodeSeparator() bool {
	return c.Artifact.CodeSeparatorIndex != nil || len(c.Artifact.CodeSeparatorIndices) > 0
}

// buildStatefulPrefix builds the prefix for an unlocking script:
// optionally _codePart + _opPushTxSig. These implicit params are pushed before all method args.
// needsCodePart should be true only when the method constructs continuation outputs
// (non-terminal stateful calls). Terminal and stateless methods don't use _codePart.
func (c *RunarContract) buildStatefulPrefix(opSigHex string, needsCodePart bool) string {
	prefix := ""
	if needsCodePart && c.hasCodeSeparator() {
		prefix += EncodePushData(c.getCodePartHex())
	}
	prefix += EncodePushData(opSigHex)
	return prefix
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

// findMethodIndex returns the public method index for a method name, or 0 if not found.
func (c *RunarContract) findMethodIndex(name string) int {
	for i, m := range c.getPublicMethods() {
		if m.Name == name {
			return i
		}
	}
	return 0
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

// reviveJSONValue converts a value that may have been serialized as a BigInt
// string with "n" suffix (e.g. "0n", "1000n", "-42n") back into a *big.Int
// when the field type is "bigint" or "int". This handles the case where
// artifacts are loaded via standard JSON parsing without a custom reviver.
func reviveJSONValue(value interface{}, fieldType string) interface{} {
	if fieldType == "bigint" || fieldType == "int" {
		switch v := value.(type) {
		case string:
			s := v
			if strings.HasSuffix(s, "n") {
				s = strings.TrimSuffix(s, "n")
			}
			n := new(big.Int)
			n.SetString(s, 10)
			return n.Int64()
		case float64:
			return int64(v)
		case int64:
			return v
		}
	}
	return value
}

// ---------------------------------------------------------------------------
// prepareCallTerminal handles the terminal method code path for PrepareCall.
// Terminal methods build a transaction with only the contract UTXO as input
// and the exact terminal outputs specified. No funding inputs, no change output.
func (c *RunarContract) prepareCallTerminal(
	methodName string,
	resolvedArgs []interface{},
	signer Signer,
	options *CallOptions,
	isStateful bool,
	needsOpPushTx bool,
	methodNeedsChange bool,
	sigIndices []int,
	prevoutsIndices []int,
	preimageIndex int,
	methodSelectorHex string,
	changePKHHex string,
	contractUtxo UTXO,
) (*PreparedCall, error) {
	termOutputs := options.TerminalOutputs

	// Build placeholder unlocking script
	var termUnlockScript string
	if needsOpPushTx {
		termUnlockScript = c.buildStatefulPrefix(strings.Repeat("00", 72), false) +
			c.BuildUnlockingScript(methodName, resolvedArgs)
	} else {
		termUnlockScript = c.BuildUnlockingScript(methodName, resolvedArgs)
	}

	// Build terminal transaction using go-sdk Transaction
	buildTerminalTx := func(unlock string) *transaction.Transaction {
		ttx := transaction.NewTransaction()
		unlockLS, _ := sdkscript.NewFromHex(unlock)
		ttx.AddInput(&transaction.TransactionInput{
			SourceTXID:       txidToChainHash(contractUtxo.Txid),
			SourceTxOutIndex: uint32(contractUtxo.OutputIndex),
			UnlockingScript:  unlockLS,
			SequenceNumber:   0xffffffff,
		})
		for _, out := range termOutputs {
			outLS, _ := sdkscript.NewFromHex(out.ScriptHex)
			ttx.AddOutput(&transaction.TransactionOutput{
				Satoshis:      uint64(out.Satoshis),
				LockingScript: outLS,
			})
		}
		return ttx
	}

	termTxObj := buildTerminalTx(termUnlockScript)
	termTx := termTxObj.Hex()
	finalOpPushTxSig := ""
	finalPreimage := ""

	termCodeSepIdx := c.getCodeSepIndex(c.findMethodIndex(methodName))
	if isStateful {
		// Build stateful terminal unlock with PLACEHOLDER user sigs
		buildUnlock := func(tx string) (unlock string, opSigHex string, preimageHex string, retErr error) {
			opSig, preimage, ptxErr := ComputeOpPushTxWithCodeSep(tx, 0, contractUtxo.Script, contractUtxo.Satoshis, termCodeSepIdx)
			if ptxErr != nil {
				return "", "", "", fmt.Errorf("OP_PUSH_TX for terminal: %w", ptxErr)
			}
			argsHex := ""
			for _, arg := range resolvedArgs {
				argsHex += encodeArg(arg)
			}
			changeHex := ""
			if methodNeedsChange && changePKHHex != "" {
				changeHex = EncodePushData(changePKHHex) + encodeArg(int64(0))
			}
			opSigHexStr := hex.EncodeToString(opSig)
			preimageHexStr := hex.EncodeToString(preimage)
			unlockStr := c.buildStatefulPrefix(opSigHexStr, false) +
				argsHex +
				changeHex +
				EncodePushData(preimageHexStr) +
				methodSelectorHex
			return unlockStr, opSigHexStr, preimageHexStr, nil
		}

		// First pass
		firstUnlock, _, _, err := buildUnlock(termTx)
		if err != nil {
			return nil, fmt.Errorf("RunarContract.PrepareCall terminal: %w", err)
		}
		termTx = buildTerminalTx(firstUnlock).Hex()

		// Second pass
		secondUnlock, opSig, preim, err := buildUnlock(termTx)
		if err != nil {
			return nil, fmt.Errorf("RunarContract.PrepareCall terminal: %w", err)
		}
		termTx = InsertUnlockingScript(termTx, 0, secondUnlock)
		finalOpPushTxSig = opSig
		finalPreimage = preim
	} else if needsOpPushTx || len(sigIndices) > 0 {
		// Stateless terminal — keep placeholder sigs
		if needsOpPushTx {
			opPushTxSig, preimage, ptxErr := ComputeOpPushTxWithCodeSep(termTx, 0,
				contractUtxo.Script, contractUtxo.Satoshis, termCodeSepIdx)
			if ptxErr != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall terminal: OP_PUSH_TX: %w", ptxErr)
			}
			finalOpPushTxSig = hex.EncodeToString(opPushTxSig)
			resolvedArgs[preimageIndex] = hex.EncodeToString(preimage)
		}
		// Don't sign Sig params — keep 72-byte placeholders
		realUnlock := c.BuildUnlockingScript(methodName, resolvedArgs)
		if needsOpPushTx && finalOpPushTxSig != "" {
			realUnlock = c.buildStatefulPrefix(finalOpPushTxSig, false) + realUnlock
			tmpTx := InsertUnlockingScript(termTx, 0, realUnlock)
			finalSig, finalPre, ptxErr := ComputeOpPushTxWithCodeSep(tmpTx, 0,
				contractUtxo.Script, contractUtxo.Satoshis, termCodeSepIdx)
			if ptxErr != nil {
				return nil, fmt.Errorf("RunarContract.PrepareCall terminal: OP_PUSH_TX rebuild: %w", ptxErr)
			}
			resolvedArgs[preimageIndex] = hex.EncodeToString(finalPre)
			finalOpPushTxSig = hex.EncodeToString(finalSig)
			finalPreimage = hex.EncodeToString(finalPre)
			realUnlock = c.buildStatefulPrefix(finalOpPushTxSig, false) +
				c.BuildUnlockingScript(methodName, resolvedArgs)
		}
		termTx = InsertUnlockingScript(termTx, 0, realUnlock)
		if finalPreimage == "" && needsOpPushTx {
			if s, ok := resolvedArgs[preimageIndex].(string); ok {
				finalPreimage = s
			}
		}
	}

	// Compute sighash from preimage
	sighash := ""
	if finalPreimage != "" {
		preimageBytes, decErr := hex.DecodeString(finalPreimage)
		if decErr == nil {
			h := sha256.Sum256(preimageBytes)
			sighash = hex.EncodeToString(h[:])
		}
	}

	return &PreparedCall{
		Sighash:           sighash,
		Preimage:          finalPreimage,
		OpPushTxSig:       finalOpPushTxSig,
		TxHex:             termTx,
		SigIndices:        sigIndices,
		methodName:        methodName,
		resolvedArgs:      resolvedArgs,
		methodSelectorHex: methodSelectorHex,
		isStateful:        isStateful,
		isTerminal:        true,
		needsOpPushTx:     needsOpPushTx,
		methodNeedsChange: methodNeedsChange,
		changePKHHex:      changePKHHex,
		changeAmount:      0,
		methodNeedsNewAmount: false,
		newAmount:         0,
		preimageIndex:     preimageIndex,
		contractUtxo:      contractUtxo,
		newLockingScript:  "",
		newSatoshis:       0,
		hasMultiOutput:    false,
		contractOutputs:   nil,
		codeSepIdx:        termCodeSepIdx,
	}, nil
}

// ---------------------------------------------------------------------------
// extractAllPrevouts extracts all input outpoints from a raw tx hex as a
// concatenated hex string. Each outpoint is txid (32 bytes LE) + vout (4 bytes LE).
func extractAllPrevouts(txHex string) string {
	bytes, _ := hex.DecodeString(txHex)
	if len(bytes) < 5 {
		return ""
	}
	offset := 4 // skip version
	inputCount, viLen := readVarintBytes(bytes, offset)
	offset += viLen

	var prevouts strings.Builder
	for i := 0; i < int(inputCount); i++ {
		// outpoint = 32 bytes txid + 4 bytes vout = 36 bytes
		if offset+36 > len(bytes) {
			break
		}
		prevouts.WriteString(hex.EncodeToString(bytes[offset : offset+36]))
		offset += 36
		// skip script
		scriptLen, svLen := readVarintBytes(bytes, offset)
		offset += svLen + int(scriptLen)
		offset += 4 // skip sequence
	}
	return prevouts.String()
}

func readVarintBytes(data []byte, offset int) (uint64, int) {
	if offset >= len(data) {
		return 0, 1
	}
	first := data[offset]
	if first < 0xfd {
		return uint64(first), 1
	} else if first == 0xfd && offset+2 < len(data) {
		return uint64(data[offset+1]) | uint64(data[offset+2])<<8, 3
	} else if first == 0xfe && offset+4 < len(data) {
		return uint64(data[offset+1]) | uint64(data[offset+2])<<8 |
			uint64(data[offset+3])<<16 | uint64(data[offset+4])<<24, 5
	}
	return 0, 9
}

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
	case *big.Int:
		return encodeBigIntScriptNumber(v)
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

// encodeBigIntScriptNumber encodes a *big.Int as a Bitcoin Script number push.
// Uses LE sign-magnitude encoding, same as encodeScriptNumber but for arbitrary precision.
func encodeBigIntScriptNumber(n *big.Int) string {
	if n.Sign() == 0 {
		return "00" // OP_0
	}
	if n.IsInt64() {
		return encodeScriptNumber(n.Int64())
	}

	// Big value: convert to LE sign-magnitude
	abs := new(big.Int).Abs(n)
	absBytes := abs.Bytes() // big-endian

	// Reverse to little-endian
	le := make([]byte, len(absBytes))
	for i, b := range absBytes {
		le[len(absBytes)-1-i] = b
	}

	// Add sign byte if needed
	if le[len(le)-1]&0x80 != 0 {
		if n.Sign() < 0 {
			le = append(le, 0x80)
		} else {
			le = append(le, 0x00)
		}
	} else if n.Sign() < 0 {
		le[len(le)-1] |= 0x80
	}

	return EncodePushData(bytesToHex(le))
}

// txidToChainHash converts a 64-char hex txid to a *chainhash.Hash for go-sdk.
func txidToChainHash(txid string) *chainhash.Hash {
	h, _ := chainhash.NewHashFromHex(txid)
	return h
}

