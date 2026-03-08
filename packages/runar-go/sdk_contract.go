package runar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

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
	// For stateful contracts, the compiler injects implicit params into every
	// public method's ABI (SigHashPreimage, and for state-mutating methods:
	// _changePKH and _changeAmount). The SDK auto-computes these.
	// Filter them out so users only pass their own args.
	isStateful := len(c.Artifact.StateFields) > 0
	methodNeedsChange := false
	for _, p := range method.Params {
		if p.Name == "_changePKH" {
			methodNeedsChange = true
			break
		}
	}
	var userParams []ABIParam
	if isStateful {
		for _, p := range method.Params {
			if p.Type != "SigHashPreimage" && p.Name != "_changePKH" && p.Name != "_changeAmount" {
				userParams = append(userParams, p)
			}
		}
	} else {
		userParams = method.Params
	}
	if len(userParams) != len(args) {
		return "", nil, fmt.Errorf(
			"RunarContract.call: method '%s' expects %d args, got %d",
			methodName, len(userParams), len(args),
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

	// Detect Sig/PubKey/SigHashPreimage/ByteString params that need auto-compute (user passed nil)
	resolvedArgs := make([]interface{}, len(args))
	copy(resolvedArgs, args)
	var sigIndices []int
	var prevoutsIndices []int
	preimageIndex := -1
	for i, param := range userParams {
		if param.Type == "Sig" && args[i] == nil {
			sigIndices = append(sigIndices, i)
			// 72-byte placeholder
			resolvedArgs[i] = strings.Repeat("00", 72)
		}
		if param.Type == "PubKey" && args[i] == nil {
			pubKey, pkErr := signer.GetPublicKey()
			if pkErr != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: getting public key for PubKey param: %w", pkErr)
			}
			resolvedArgs[i] = pubKey
		}
		if param.Type == "SigHashPreimage" && args[i] == nil {
			preimageIndex = i
			// Placeholder preimage (will be replaced after tx construction)
			resolvedArgs[i] = strings.Repeat("00", 181)
		}
		if param.Type == "ByteString" && args[i] == nil {
			prevoutsIndices = append(prevoutsIndices, i)
			// Placeholder sized to estimated input count (1 primary + N extra + 1 funding)
			nExtra := 0
			if options != nil {
				nExtra = len(options.AdditionalContractInputs)
			}
			estimatedInputs := 1 + nExtra + 1
			resolvedArgs[i] = strings.Repeat("00", 36*estimatedInputs)
		}
	}

	// For stateful contracts, preimage is always needed (auto-computed by the
	// stateful path below), even though it's not in userParams.
	needsOpPushTx := preimageIndex >= 0 || isStateful

	// Collect additional contract inputs (e.g., for merge)
	var extraContractUtxos []*UTXO
	if options != nil {
		extraContractUtxos = options.AdditionalContractInputs
	}

	// Build contract outputs: multi-output (options.Outputs) takes priority,
	// then single continuation (options.NewState), then default.
	var contractOutputs []ContractOutput
	hasMultiOutput := options != nil && len(options.Outputs) > 0

	newLockingScript := ""
	newSatoshis := int64(0)

	if isStateful && hasMultiOutput {
		// Multi-output: build a locking script for each output
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
		// For single-output continuations, the on-chain script uses the input amount
		// (extracted from the preimage). The SDK output must match.
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

	// Fetch fee rate and funding UTXOs for all contract types.
	// For stateful contracts with change output support, the change output
	// is verified by the on-chain script (hashOutputs check).
	feeRate, feeErr := provider.GetFeeRate()
	if feeErr != nil {
		return "", nil, fmt.Errorf("RunarContract.Call: getting fee rate: %w", feeErr)
	}
	changeScript := BuildP2PKHScript(changeAddress)
	allFundingUtxos, err := provider.GetUtxos(address)
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Call: getting UTXOs: %w", err)
	}
	// Filter out the current contract UTXO from funding UTXOs
	var additionalUtxos []UTXO
	for _, u := range allFundingUtxos {
		if !(u.Txid == c.currentUtxo.Txid && u.OutputIndex == c.currentUtxo.OutputIndex) {
			additionalUtxos = append(additionalUtxos, u)
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
				return "", nil, fmt.Errorf("RunarContract.Call: getting public key for change PKH: %w", pkErr)
			}
			changePubKeyHex = pk
		}
		pubKeyBytes, decErr := hex.DecodeString(changePubKeyHex)
		if decErr != nil {
			return "", nil, fmt.Errorf("RunarContract.Call: decoding change pubkey hex: %w", decErr)
		}
		h := sha256.Sum256(pubKeyBytes)
		r := ripemd160.New()
		r.Write(h[:])
		changePKHHex = hex.EncodeToString(r.Sum(nil))
	}

	// Build the unlocking script. For contracts with checkPreimage (stateful
	// or stateless with SigHashPreimage params), OP_PUSH_TX data is inserted:
	//   Stateful: <opPushTxSig> <user_args> <txPreimage> <methodSelector>
	//   Stateless: <opPushTxSig> <user_args_with_preimage> <methodSelector>
	// This requires building the TX first with a placeholder, computing the
	// preimage, then rebuilding the unlock.

	// Initial unlocking script (with placeholders)
	var unlockingScript string
	if needsOpPushTx || isStateful {
		// Prepend placeholder _opPushTxSig
		unlockingScript = EncodePushData(strings.Repeat("00", 72)) +
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
						return "", nil, fmt.Errorf("RunarContract.Call: getting public key for PubKey param (extra input %d): %w", i, pkErr)
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
		extraUnlockPlaceholders[i] = EncodePushData(strings.Repeat("00", 72)) +
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

	txHex, inputCount, changeAmount := BuildCallTransaction(
		*c.currentUtxo,
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
	signedTx := txHex
	p2pkhStartIdx := 1 + len(extraContractUtxos)
	for i := p2pkhStartIdx; i < inputCount; i++ {
		utxoIdx := i - p2pkhStartIdx
		if utxoIdx < len(additionalUtxos) {
			utxo := additionalUtxos[utxoIdx]
			sig, signErr := signer.Sign(signedTx, i, utxo.Script, utxo.Satoshis, nil)
			if signErr != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: signing input %d: %w", i, signErr)
			}
			pubKey, pkErr := signer.GetPublicKey()
			if pkErr != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: getting public key: %w", pkErr)
			}
			unlockScript := EncodePushData(sig) + EncodePushData(pubKey)
			signedTx = InsertUnlockingScript(signedTx, i, unlockScript)
		}
	}

	// For stateful contracts, build the OP_PUSH_TX unlocking script:
	//   <opPushTxSig> <user_args> <txPreimage> <methodSelector>
	if isStateful {
		// Compute method selector
		methodSelectorHex := ""
		publicMethods := c.getPublicMethods()
		if len(publicMethods) > 1 {
			for i, m := range publicMethods {
				if m.Name == methodName {
					methodSelectorHex = encodeScriptNumber(int64(i))
					break
				}
			}
		}

		// Helper to build a stateful unlocking script for a given input
		buildStatefulUnlock := func(tx string, inputIdx int, subscript string, sats int64, baseArgs []interface{}, txChangeAmount int64) (string, error) {
			opSig, preimage, ptxErr := ComputeOpPushTx(tx, inputIdx, subscript, sats)
			if ptxErr != nil {
				return "", fmt.Errorf("OP_PUSH_TX for input %d: %w", inputIdx, ptxErr)
			}
			// Clone baseArgs for this input (Sig params are input-specific)
			inputArgs := make([]interface{}, len(baseArgs))
			copy(inputArgs, baseArgs)
			for _, idx := range sigIndices {
				realSig, sigErr := signer.Sign(tx, inputIdx, subscript, sats, nil)
				if sigErr != nil {
					return "", fmt.Errorf("auto-signing Sig param %d for input %d: %w", idx, inputIdx, sigErr)
				}
				inputArgs[idx] = realSig
			}
			// Resolve ByteString params (auto-compute allPrevouts from tx)
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
			// Append change params (PKH + amount) for methods that need them
			changeHex := ""
			if methodNeedsChange && changePKHHex != "" {
				changeHex = EncodePushData(changePKHHex) + encodeArg(txChangeAmount)
			}
			return EncodePushData(hex.EncodeToString(opSig)) +
				argsHex +
				changeHex +
				EncodePushData(hex.EncodeToString(preimage)) +
				methodSelectorHex, nil
		}

		// First pass: build unlocking scripts with current tx layout
		input0Unlock, err := buildStatefulUnlock(signedTx, 0, c.currentUtxo.Script, c.currentUtxo.Satoshis, resolvedArgs, changeAmount)
		if err != nil {
			return "", nil, fmt.Errorf("RunarContract.Call: %w", err)
		}
		extraUnlocks := make([]string, len(extraContractUtxos))
		for i, mu := range extraContractUtxos {
			extraUnlocks[i], err = buildStatefulUnlock(signedTx, i+1, mu.Script, mu.Satoshis, extraResolvedArgs[i], changeAmount)
			if err != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: %w", err)
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
		txHex, inputCount, changeAmount = BuildCallTransaction(
			*c.currentUtxo,
			input0Unlock,
			newLockingScript,
			newSatoshis,
			changeAddress,
			changeScript,
			additionalUtxos,
			feeRate,
			rebuildOpts,
		)
		signedTx = txHex

		// Second pass: recompute with final tx (preimage changes with unlock size)
		finalInput0Unlock, err := buildStatefulUnlock(signedTx, 0, c.currentUtxo.Script, c.currentUtxo.Satoshis, resolvedArgs, changeAmount)
		if err != nil {
			return "", nil, fmt.Errorf("RunarContract.Call: %w", err)
		}
		signedTx = InsertUnlockingScript(signedTx, 0, finalInput0Unlock)

		for i, mu := range extraContractUtxos {
			finalMergeUnlock, mergeErr := buildStatefulUnlock(signedTx, i+1, mu.Script, mu.Satoshis, extraResolvedArgs[i], changeAmount)
			if mergeErr != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: %w", mergeErr)
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
					return "", nil, fmt.Errorf("RunarContract.Call: re-signing input %d: %w", i, signErr)
				}
				pubKey, pkErr := signer.GetPublicKey()
				if pkErr != nil {
					return "", nil, fmt.Errorf("RunarContract.Call: getting public key: %w", pkErr)
				}
				unlockScript := EncodePushData(sig) + EncodePushData(pubKey)
				signedTx = InsertUnlockingScript(signedTx, i, unlockScript)
			}
		}
	} else if needsOpPushTx || len(sigIndices) > 0 {
		// Stateless with SigHashPreimage or Sig params: auto-compute
		var opPushTxSigHex string
		if needsOpPushTx {
			opPushTxSig, preimage, ptxErr := ComputeOpPushTx(signedTx, 0,
				c.currentUtxo.Script, c.currentUtxo.Satoshis)
			if ptxErr != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: OP_PUSH_TX: %w", ptxErr)
			}
			opPushTxSigHex = hex.EncodeToString(opPushTxSig)
			resolvedArgs[preimageIndex] = hex.EncodeToString(preimage)
		}

		for _, idx := range sigIndices {
			realSig, sigErr := signer.Sign(signedTx, 0, c.currentUtxo.Script, c.currentUtxo.Satoshis, nil)
			if sigErr != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: auto-signing Sig param %d: %w", idx, sigErr)
			}
			resolvedArgs[idx] = realSig
		}

		realUnlockingScript := c.BuildUnlockingScript(methodName, resolvedArgs)
		if needsOpPushTx && opPushTxSigHex != "" {
			realUnlockingScript = EncodePushData(opPushTxSigHex) + realUnlockingScript

			tmpTx := InsertUnlockingScript(signedTx, 0, realUnlockingScript)
			finalSig, finalPreimage, ptxErr := ComputeOpPushTx(tmpTx, 0,
				c.currentUtxo.Script, c.currentUtxo.Satoshis)
			if ptxErr != nil {
				return "", nil, fmt.Errorf("RunarContract.Call: OP_PUSH_TX for rebuild: %w", ptxErr)
			}
			resolvedArgs[preimageIndex] = hex.EncodeToString(finalPreimage)
			for _, idx := range sigIndices {
				realSig, sigErr := signer.Sign(tmpTx, 0, c.currentUtxo.Script, c.currentUtxo.Satoshis, nil)
				if sigErr != nil {
					return "", nil, fmt.Errorf("RunarContract.Call: auto-signing Sig param %d: %w", idx, sigErr)
				}
				resolvedArgs[idx] = realSig
			}
			realUnlockingScript = EncodePushData(hex.EncodeToString(finalSig)) +
				c.BuildUnlockingScript(methodName, resolvedArgs)
		}
		signedTx = InsertUnlockingScript(signedTx, 0, realUnlockingScript)
	}

	// Broadcast
	txid, err := provider.Broadcast(signedTx)
	if err != nil {
		return "", nil, fmt.Errorf("RunarContract.Call: broadcasting: %w", err)
	}

	// Update tracked UTXO for stateful contracts
	if isStateful && hasMultiOutput && len(contractOutputs) > 0 {
		// Multi-output: track the first continuation output
		c.currentUtxo = &UTXO{
			Txid:        txid,
			OutputIndex: 0,
			Satoshis:    contractOutputs[0].Satoshis,
			Script:      contractOutputs[0].Script,
		}
	} else if isStateful && newLockingScript != "" {
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

