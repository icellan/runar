// sdk-usage-go.go -- Go SDK usage examples for all 8 TSOP contracts.
//
// Demonstrates how to use the TSOP Go compiler and the official BSV go-sdk to:
//   1. Compile .tsop.ts contract source files to Bitcoin Script artifacts
//   2. Generate keys, derive addresses, and build locking/unlocking scripts
//   3. Construct deployment transactions using go-sdk transaction builder
//   4. Compute BIP-143 sighash preimages for OP_PUSH_TX contracts
//   5. Sign transactions with real ECDSA (secp256k1)
//
// Prerequisites:
//   go get github.com/bsv-blockchain/go-sdk
//   go get github.com/tsop/compiler-go
//
// Build & run:  go run sdk-usage-go.go

package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"

	// TSOP Go compiler -- used as a library.
	// In a real project:  import tsop "github.com/tsop/compiler-go"
	// Exports: CompileFromSource, CompileFromIR, CompileFromIRBytes,
	//          CompileSourceToIR, ArtifactToJSON, and the Artifact/ABI types.
)

// =========================================================================
// OP_PUSH_TX Key (private key = 1)
// =========================================================================
// The OP_PUSH_TX technique uses a well-known keypair to prove a pushed
// preimage matches the spending transaction:
//   Private key:  k = 1
//   Public key:   P = G  (secp256k1 generator, compressed)
// Any valid ECDSA signature under this key verifies the preimage is genuine.
// Reference: https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX

var (
	opPushTxKey    *ec.PrivateKey
	opPushTxPubKey *ec.PublicKey
)

func init() {
	// Private key = 1 (big-endian, 32 bytes, zero-padded)
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	opPushTxKey, opPushTxPubKey = ec.PrivateKeyFromBytes(keyBytes)
}

// signOpPushTx signs a BIP-143 sighash preimage using the OP_PUSH_TX key (k=1).
// Returns DER-encoded signature with SIGHASH_ALL|FORKID appended.
func signOpPushTx(tx *transaction.Transaction, inputIdx uint32) ([]byte, []byte, error) {
	// Compute BIP-143 preimage using the go-sdk
	preimage, err := tx.CalcInputPreimage(inputIdx, sighash.AllForkID)
	if err != nil {
		return nil, nil, fmt.Errorf("calc preimage: %w", err)
	}

	// Double-SHA256 hash of the preimage
	hash := crypto.Sha256d(preimage)

	// Sign with private key = 1
	sig, err := opPushTxKey.Sign(hash)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: %w", err)
	}

	// DER-encode and append sighash flag
	sigBytes := sig.Serialize()
	sigBytes = append(sigBytes, byte(sighash.AllForkID))

	return sigBytes, preimage, nil
}

// buildUnlockingScript constructs a script by pushing each data element.
func buildUnlockingScript(pushes ...[]byte) *script.Script {
	s := &script.Script{}
	for _, data := range pushes {
		_ = s.AppendPushData(data)
	}
	return s
}

// appendMethodIndex appends a TSOP method dispatch index to a script.
// Uses canonical Bitcoin Script number opcodes: OP_0 (0), OP_1..OP_16 (1-16).
func appendMethodIndex(s *script.Script, idx int) {
	if idx == 0 {
		_ = s.AppendOpcodes(script.Op0)
	} else if idx >= 1 && idx <= 16 {
		_ = s.AppendOpcodes(byte(0x50 + idx)) // OP_1=0x51, OP_2=0x52, ...
	} else {
		_ = s.AppendPushData(big.NewInt(int64(idx)).Bytes())
	}
}

// =========================================================================
// Example 1: P2PKH (Pay to Public Key Hash)
// =========================================================================
// Source: examples/p2pkh/P2PKH.tsop.ts
// Constructor: (pubKeyHash: Addr)
// Method:      unlock(sig: Sig, pubKey: PubKey)
// Stateful:    No

func exampleP2PKH() {
	fmt.Println("=== Example 1: P2PKH ===")

	// --- Step 1: Compile the contract ---
	// artifact, err := tsop.CompileFromSource("examples/p2pkh/P2PKH.tsop.ts")
	// lockingScript, _ := script.NewFromHex(artifact.Script)
	fmt.Println("  artifact, err := tsop.CompileFromSource(\"examples/p2pkh/P2PKH.tsop.ts\")")

	// --- Step 2: Generate a keypair using go-sdk ---
	ownerKey, err := ec.NewPrivateKey()
	if err != nil {
		panic(err)
	}
	ownerPub := ownerKey.PubKey()
	ownerAddr, _ := script.NewAddressFromPublicKey(ownerPub, true)

	fmt.Printf("  Owner address: %s\n", ownerAddr.AddressString)
	fmt.Printf("  Owner pubkey:  %s\n", hex.EncodeToString(ownerPub.Compressed()))

	// --- Step 3: Build P2PKH locking script via go-sdk ---
	lockScript, _ := p2pkh.Lock(ownerAddr)

	// --- Step 4: Deploy -- create a UTXO locked by the contract ---
	// In production, the locking script comes from the compiled TSOP artifact.
	// Here we use a standard P2PKH for demonstration.
	fundTxIDHex := "0102030405060708091011121314151617181920212223242526272829303132"
	deployTx := transaction.NewTransaction()
	_ = deployTx.AddInputFrom(fundTxIDHex, 0, lockScript.String(), 50000, nil)
	deployTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      10000,
		LockingScript: lockScript,
	})

	deployTxID := deployTx.TxID()
	fmt.Printf("  Deploy TXID: %s\n", deployTxID.String()[:32]+"...")

	// --- Step 5: Spend -- unlock(sig, pubKey) ---
	// The go-sdk P2PKH template handles signing automatically.
	unlocker, _ := p2pkh.Unlock(ownerKey, nil)

	spendTx := transaction.NewTransaction()
	_ = spendTx.AddInputFrom(deployTxID.String(), 0, lockScript.String(), 10000, unlocker)
	_ = spendTx.PayToAddress(ownerAddr.AddressString, 9500)

	// Sign all inputs -- the P2PKH template computes sighash and signs
	_ = spendTx.Sign()

	fmt.Printf("  Spend TX: %d bytes\n", spendTx.Size())
	fmt.Printf("  ScriptSig: %s\n", spendTx.Inputs[0].UnlockingScript.String()[:40]+"...")
	fmt.Println("  Verifies: HASH160(pubKey) == pubKeyHash && CHECKSIG(sig, pubKey)")
	fmt.Println()
}

// =========================================================================
// Example 2: Escrow (multi-method, no state)
// =========================================================================
// Source: examples/escrow/Escrow.tsop.ts
// Constructor: (buyer: PubKey, seller: PubKey, arbiter: PubKey)
// Methods (4): releaseBySeller(sig), releaseByArbiter(sig),
//              refundToBuyer(sig), refundByArbiter(sig)
// Dispatch:    method index pushed as top stack element (0-3)

func exampleEscrow() {
	fmt.Println("=== Example 2: Escrow (4 methods) ===")

	// artifact, err := tsop.CompileFromSource("examples/escrow/Escrow.tsop.ts")
	fmt.Println("  artifact, err := tsop.CompileFromSource(\"examples/escrow/Escrow.tsop.ts\")")

	// Generate 3 keypairs: buyer, seller, arbiter
	buyerKey, _ := ec.NewPrivateKey()
	sellerKey, _ := ec.NewPrivateKey()
	arbiterKey, _ := ec.NewPrivateKey()
	_ = arbiterKey // used in method 1 and 3

	fmt.Printf("  Buyer pubkey:   %s...\n", hex.EncodeToString(buyerKey.PubKey().Compressed())[:20])
	fmt.Printf("  Seller pubkey:  %s...\n", hex.EncodeToString(sellerKey.PubKey().Compressed())[:20])

	// The TSOP compiler embeds constructor args (buyer, seller, arbiter pubkeys)
	// into the locking script at compile time. The deployed script is self-contained.
	//
	// Multi-method dispatch: the compiler emits OP_DUP/OP_NUMEQUAL/OP_IF chains.
	// scriptSig must push: <method_args...> <method_index>
	//   0: releaseBySeller   1: releaseByArbiter
	//   2: refundToBuyer     3: refundByArbiter

	// Simulate a compiled contract locking script (in production, from artifact.Script)
	lockScript, _ := script.NewFromHex("aa")

	// --- Call releaseBySeller (method 0): <sig> <0> ---
	// Sign the spending transaction's sighash
	prevTxIDHex := strings.Repeat("aa", 32)
	spendTx := transaction.NewTransaction()
	_ = spendTx.AddInputFrom(prevTxIDHex, 0, lockScript.String(), 50000, nil)
	sellerAddr, _ := script.NewAddressFromPublicKey(sellerKey.PubKey(), true)
	_ = spendTx.PayToAddress(sellerAddr.AddressString, 49500)

	// Compute sighash and sign with seller's key
	sigHash, _ := spendTx.CalcInputSignatureHash(0, sighash.AllForkID)
	sellerSig, _ := sellerKey.Sign(sigHash)
	sellerSigBytes := append(sellerSig.Serialize(), byte(sighash.AllForkID))

	// Build unlocking script: <sig> <method_index=0>
	scriptSig := buildUnlockingScript(sellerSigBytes)
	appendMethodIndex(scriptSig, 0) // OP_0
	spendTx.Inputs[0].UnlockingScript = scriptSig

	fmt.Printf("  releaseBySeller scriptSig: <sig> OP_0 (%d bytes)\n", len(*scriptSig))

	// --- Call refundToBuyer (method 2): <sig> <2> ---
	buyerSigHash, _ := spendTx.CalcInputSignatureHash(0, sighash.AllForkID)
	buyerSig, _ := buyerKey.Sign(buyerSigHash)
	buyerSigBytes := append(buyerSig.Serialize(), byte(sighash.AllForkID))
	refundScript := buildUnlockingScript(buyerSigBytes)
	appendMethodIndex(refundScript, 2) // OP_2

	fmt.Printf("  refundToBuyer   scriptSig: <sig> OP_2 (%d bytes)\n", len(*refundScript))
	fmt.Printf("  Spend TX: %d bytes\n\n", spendTx.Size())
}

// =========================================================================
// Example 3: Stateful Counter (OP_PUSH_TX)
// =========================================================================
// Source: examples/stateful-counter/Counter.tsop.ts
// Constructor: (count: bigint)      State: count (mutable)
// Methods:     increment(txPreimage), decrement(txPreimage)
// The contract verifies hash256(getStateScript()) == extractOutputHash(preimage),
// ensuring the spending TX output carries the correctly updated state.

func exampleCounter() {
	fmt.Println("=== Example 3: Stateful Counter (OP_PUSH_TX) ===")

	// artifact, err := tsop.CompileFromSource("examples/stateful-counter/Counter.tsop.ts")
	fmt.Println("  artifact, err := tsop.CompileFromSource(\"examples/stateful-counter/Counter.tsop.ts\")")

	lockScript, _ := script.NewFromHex("aa") // placeholder for artifact.Script
	fundTxIDHex := strings.Repeat("10", 32)

	// --- Deploy with count=0 ---
	deployTx := transaction.NewTransaction()
	_ = deployTx.AddInputFrom(fundTxIDHex, 0, "00", 200000, nil)
	deployTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      100000,
		LockingScript: lockScript,
	})
	dID := deployTx.TxID()
	fmt.Printf("  Deploy (count=0): TXID=%s...\n", dID.String()[:32])

	// --- Spend: increment (method 0, count 0 -> 1) ---
	// Build TX skeleton with output carrying updated contract state (count=1).
	spendTx := transaction.NewTransaction()
	spendTx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       dID,
		SourceTxOutIndex: 0,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, &transaction.TransactionOutput{
		Satoshis:      100000,
		LockingScript: lockScript,
	})
	spendTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      99500,
		LockingScript: lockScript, // contract continues with updated state
	})

	// Compute BIP-143 preimage and OP_PUSH_TX signature using go-sdk
	opPushTxSig, preimage, err := signOpPushTx(spendTx, 0)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}

	hash := crypto.Sha256d(preimage)
	fmt.Printf("  Preimage: %d bytes, sighash=%s...\n", len(preimage), hex.EncodeToString(hash[:16]))
	fmt.Printf("  OP_PUSH_TX sig: %d bytes (DER + sighash flag)\n", len(opPushTxSig))

	// scriptSig: <opPushTxSig> <preimage> <methodIndex=0>
	counterScript := buildUnlockingScript(opPushTxSig, preimage)
	appendMethodIndex(counterScript, 0) // OP_0
	spendTx.Inputs[0].UnlockingScript = counterScript

	fmt.Printf("  Spend TX (count 0->1): %d bytes\n", spendTx.Size())
	fmt.Println("  scriptSig: <opPushTxSig> <preimage> OP_0")
	fmt.Println("  Decrement: same with OP_1 for method index 1")
	fmt.Println()
}

// =========================================================================
// Example 4: Fungible Token (stateful, OP_PUSH_TX)
// =========================================================================
// Source: examples/token-ft/FungibleTokenExample.tsop.ts
// Constructor: (owner: PubKey, supply: bigint)
// State:       owner (mutable)     Readonly: supply
// Method:      transfer(sig, newOwner, txPreimage)

func exampleFungibleToken() {
	fmt.Println("=== Example 4: Fungible Token ===")
	fmt.Println("  artifact, err := tsop.CompileFromSource(\"examples/token-ft/FungibleTokenExample.tsop.ts\")")

	ownerKey, _ := ec.NewPrivateKey()
	newOwnerKey, _ := ec.NewPrivateKey()

	lockScript, _ := script.NewFromHex("aa")
	fundTxIDHex := strings.Repeat("44", 32)

	// --- Deploy ---
	deployTx := transaction.NewTransaction()
	_ = deployTx.AddInputFrom(fundTxIDHex, 0, "00", 100000, nil)
	deployTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      50000,
		LockingScript: lockScript,
	})
	dID := deployTx.TxID()

	// --- Transfer: single method, no method index needed ---
	spendTx := transaction.NewTransaction()
	spendTx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       dID,
		SourceTxOutIndex: 0,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, &transaction.TransactionOutput{
		Satoshis:      50000,
		LockingScript: lockScript,
	})
	spendTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      49500,
		LockingScript: lockScript, // continues with new owner
	})

	// Compute OP_PUSH_TX signature
	opPushTxSig, preimage, _ := signOpPushTx(spendTx, 0)

	// Sign with current owner's key
	sigHash, _ := spendTx.CalcInputSignatureHash(0, sighash.AllForkID)
	ownerSig, _ := ownerKey.Sign(sigHash)
	ownerSigBytes := append(ownerSig.Serialize(), byte(sighash.AllForkID))

	// scriptSig: <ownerSig> <newOwnerPubKey> <opPushTxSig> <preimage>
	newOwnerPubBytes := newOwnerKey.PubKey().Compressed()
	spendTx.Inputs[0].UnlockingScript = buildUnlockingScript(
		ownerSigBytes, newOwnerPubBytes, opPushTxSig, preimage,
	)

	fmt.Printf("  Transfer TX: %d bytes\n", spendTx.Size())
	fmt.Println("  scriptSig: <ownerSig> <newOwnerPubKey> <opPushTxSig> <preimage>")
	fmt.Println("  Verifies: checkSig(sig,owner) && checkPreimage(preimage)")
	fmt.Println("  Then: hash256(getStateScript()) == extractOutputHash(preimage)")
	fmt.Println()
}

// =========================================================================
// Example 5: NFT (stateful + burn method)
// =========================================================================
// Source: examples/token-nft/NFTExample.tsop.ts
// Constructor: (owner: PubKey, tokenId: ByteString, metadata: ByteString)
// State:       owner (mutable)
// Methods:     transfer(sig, newOwner, txPreimage) [0], burn(sig) [1]

func exampleNFT() {
	fmt.Println("=== Example 5: NFT ===")
	fmt.Println("  artifact, err := tsop.CompileFromSource(\"examples/token-nft/NFTExample.tsop.ts\")")

	ownerKey, _ := ec.NewPrivateKey()
	tokenId := hex.EncodeToString([]byte("NFT-001"))
	metadata := hex.EncodeToString([]byte("ipfs://QmExample"))
	fmt.Printf("  tokenId=%s, metadata=%s\n", tokenId, metadata)

	lockScript, _ := script.NewFromHex("aa")
	fundTxIDHex := strings.Repeat("55", 32)

	// --- Transfer (method 0): OP_PUSH_TX pattern ---
	fmt.Println("  transfer scriptSig: <ownerSig> <newOwner> <opPushTxSig> <preimage> OP_0")

	// --- Burn (method 1): NO OP_PUSH_TX, no state continuation ---
	burnTx := transaction.NewTransaction()
	_ = burnTx.AddInputFrom(fundTxIDHex, 0, lockScript.String(), 50000, nil)
	ownerAddr, _ := script.NewAddressFromPublicKey(ownerKey.PubKey(), true)
	_ = burnTx.PayToAddress(ownerAddr.AddressString, 49500)

	// Sign burn TX
	burnHash, _ := burnTx.CalcInputSignatureHash(0, sighash.AllForkID)
	burnSig, _ := ownerKey.Sign(burnHash)
	burnSigBytes := append(burnSig.Serialize(), byte(sighash.AllForkID))

	// scriptSig: <ownerSig> <method_index=1>
	burnScript := buildUnlockingScript(burnSigBytes)
	appendMethodIndex(burnScript, 1) // OP_1
	burnTx.Inputs[0].UnlockingScript = burnScript

	fmt.Printf("  burn scriptSig: <ownerSig> OP_1 (%d bytes)\n", len(*burnTx.Inputs[0].UnlockingScript))
	fmt.Println("  Burn destroys the token -- no output carries the contract forward.")
	fmt.Println()
}

// =========================================================================
// Example 6: Auction (stateful + locktime)
// =========================================================================
// Source: examples/auction/Auction.tsop.ts
// Constructor: (auctioneer, highestBidder, highestBid, deadline)
// State:       highestBidder (PubKey), highestBid (bigint)
// Methods:     bid(bidder, bidAmount, txPreimage) [0]
//              close(sig, txPreimage) [1]
// Uses extractLocktime(preimage) for deadline enforcement.

func exampleAuction() {
	fmt.Println("=== Example 6: Auction (stateful + locktime) ===")
	fmt.Println("  artifact, err := tsop.CompileFromSource(\"examples/auction/Auction.tsop.ts\")")

	auctioneerKey, _ := ec.NewPrivateKey()
	prevBidderKey, _ := ec.NewPrivateKey()
	_ = auctioneerKey

	deadline := uint32(800000) // block height
	lockScript, _ := script.NewFromHex("aa")
	fundTxIDHex := strings.Repeat("66", 32)

	// --- bid() [method 0] ---
	// nLocktime must be < deadline. nSequence < 0xffffffff to enable locktime.
	newBidderKey, _ := ec.NewPrivateKey()
	newBidderPub := newBidderKey.PubKey().Compressed()

	fundTxID, _ := chainhash.NewHashFromHex(fundTxIDHex)
	bidTx := transaction.NewTransaction()
	bidTx.LockTime = deadline - 1 // must be < deadline
	bidTx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       fundTxID,
		SourceTxOutIndex: 0,
		SequenceNumber:   0xfffffffe, // < 0xffffffff to enable locktime
	}, &transaction.TransactionOutput{
		Satoshis:      50000,
		LockingScript: lockScript,
	})

	// Output 0: contract continuation with updated state
	bidTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      51000, // new bid amount
		LockingScript: lockScript,
	})
	// Output 1: refund previous bidder
	prevBidderAddr, _ := script.NewAddressFromPublicKey(prevBidderKey.PubKey(), true)
	_ = bidTx.PayToAddress(prevBidderAddr.AddressString, 1000)

	// OP_PUSH_TX signature
	opPushTxSig, preimage, _ := signOpPushTx(bidTx, 0)

	// scriptSig: <bidder> <bidAmount> <opPushTxSig> <preimage> OP_0
	bidAmountBytes := big.NewInt(2000).Bytes()
	bidScript := buildUnlockingScript(newBidderPub, bidAmountBytes, opPushTxSig, preimage)
	appendMethodIndex(bidScript, 0) // OP_0
	bidTx.Inputs[0].UnlockingScript = bidScript

	fmt.Printf("  Bid TX: %d bytes, nLocktime=%d (< deadline %d)\n",
		bidTx.Size(), bidTx.LockTime, deadline)
	fmt.Println("  Verifies: bidAmount > highestBid && extractLocktime(preimage) < deadline")

	// --- close() [method 1] ---
	// nLocktime must be >= deadline.
	fmt.Println("  close scriptSig: <auctioneerSig> <opPushTxSig> <preimage> OP_1")
	fmt.Printf("  close TX nLocktime >= %d, no state continuation.\n\n", deadline)
}

// =========================================================================
// Example 7: Oracle Price Feed (Rabin signature)
// =========================================================================
// Source: examples/oracle-price/OraclePriceFeed.tsop.ts
// Constructor: (oraclePubKey: RabinPubKey, receiver: PubKey)
// Method:      settle(price, rabinSig, padding, sig)
// Stateless -- no OP_PUSH_TX needed.

func exampleOraclePriceFeed() {
	fmt.Println("=== Example 7: Oracle Price Feed (Rabin sig) ===")
	fmt.Println("  artifact, err := tsop.CompileFromSource(\"examples/oracle-price/OraclePriceFeed.tsop.ts\")")

	receiverKey, _ := ec.NewPrivateKey()
	lockScript, _ := script.NewFromHex("aa")
	fundTxIDHex := strings.Repeat("77", 32)

	// The oracle signs price data with its Rabin private key off-chain.
	// On-chain the contract verifies: verifyRabinSig(num2bin(price,8), rabinSig, padding, pubKey)
	price := int64(55000)
	fmt.Printf("  price=%d\n", price)

	spendTx := transaction.NewTransaction()
	_ = spendTx.AddInputFrom(fundTxIDHex, 0, lockScript.String(), 50000, nil)
	receiverAddr, _ := script.NewAddressFromPublicKey(receiverKey.PubKey(), true)
	_ = spendTx.PayToAddress(receiverAddr.AddressString, 49500)

	// Sign with receiver's key
	sigHash, _ := spendTx.CalcInputSignatureHash(0, sighash.AllForkID)
	sig, _ := receiverKey.Sign(sigHash)
	sigBytes := append(sig.Serialize(), byte(sighash.AllForkID))

	// scriptSig: <price> <rabinSig> <padding> <receiverSig>
	priceBytes := big.NewInt(price).Bytes()
	rabinSig := make([]byte, 64) // placeholder Rabin signature
	padding := make([]byte, 32)  // placeholder Rabin padding
	spendTx.Inputs[0].UnlockingScript = buildUnlockingScript(
		priceBytes, rabinSig, padding, sigBytes,
	)

	fmt.Printf("  scriptSig: <price> <rabinSig> <padding> <receiverSig> (%d bytes)\n",
		len(*spendTx.Inputs[0].UnlockingScript))
	fmt.Println("  Verifies: verifyRabinSig && price > 50000 && checkSig(sig, receiver)")
	fmt.Println()
}

// =========================================================================
// Example 8: Covenant Vault (OP_PUSH_TX, output enforcement)
// =========================================================================
// Source: examples/covenant-vault/CovenantVault.tsop.ts
// Constructor: (owner: PubKey, recipient: Addr, minAmount: bigint)
// Method:      spend(sig, amount, txPreimage)
// Stateless but uses checkPreimage to enforce spending constraints.

func exampleCovenantVault() {
	fmt.Println("=== Example 8: Covenant Vault ===")
	fmt.Println("  artifact, err := tsop.CompileFromSource(\"examples/covenant-vault/CovenantVault.tsop.ts\")")

	ownerKey, _ := ec.NewPrivateKey()
	recipientKey, _ := ec.NewPrivateKey()
	recipientAddr, _ := script.NewAddressFromPublicKey(recipientKey.PubKey(), true)
	minAmount := uint64(10000)
	spendAmount := uint64(15000)

	lockScript, _ := script.NewFromHex("aa")
	fundTxIDHex := strings.Repeat("99", 32)
	fundTxID, _ := chainhash.NewHashFromHex(fundTxIDHex)

	spendTx := transaction.NewTransaction()
	spendTx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       fundTxID,
		SourceTxOutIndex: 0,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, &transaction.TransactionOutput{
		Satoshis:      100000,
		LockingScript: lockScript,
	})
	_ = spendTx.PayToAddress(recipientAddr.AddressString, spendAmount)

	// OP_PUSH_TX signature
	opPushTxSig, preimage, _ := signOpPushTx(spendTx, 0)

	// Sign with owner's key
	sigHash, _ := spendTx.CalcInputSignatureHash(0, sighash.AllForkID)
	ownerSig, _ := ownerKey.Sign(sigHash)
	ownerSigBytes := append(ownerSig.Serialize(), byte(sighash.AllForkID))

	// scriptSig: <ownerSig> <amount> <opPushTxSig> <preimage>
	amountBytes := big.NewInt(int64(spendAmount)).Bytes()
	spendTx.Inputs[0].UnlockingScript = buildUnlockingScript(
		ownerSigBytes, amountBytes, opPushTxSig, preimage,
	)

	fmt.Printf("  Spend TX: %d bytes, amount=%d (>= minAmount=%d)\n",
		spendTx.Size(), spendAmount, minAmount)
	fmt.Println("  scriptSig: <ownerSig> <amount> <opPushTxSig> <preimage>")
	fmt.Println("  Verifies: checkSig && checkPreimage && amount >= minAmount")
	fmt.Printf("  Rejection: amount=%d would fail (< %d)\n\n", 5000, minAmount)
}

// =========================================================================
// OP_PUSH_TX Deep Dive
// =========================================================================

func explainOpPushTx() {
	fmt.Println("=== OP_PUSH_TX: How It Works ===")
	fmt.Println()
	fmt.Println("OP_PUSH_TX is a technique (not an opcode) allowing a locking script")
	fmt.Println("to introspect the spending transaction. Used by stateful contracts")
	fmt.Println("(Counter, FT, NFT, Auction) and covenant contracts (Vault).")
	fmt.Println()
	fmt.Println("Mechanism:")
	fmt.Println("  1. Spender builds BIP-143 sighash preimage and pushes it on stack")
	fmt.Println("  2. Locking script verifies via ECDSA with well-known keypair (k=1)")
	fmt.Println("  3. OP_CHECKSIG confirms preimage matches current transaction")
	fmt.Println()
	fmt.Printf("  Private key:  1\n")
	fmt.Printf("  Public key:   G = %s\n", hex.EncodeToString(opPushTxPubKey.Compressed()))
	fmt.Println()
	fmt.Println("go-sdk sighash preimage:")
	fmt.Println("  preimage, _ := tx.CalcInputPreimage(idx, sighash.AllForkID)")
	fmt.Println("  hash, _ := tx.CalcInputSignatureHash(idx, sighash.AllForkID)")
	fmt.Println("  sig, _ := opPushTxKey.Sign(hash)")
	fmt.Println()
	fmt.Println("BIP-143 preimage layout:")
	fmt.Println("  [0:4]   nVersion       [4:36]  hashPrevouts   [36:68]  hashSequence")
	fmt.Println("  [68:104] outpoint       [104:]  scriptCode(var) amount(8) nSequence(4)")
	fmt.Println("  [...-40] hashOutputs(32) nLocktime(4) sighashType(4)")
	fmt.Println()
	fmt.Println("Field extractors (used by contracts):")
	fmt.Println("  extractOutputHash -- verifies output matches updated state")
	fmt.Println("  extractLocktime   -- time-based logic (Auction deadline)")
	fmt.Println("  extractAmount     -- value constraints (Covenant minAmount)")
	fmt.Println()
	fmt.Println("Reference: https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX")
	fmt.Println()
}

// =========================================================================
// Main
// =========================================================================

func main() {
	fmt.Println("TSOP Go SDK Usage Examples")
	fmt.Println("==========================")
	fmt.Println()
	fmt.Println("Dependencies:")
	fmt.Println("  github.com/bsv-blockchain/go-sdk  -- BSV transaction building, signing, keys")
	fmt.Println("  github.com/tsop/compiler-go        -- TSOP contract compilation")
	fmt.Println()
	fmt.Println("Compiler API (github.com/tsop/compiler-go):")
	fmt.Println("  CompileFromSource(path)   -- .tsop.ts -> Artifact (passes 1-6)")
	fmt.Println("  CompileSourceToIR(path)   -- .tsop.ts -> ANFProgram (passes 1-4)")
	fmt.Println("  CompileFromIR(path)       -- ANF JSON -> Artifact (passes 5-6)")
	fmt.Println("  CompileFromIRBytes(data)  -- ANF bytes -> Artifact")
	fmt.Println("  ArtifactToJSON(artifact)  -- Artifact -> JSON")
	fmt.Println()
	fmt.Println("go-sdk API (github.com/bsv-blockchain/go-sdk):")
	fmt.Println("  ec.NewPrivateKey()                        -- Generate random keypair")
	fmt.Println("  ec.PrivateKeyFromHex(hex)                 -- Import private key")
	fmt.Println("  key.PubKey().Compressed()                 -- Get compressed public key bytes")
	fmt.Println("  script.NewAddressFromPublicKey(pub, true) -- Derive BSV address")
	fmt.Println("  transaction.NewTransaction()              -- Create transaction")
	fmt.Println("  tx.AddInputFrom(txid, vout, script, sat)  -- Add UTXO input")
	fmt.Println("  tx.PayToAddress(addr, sat)                -- Add P2PKH output")
	fmt.Println("  tx.CalcInputPreimage(idx, flag)           -- BIP-143 preimage")
	fmt.Println("  key.Sign(hash)                            -- ECDSA sign")
	fmt.Println()

	exampleP2PKH()
	exampleEscrow()
	exampleCounter()
	exampleFungibleToken()
	exampleNFT()
	exampleAuction()
	exampleOraclePriceFeed()
	exampleCovenantVault()
	explainOpPushTx()

	fmt.Println("Contract Summary:")
	fmt.Println("  P2PKH              | stateless | unlock(sig, pubKey)")
	fmt.Println("  Escrow             | stateless | 4 methods, method index dispatch")
	fmt.Println("  Counter            | stateful  | increment/decrement + OP_PUSH_TX")
	fmt.Println("  SimpleFungibleToken| stateful  | transfer + OP_PUSH_TX")
	fmt.Println("  SimpleNFT          | stateful  | transfer (OP_PUSH_TX) + burn (no preimage)")
	fmt.Println("  Auction            | stateful  | bid/close + OP_PUSH_TX + locktime")
	fmt.Println("  OraclePriceFeed    | stateless | Rabin sig verification")
	fmt.Println("  CovenantVault      | stateless | OP_PUSH_TX for output constraints")
}
