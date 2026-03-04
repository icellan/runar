package runar

import (
	"encoding/hex"
	"fmt"
	"regexp"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// ---------------------------------------------------------------------------
// Signer interface
// ---------------------------------------------------------------------------

// Signer abstracts private key operations for signing transactions.
type Signer interface {
	// GetPublicKey returns the hex-encoded compressed public key (66 hex chars).
	GetPublicKey() (string, error)

	// GetAddress returns the BSV address.
	GetAddress() (string, error)

	// Sign signs a transaction input.
	// txHex is the full raw transaction hex being signed.
	// inputIndex is the index of the input being signed.
	// subscript is the locking script of the UTXO being spent (hex).
	// satoshis is the satoshi value of the UTXO being spent.
	// sigHashType is the sighash flags (nil defaults to ALL|FORKID = 0x41).
	// Returns the DER-encoded signature with sighash byte appended, hex-encoded.
	Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error)
}

// ---------------------------------------------------------------------------
// LocalSigner — private key in memory
// ---------------------------------------------------------------------------

var hexKeyRegex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
var wifRegex = regexp.MustCompile(`^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$`)

// LocalSigner holds a private key in memory for signing transactions.
// Suitable for CLI tooling and testing. For production wallets, use
// ExternalSigner with hardware wallet callbacks instead.
type LocalSigner struct {
	privKey *ec.PrivateKey
}

// NewLocalSigner creates a LocalSigner from a private key.
// keyInput can be a 64-char hex string or a WIF-encoded key (starts with 5/K/L).
func NewLocalSigner(keyInput string) (*LocalSigner, error) {
	var privKey *ec.PrivateKey
	var err error

	if hexKeyRegex.MatchString(keyInput) {
		privKey, err = ec.PrivateKeyFromHex(keyInput)
		if err != nil {
			return nil, fmt.Errorf("LocalSigner: invalid hex private key: %w", err)
		}
	} else if wifRegex.MatchString(keyInput) {
		privKey, err = ec.PrivateKeyFromWif(keyInput)
		if err != nil {
			return nil, fmt.Errorf("LocalSigner: invalid WIF key: %w", err)
		}
	} else {
		return nil, fmt.Errorf("LocalSigner: expected a 64-char hex private key or a WIF-encoded key (starts with 5, K, or L)")
	}

	return &LocalSigner{privKey: privKey}, nil
}

// GetPublicKey returns the hex-encoded compressed public key (66 hex chars).
func (s *LocalSigner) GetPublicKey() (string, error) {
	return hex.EncodeToString(s.privKey.PubKey().Compressed()), nil
}

// GetAddress returns the mainnet BSV P2PKH address.
func (s *LocalSigner) GetAddress() (string, error) {
	addr, err := script.NewAddressFromPublicKey(s.privKey.PubKey(), true)
	if err != nil {
		return "", fmt.Errorf("LocalSigner: address derivation failed: %w", err)
	}
	return addr.AddressString, nil
}

// Sign signs a transaction input using BIP-143 sighash and ECDSA.
func (s *LocalSigner) Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
	flag := sighash.AllForkID
	if sigHashType != nil {
		flag = sighash.Flag(*sigHashType)
	}

	tx, err := transaction.NewTransactionFromHex(txHex)
	if err != nil {
		return "", fmt.Errorf("LocalSigner: failed to parse transaction: %w", err)
	}

	if inputIndex < 0 || inputIndex >= len(tx.Inputs) {
		return "", fmt.Errorf("LocalSigner: input index %d out of range (tx has %d inputs)", inputIndex, len(tx.Inputs))
	}

	lockScript, err := script.NewFromHex(subscript)
	if err != nil {
		return "", fmt.Errorf("LocalSigner: failed to parse subscript: %w", err)
	}

	tx.Inputs[inputIndex].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(satoshis),
		LockingScript: lockScript,
	})

	sigHashBytes, err := tx.CalcInputSignatureHash(uint32(inputIndex), flag)
	if err != nil {
		return "", fmt.Errorf("LocalSigner: sighash computation failed: %w", err)
	}

	sig, err := s.privKey.Sign(sigHashBytes)
	if err != nil {
		return "", fmt.Errorf("LocalSigner: ECDSA signing failed: %w", err)
	}

	derBytes := sig.Serialize()
	result := append(derBytes, byte(flag))
	return hex.EncodeToString(result), nil
}

// ---------------------------------------------------------------------------
// MockSigner — deterministic signer for testing
// ---------------------------------------------------------------------------

// MockSignerImpl is a mock signer that returns deterministic values for testing.
// It does not perform real cryptographic operations.
type MockSignerImpl struct {
	pubKey  string
	address string
}

// NewMockSigner creates a mock signer with the given public key hex and address.
// If empty strings are passed, defaults are used.
func NewMockSigner(pubKeyHex, address string) *MockSignerImpl {
	if pubKeyHex == "" {
		// Default: 33-byte compressed public key (02 + 32 zero bytes)
		pubKeyHex = "02" + repeatHex("00", 32)
	}
	if address == "" {
		address = repeatHex("00", 20) // 40-char hex as a mock address
	}
	return &MockSignerImpl{
		pubKey:  pubKeyHex,
		address: address,
	}
}

// GetPublicKey returns the mock public key.
func (s *MockSignerImpl) GetPublicKey() (string, error) {
	return s.pubKey, nil
}

// GetAddress returns the mock address.
func (s *MockSignerImpl) GetAddress() (string, error) {
	return s.address, nil
}

// Sign returns a mock DER-encoded signature (72 zero bytes as hex).
func (s *MockSignerImpl) Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
	// Return a deterministic 72-byte mock signature (all zeros) + sighash byte 0x41
	return repeatHex("00", 71) + "41", nil
}

// ---------------------------------------------------------------------------
// ExternalSigner — callback-based signer
// ---------------------------------------------------------------------------

// SignFunc is a callback function for signing.
type SignFunc func(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error)

// ExternalSigner wraps a callback function as a Signer.
type ExternalSigner struct {
	pubKey  string
	address string
	signFn  SignFunc
}

// NewExternalSigner creates a signer from callback functions.
func NewExternalSigner(pubKeyHex, address string, signFn SignFunc) *ExternalSigner {
	return &ExternalSigner{
		pubKey:  pubKeyHex,
		address: address,
		signFn:  signFn,
	}
}

// GetPublicKey returns the external public key.
func (s *ExternalSigner) GetPublicKey() (string, error) {
	return s.pubKey, nil
}

// GetAddress returns the external address.
func (s *ExternalSigner) GetAddress() (string, error) {
	return s.address, nil
}

// Sign delegates to the callback function.
func (s *ExternalSigner) Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
	return s.signFn(txHex, inputIndex, subscript, satoshis, sigHashType)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func repeatHex(b string, count int) string {
	result := make([]byte, 0, len(b)*count)
	for i := 0; i < count; i++ {
		result = append(result, b...)
	}
	return string(result)
}
