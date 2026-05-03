//go:build integration

package integration

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// BLAKE3 integration tests — port of integration/ts/blake3.test.ts.
//
// The Go compiler and SDK are exercised via inline contract sources. Each
// test compiles a minimal SmartContract that calls blake3Compress or
// blake3Hash, deploys it on regtest, then spends via contract.Call. The
// compiled script is ~11 KB; correctness is validated by the BSV node's
// real script interpreter, not the SDK interpreter.
//
// A pure-Go reference implementation of the BLAKE3 compression function
// computes the expected digests so the locking script's "expected" property
// can be baked at deployment time.

// ---------------------------------------------------------------------------
// BLAKE3 reference implementation (pure Go)
// ---------------------------------------------------------------------------

var blake3IV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

var blake3MsgPerm = [16]int{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

func blake3IVHex() string {
	var sb strings.Builder
	for _, w := range blake3IV {
		fmt.Fprintf(&sb, "%08x", w)
	}
	return sb.String()
}

func rotr32(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

func blake3G(state []uint32, a, b, c, d int, mx, my uint32) {
	state[a] = state[a] + state[b] + mx
	state[d] = rotr32(state[d]^state[a], 16)
	state[c] = state[c] + state[d]
	state[b] = rotr32(state[b]^state[c], 12)
	state[a] = state[a] + state[b] + my
	state[d] = rotr32(state[d]^state[a], 8)
	state[c] = state[c] + state[d]
	state[b] = rotr32(state[b]^state[c], 7)
}

func blake3Round(state []uint32, m []uint32) {
	blake3G(state, 0, 4, 8, 12, m[0], m[1])
	blake3G(state, 1, 5, 9, 13, m[2], m[3])
	blake3G(state, 2, 6, 10, 14, m[4], m[5])
	blake3G(state, 3, 7, 11, 15, m[6], m[7])
	blake3G(state, 0, 5, 10, 15, m[8], m[9])
	blake3G(state, 1, 6, 11, 12, m[10], m[11])
	blake3G(state, 2, 7, 8, 13, m[12], m[13])
	blake3G(state, 3, 4, 9, 14, m[14], m[15])
}

func referenceBlake3Compress(cvHex, blockHex string) string {
	if len(cvHex) != 64 || len(blockHex) != 128 {
		panic(fmt.Sprintf("blake3Compress: cv must be 32 bytes, block must be 64 bytes (got cv=%d hex chars, block=%d hex chars)", len(cvHex), len(blockHex)))
	}
	cvBytes, err := hex.DecodeString(cvHex)
	if err != nil {
		panic(err)
	}
	blockBytes, err := hex.DecodeString(blockHex)
	if err != nil {
		panic(err)
	}

	var cv [8]uint32
	for i := 0; i < 8; i++ {
		cv[i] = uint32(cvBytes[i*4])<<24 | uint32(cvBytes[i*4+1])<<16 | uint32(cvBytes[i*4+2])<<8 | uint32(cvBytes[i*4+3])
	}
	var m [16]uint32
	for i := 0; i < 16; i++ {
		m[i] = uint32(blockBytes[i*4])<<24 | uint32(blockBytes[i*4+1])<<16 | uint32(blockBytes[i*4+2])<<8 | uint32(blockBytes[i*4+3])
	}

	state := []uint32{
		cv[0], cv[1], cv[2], cv[3],
		cv[4], cv[5], cv[6], cv[7],
		blake3IV[0], blake3IV[1], blake3IV[2], blake3IV[3],
		0, 0, 64, 11,
	}

	msg := make([]uint32, 16)
	copy(msg, m[:])
	for r := 0; r < 7; r++ {
		blake3Round(state, msg)
		if r < 6 {
			next := make([]uint32, 16)
			for i, idx := range blake3MsgPerm {
				next[i] = msg[idx]
			}
			msg = next
		}
	}

	var out [8]uint32
	for i := 0; i < 8; i++ {
		out[i] = state[i] ^ state[i+8]
	}

	var sb strings.Builder
	for _, w := range out {
		fmt.Fprintf(&sb, "%08x", w)
	}
	return sb.String()
}

func referenceBlake3Hash(msgHex string) string {
	if len(msgHex)%2 != 0 {
		panic("blake3Hash: msg hex must have even length")
	}
	if len(msgHex)/2 > 64 {
		panic("blake3Hash: msg must fit a single 64-byte block")
	}
	padded := msgHex + strings.Repeat("00", 64-len(msgHex)/2)
	return referenceBlake3Compress(blake3IVHex(), padded)
}

// ---------------------------------------------------------------------------
// Inline contract sources
// ---------------------------------------------------------------------------

const blake3CompressSource = `
import { SmartContract, assert, blake3Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Blake3CompressVerify extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(chainingValue: ByteString, block: ByteString) {
    const result = blake3Compress(chainingValue, block);
    assert(result === this.expected);
  }
}
`

const blake3HashSource = `
import { SmartContract, assert, blake3Hash } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Blake3HashVerify extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(message: ByteString) {
    const result = blake3Hash(message);
    assert(result === this.expected);
  }
}
`

// ---------------------------------------------------------------------------
// Compiled artifacts (cached across tests in this file)
// ---------------------------------------------------------------------------

var (
	blake3CompressArtifact     *runar.RunarArtifact
	blake3CompressArtifactOnce sync.Once
	blake3HashArtifact         *runar.RunarArtifact
	blake3HashArtifactOnce     sync.Once
)

func getBlake3CompressArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	blake3CompressArtifactOnce.Do(func() {
		var err error
		blake3CompressArtifact, err = helpers.CompileSourceStringToSDKArtifact(
			blake3CompressSource, "Blake3CompressVerify.runar.ts", map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile Blake3CompressVerify: %v", err)
		}
	})
	return blake3CompressArtifact
}

func getBlake3HashArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	blake3HashArtifactOnce.Do(func() {
		var err error
		blake3HashArtifact, err = helpers.CompileSourceStringToSDKArtifact(
			blake3HashSource, "Blake3HashVerify.runar.ts", map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile Blake3HashVerify: %v", err)
		}
	})
	return blake3HashArtifact
}

// deployAndVerifyBlake3 wires up a funded wallet, deploys the artifact with
// the supplied expected digest, and asserts that contract.Call("verify", args)
// is accepted by the BSV node.
func deployAndVerifyBlake3(t *testing.T, artifact *runar.RunarArtifact, expected string, args []interface{}) {
	t.Helper()
	contract := runar.NewRunarContract(artifact, []interface{}{expected})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	txid, _, err := contract.Call("verify", args, provider, signer, nil)
	if err != nil {
		t.Fatalf("call verify: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d (%s)", len(txid), txid)
	}
	t.Logf("verify TX confirmed: %s", txid)
}

// ---------------------------------------------------------------------------
// Tests — blake3Compress
// ---------------------------------------------------------------------------

func TestBlake3_Compress_EmptyBlockWithIV(t *testing.T) {
	artifact := getBlake3CompressArtifact(t)
	t.Logf("Blake3CompressVerify script: %d bytes", len(artifact.Script)/2)
	block := strings.Repeat("00", 64)
	expected := referenceBlake3Compress(blake3IVHex(), block)
	deployAndVerifyBlake3(t, artifact, expected, []interface{}{blake3IVHex(), block})
}

func TestBlake3_Compress_AbcPaddedTo64(t *testing.T) {
	artifact := getBlake3CompressArtifact(t)
	block := "616263" + strings.Repeat("00", 61)
	expected := referenceBlake3Compress(blake3IVHex(), block)
	deployAndVerifyBlake3(t, artifact, expected, []interface{}{blake3IVHex(), block})
}

func TestBlake3_Compress_NonIVChainingValue(t *testing.T) {
	artifact := getBlake3CompressArtifact(t)
	customCV := strings.Repeat("deadbeef", 8)
	block := strings.Repeat("ff", 64)
	expected := referenceBlake3Compress(customCV, block)
	deployAndVerifyBlake3(t, artifact, expected, []interface{}{customCV, block})
}

func TestBlake3_Compress_RejectsWrongDigest(t *testing.T) {
	artifact := getBlake3CompressArtifact(t)
	block := strings.Repeat("00", 64)
	wrongExpected := strings.Repeat("00", 32)

	contract := runar.NewRunarContract(artifact, []interface{}{wrongExpected})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, _, err := contract.Call("verify", []interface{}{blake3IVHex(), block}, provider, signer, nil); err == nil {
		t.Fatalf("expected wrong-digest verify call to be rejected, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// Tests — blake3Hash
// ---------------------------------------------------------------------------

func TestBlake3_Hash_VariousMessages(t *testing.T) {
	artifact := getBlake3HashArtifact(t)
	t.Logf("Blake3HashVerify script: %d bytes", len(artifact.Script)/2)

	cases := []struct {
		name   string
		msgHex string
	}{
		{"empty", ""},
		{"abc", "616263"},
		{"32_bytes_ab", strings.Repeat("ab", 32)},
		{"64_bytes_cd", strings.Repeat("cd", 64)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expected := referenceBlake3Hash(tc.msgHex)
			deployAndVerifyBlake3(t, artifact, expected, []interface{}{tc.msgHex})
		})
	}
}

func TestBlake3_Hash_RejectsWrongDigest(t *testing.T) {
	artifact := getBlake3HashArtifact(t)
	wrongExpected := strings.Repeat("ff", 32)

	contract := runar.NewRunarContract(artifact, []interface{}{wrongExpected})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, _, err := contract.Call("verify", []interface{}{"616263"}, provider, signer, nil); err == nil {
		t.Fatalf("expected wrong-digest hash verify call to be rejected, but it succeeded")
	}
}
