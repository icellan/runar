//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// SHA-256 compress integration tests — port of integration/ts/sha256-compress.test.ts.
//
// These exercise the sha256Compress intrinsic on a real BSV node. Each test
// compiles a stateless contract whose body calls sha256Compress against a
// caller-provided state + block, asserts the result matches a digest baked
// into the locking script (or matches OP_SHA256 cross-verification), and
// confirms the BSV interpreter accepts/rejects the spend.

const sha256Init = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"

// sha256Pad pads msgHex per FIPS 180-4 Section 5.1.1 to a multiple of 64 bytes.
func sha256Pad(msgHex string) string {
	if len(msgHex)%2 != 0 {
		panic("sha256Pad: msgHex must have even length")
	}
	msgBytes := len(msgHex) / 2
	bitLen := uint64(msgBytes) * 8
	padded := msgHex + "80"
	for (len(padded)/2)%64 != 56 {
		padded += "00"
	}
	padded += fmt.Sprintf("%016x", bitLen)
	return padded
}

// referenceSha256Compress is a pure-Go SHA-256 compression function used to
// compute expected digests for non-cross-verify tests (single block from an
// arbitrary intermediate state).
func referenceSha256Compress(stateHex, blockHex string) string {
	if len(stateHex) != 64 || len(blockHex) != 128 {
		panic(fmt.Sprintf("sha256Compress: state must be 32 bytes, block must be 64 bytes (got state=%d hex chars, block=%d hex chars)", len(stateHex), len(blockHex)))
	}
	K := []uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
	rotr := func(x uint32, n uint) uint32 {
		return (x >> n) | (x << (32 - n))
	}

	stateBytes, err := hex.DecodeString(stateHex)
	if err != nil {
		panic(err)
	}
	blockBytes, err := hex.DecodeString(blockHex)
	if err != nil {
		panic(err)
	}

	var H [8]uint32
	for i := 0; i < 8; i++ {
		H[i] = uint32(stateBytes[i*4])<<24 | uint32(stateBytes[i*4+1])<<16 | uint32(stateBytes[i*4+2])<<8 | uint32(stateBytes[i*4+3])
	}
	W := make([]uint32, 64)
	for i := 0; i < 16; i++ {
		W[i] = uint32(blockBytes[i*4])<<24 | uint32(blockBytes[i*4+1])<<16 | uint32(blockBytes[i*4+2])<<8 | uint32(blockBytes[i*4+3])
	}
	for t := 16; t < 64; t++ {
		s0 := rotr(W[t-15], 7) ^ rotr(W[t-15], 18) ^ (W[t-15] >> 3)
		s1 := rotr(W[t-2], 17) ^ rotr(W[t-2], 19) ^ (W[t-2] >> 10)
		W[t] = s1 + W[t-7] + s0 + W[t-16]
	}

	a, b, c, d, e, f, g, h := H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]
	for t := 0; t < 64; t++ {
		S1 := rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
		ch := (e & f) ^ (^e & g)
		T1 := h + S1 + ch + K[t] + W[t]
		S0 := rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		T2 := S0 + maj
		h = g
		g = f
		f = e
		e = d + T1
		d = c
		c = b
		b = a
		a = T1 + T2
	}

	out := []uint32{a + H[0], b + H[1], c + H[2], d + H[3], e + H[4], f + H[5], g + H[6], h + H[7]}
	var sb strings.Builder
	for _, w := range out {
		fmt.Fprintf(&sb, "%08x", w)
	}
	return sb.String()
}

// nativeSha256Hex returns SHA-256(hexBytes) as a hex string.
func nativeSha256Hex(hexBytes string) string {
	b, err := hex.DecodeString(hexBytes)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// Inline contract sources
// ---------------------------------------------------------------------------

const sha256CompressSource = `
import { SmartContract, assert, sha256Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256CompressVerify extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, block: ByteString) {
    const result = sha256Compress(state, block);
    assert(result === this.expected);
  }
}
`

const sha256CrossVerifySource = `
import { SmartContract, assert, sha256Compress, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256CompressCross extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(message: ByteString, paddedBlock: ByteString) {
    const compressed = sha256Compress(this.initState, paddedBlock);
    const native = sha256(message);
    assert(compressed === native);
  }
}
`

const sha256TwoBlockSource = `
import { SmartContract, assert, sha256Compress, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256CompressTwoBlock extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(message: ByteString, block1: ByteString, block2: ByteString) {
    const mid = sha256Compress(this.initState, block1);
    const final = sha256Compress(mid, block2);
    const native = sha256(message);
    assert(final === native);
  }
}
`

var (
	sha256CompressArt     *runar.RunarArtifact
	sha256CompressArtOnce sync.Once
	sha256CrossArt        *runar.RunarArtifact
	sha256CrossArtOnce    sync.Once
	sha256TwoBlockArt     *runar.RunarArtifact
	sha256TwoBlockArtOnce sync.Once
)

func getSha256CompressArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	sha256CompressArtOnce.Do(func() {
		var err error
		sha256CompressArt, err = helpers.CompileSourceStringToSDKArtifact(
			sha256CompressSource, "Sha256CompressVerify.runar.ts", map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile Sha256CompressVerify: %v", err)
		}
	})
	return sha256CompressArt
}

func getSha256CrossArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	sha256CrossArtOnce.Do(func() {
		var err error
		sha256CrossArt, err = helpers.CompileSourceStringToSDKArtifact(
			sha256CrossVerifySource, "Sha256CompressCross.runar.ts", map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile Sha256CompressCross: %v", err)
		}
	})
	return sha256CrossArt
}

func getSha256TwoBlockArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	sha256TwoBlockArtOnce.Do(func() {
		var err error
		sha256TwoBlockArt, err = helpers.CompileSourceStringToSDKArtifact(
			sha256TwoBlockSource, "Sha256CompressTwoBlock.runar.ts", map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile Sha256CompressTwoBlock: %v", err)
		}
	})
	return sha256TwoBlockArt
}

func deployAndVerifySha256(t *testing.T, artifact *runar.RunarArtifact, ctorArg string, args []interface{}) {
	t.Helper()
	contract := runar.NewRunarContract(artifact, []interface{}{ctorArg})

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
		t.Fatalf("expected 64-char txid, got %d", len(txid))
	}
	t.Logf("verify TX confirmed: %s", txid)
}

// ---------------------------------------------------------------------------
// Single-block path: explicit padded block + hardcoded digest
// ---------------------------------------------------------------------------

func TestSha256Compress_SingleBlockAbc(t *testing.T) {
	artifact := getSha256CompressArtifact(t)
	t.Logf("Sha256CompressVerify script: %d bytes", len(artifact.Script)/2)

	block :=
		"6162638000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000018"
	expected := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	deployAndVerifySha256(t, artifact, expected, []interface{}{sha256Init, block})
}

// ---------------------------------------------------------------------------
// Cross-verification: contract checks sha256Compress(state, padded) == sha256(msg)
// ---------------------------------------------------------------------------

func TestSha256Compress_CrossVerifyAbc(t *testing.T) {
	artifact := getSha256CrossArtifact(t)
	msgHex := "616263"
	padded := sha256Pad(msgHex)
	deployAndVerifySha256(t, artifact, sha256Init, []interface{}{msgHex, padded})
}

func TestSha256Compress_CrossVerify55Bytes(t *testing.T) {
	artifact := getSha256CrossArtifact(t)
	msgHex := strings.Repeat("aa", 55)
	padded := sha256Pad(msgHex)
	if len(padded)/2 != 64 {
		t.Fatalf("expected single-block padding (64 bytes), got %d", len(padded)/2)
	}
	deployAndVerifySha256(t, artifact, sha256Init, []interface{}{msgHex, padded})
}

// ---------------------------------------------------------------------------
// Two-block path: 56-byte message requires 2 blocks
// ---------------------------------------------------------------------------

func TestSha256Compress_TwoBlock56Bytes(t *testing.T) {
	artifact := getSha256TwoBlockArtifact(t)
	msgHex := strings.Repeat("bb", 56)
	padded := sha256Pad(msgHex)
	if len(padded)/2 != 128 {
		t.Fatalf("expected two-block padding (128 bytes), got %d", len(padded)/2)
	}
	block1 := padded[:128]
	block2 := padded[128:]
	deployAndVerifySha256(t, artifact, sha256Init, []interface{}{msgHex, block1, block2})
}

// ---------------------------------------------------------------------------
// Non-initial state: compression starts from an arbitrary intermediate state
// ---------------------------------------------------------------------------

func TestSha256Compress_NonInitialState(t *testing.T) {
	artifact := getSha256CompressArtifact(t)
	// Use SHA-256("abc") as the intermediate state, compress padded "ff"*10.
	midState := nativeSha256Hex("616263")
	block := sha256Pad(strings.Repeat("ff", 10))
	expected := referenceSha256Compress(midState, block)
	deployAndVerifySha256(t, artifact, expected, []interface{}{midState, block})
}

// ---------------------------------------------------------------------------
// Rejection: wrong expected digest fails on-chain
// ---------------------------------------------------------------------------

func TestSha256Compress_RejectsWrongDigest(t *testing.T) {
	artifact := getSha256CompressArtifact(t)
	block :=
		"6162638000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000018"
	wrong := strings.Repeat("00", 32)

	contract := runar.NewRunarContract(artifact, []interface{}{wrong})

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
	if _, _, err := contract.Call("verify", []interface{}{sha256Init, block}, provider, signer, nil); err == nil {
		t.Fatalf("expected wrong-digest verify call to be rejected, but it succeeded")
	}
}
