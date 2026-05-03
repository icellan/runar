//go:build integration

package integration

import (
	"strings"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// SHA-256 finalize integration tests — port of integration/ts/sha256-finalize.test.ts.
//
// sha256Finalize applies SHA-256 padding internally and runs 1 or 2
// compressions depending on the remaining message length. These tests
// cross-verify the finalize result against OP_SHA256 over the same message,
// and exercise the chained compress + finalize path for messages that span
// at least two SHA-256 blocks.

const sha256FinalizeCrossSource = `
import { SmartContract, assert, sha256Finalize, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256FinalizeCross extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(message: ByteString, msgBitLen: bigint) {
    const computed = sha256Finalize(this.initState, message, msgBitLen);
    const native = sha256(message);
    assert(computed === native);
  }
}
`

const sha256FinalizeChainedSource = `
import { SmartContract, assert, sha256Compress, sha256Finalize, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256FinalizeChained extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(message: ByteString, firstBlock: ByteString, remaining: ByteString, msgBitLen: bigint) {
    const mid = sha256Compress(this.initState, firstBlock);
    const computed = sha256Finalize(mid, remaining, msgBitLen);
    const native = sha256(message);
    assert(computed === native);
  }
}
`

var (
	sha256FinalizeCrossArt     *runar.RunarArtifact
	sha256FinalizeCrossArtOnce sync.Once
	sha256FinalizeChainArt     *runar.RunarArtifact
	sha256FinalizeChainArtOnce sync.Once
)

func getSha256FinalizeCrossArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	sha256FinalizeCrossArtOnce.Do(func() {
		var err error
		sha256FinalizeCrossArt, err = helpers.CompileSourceStringToSDKArtifact(
			sha256FinalizeCrossSource, "Sha256FinalizeCross.runar.ts", map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile Sha256FinalizeCross: %v", err)
		}
	})
	return sha256FinalizeCrossArt
}

func getSha256FinalizeChainedArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	sha256FinalizeChainArtOnce.Do(func() {
		var err error
		sha256FinalizeChainArt, err = helpers.CompileSourceStringToSDKArtifact(
			sha256FinalizeChainedSource, "Sha256FinalizeChained.runar.ts", map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile Sha256FinalizeChained: %v", err)
		}
	})
	return sha256FinalizeChainArt
}

func deployAndVerifyFinalize(t *testing.T, artifact *runar.RunarArtifact, args []interface{}) {
	t.Helper()
	contract := runar.NewRunarContract(artifact, []interface{}{sha256Init})

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
	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1000000}); err != nil {
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
// Single-block messages (remaining ≤ 55 bytes)
// ---------------------------------------------------------------------------

func TestSha256Finalize_SingleBlockMessages(t *testing.T) {
	artifact := getSha256FinalizeCrossArtifact(t)
	t.Logf("Sha256FinalizeCross script: %d bytes", len(artifact.Script)/2)

	cases := []struct {
		name string
		hex  string
		bits int64
	}{
		{"abc_3_bytes", "616263", 24},
		{"empty_0_bytes", "", 0},
		{"single_byte", "42", 8},
		{"max_55_bytes", strings.Repeat("aa", 55), 440},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deployAndVerifyFinalize(t, artifact, []interface{}{tc.hex, tc.bits})
		})
	}
}

// ---------------------------------------------------------------------------
// Two-block messages (56 ≤ remaining ≤ 119 bytes)
// ---------------------------------------------------------------------------

func TestSha256Finalize_TwoBlockMessages(t *testing.T) {
	artifact := getSha256FinalizeCrossArtifact(t)

	cases := []struct {
		name string
		hex  string
		bits int64
	}{
		{"min_56_bytes", strings.Repeat("bb", 56), 448},
		{"64_bytes", strings.Repeat("cc", 64), 512},
		{"100_bytes", strings.Repeat("dd", 100), 800},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deployAndVerifyFinalize(t, artifact, []interface{}{tc.hex, tc.bits})
		})
	}
}

// ---------------------------------------------------------------------------
// Chained: sha256Compress first 64 bytes, then sha256Finalize the remainder
// ---------------------------------------------------------------------------

func TestSha256Finalize_ChainedCompress120Bytes(t *testing.T) {
	artifact := getSha256FinalizeChainedArtifact(t)
	msgHex := strings.Repeat("ee", 120)
	firstBlock := msgHex[:128]
	remaining := msgHex[128:]
	deployAndVerifyFinalize(t, artifact, []interface{}{msgHex, firstBlock, remaining, int64(960)})
}
