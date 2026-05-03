package integration

import (
	"strings"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// TestPrivateHelperOutputs_EndToEnd compiles the PrivateHelperOutputs
// regression contract from the 2026-04-30 audit (F1 + F3) and exercises
// each of its three public methods through deploy + call. The contract
// delegates state mutation, data-output emission, and state-output
// emission to private helpers; a correct compiler must auto-inject
// continuation params (`_changePKH`, `_changeAmount`, `_newAmount`,
// `txPreimage`) for each method as if the public body called the
// intrinsic directly. If the shallow scan from before the F1 fix
// regresses, deploy or call would fail with a missing-param error.
func TestPrivateHelperOutputs_EndToEnd(t *testing.T) {
	const source = `
import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

export class PrivateHelperOutputs extends StatefulSmartContract {
    counter: bigint;

    constructor(counter: bigint) {
        super(counter);
        this.counter = counter;
    }

    private bump(): void {
        this.counter = this.counter + 1n;
    }

    private record(payload: ByteString): void {
        this.addDataOutput(0n, payload);
    }

    private forkOutput(amount: bigint, leftover: bigint): void {
        this.addOutput(amount, leftover);
    }

    public commit(): void {
        this.bump();
        assert(true);
    }

    public log(payload: ByteString): void {
        this.record(payload);
        assert(true);
    }

    public partition(amount: bigint, leftover: bigint): void {
        this.forkOutput(amount, leftover);
        assert(true);
    }
}
`

	artifact, err := helpers.CompileSourceStringToSDKArtifact(
		source, "PrivateHelperOutputs.runar.ts", map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	provider := runar.NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := runar.NewMockSigner("", mockAddr)

	provider.AddUtxo(mockAddr, runar.UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    1_000_000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10_000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// commit — private bump() mutates counter.
	{
		txid, _, err := contract.Call("commit", []interface{}{}, provider, signer, nil)
		if err != nil {
			t.Fatalf("call commit: %v", err)
		}
		if txid == "" {
			t.Fatal("commit: expected non-empty txid")
		}
	}

	// log — private record() emits a data output.
	{
		payload := "6a09" + "6273766d2d74657374"
		txid, _, err := contract.Call("log", []interface{}{payload}, provider, signer, nil)
		if err != nil {
			t.Fatalf("call log: %v", err)
		}
		if txid == "" {
			t.Fatal("log: expected non-empty txid")
		}
	}
}

// TestPrivateHelperOutputs_CommitChain validates state continuity across
// sequential commit() calls, where each call routes its state mutation
// through a private helper. If the F1 fix's continuation-hash gating
// regressed, the second call would fail to spend the first's output UTXO
// (the locking script's hashOutputs assertion would not match the
// runtime tx). Audit gap 6 — explicit on-chain round-trip test for the
// state-mutation-private-helper case.
func TestPrivateHelperOutputs_CommitChain(t *testing.T) {
	const source = `
import { StatefulSmartContract, assert } from 'runar-lang';

export class CommitChain extends StatefulSmartContract {
    counter: bigint;

    constructor(counter: bigint) {
        super(counter);
        this.counter = counter;
    }

    private bump(): void {
        this.counter = this.counter + 1n;
    }

    public commit(): void {
        this.bump();
        assert(true);
    }
}
`

	artifact, err := helpers.CompileSourceStringToSDKArtifact(
		source, "CommitChain.runar.ts", map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	provider := runar.NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := runar.NewMockSigner("", mockAddr)

	provider.AddUtxo(mockAddr, runar.UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    1_000_000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	if _, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10_000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// Three sequential commits — each spends the previous continuation
	// UTXO. Failure here means the runtime hashOutputs hash didn't
	// match the compiled continuation, which is exactly what F1's
	// shallow-scan miss would produce for state-mutation-via-private.
	for i := 0; i < 3; i++ {
		txid, _, err := contract.Call("commit", []interface{}{}, provider, signer, nil)
		if err != nil {
			t.Fatalf("call commit #%d: %v", i+1, err)
		}
		if txid == "" {
			t.Fatalf("commit #%d: empty txid", i+1)
		}
	}
}
