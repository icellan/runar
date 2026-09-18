//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	runar "github.com/icellan/runar/packages/runar-go"
)

type TypedArg struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type InscriptionInput struct {
	ContentType string `json:"contentType"`
	Data        string `json:"data"`
}

// WalletDeployInput drives the tier's WALLET funding path (R-062) instead of
// only building the locking script, so all seven tiers can be asked to agree
// on accept-vs-refuse for one artifact.
type WalletDeployInput struct {
	Satoshis           int64    `json:"satoshis,omitempty"`
	AcknowledgeUnsound []string `json:"acknowledgeUnsound,omitempty"`
}

type Input struct {
	Artifact        json.RawMessage  `json:"artifact"`
	ConstructorArgs []TypedArg       `json:"constructorArgs"`
	Inscription     *InscriptionInput `json:"inscription,omitempty"`
	WalletDeploy    *WalletDeployInput `json:"walletDeploy,omitempty"`
}

// stubWallet is the smallest BRC-100 wallet that can fund a deploy.
type stubWallet struct{}

func (stubWallet) GetPublicKey(protocolID [2]interface{}, keyID string) (string, error) {
	return "02" + "11111111111111111111111111111111", nil
}

func (stubWallet) CreateSignature(hash []byte, protocolID [2]interface{}, keyID string) ([]byte, error) {
	return []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, nil
}

func (stubWallet) CreateAction(description string, outputs []runar.WalletActionOutput) (*runar.WalletActionResult, error) {
	return &runar.WalletActionResult{Txid: "ab", RawTx: ""}, nil
}

func (stubWallet) ListOutputs(basket string, tags []string, limit int) ([]runar.WalletOutput, error) {
	return nil, nil
}

func convertArg(arg TypedArg) interface{} {
	switch arg.Type {
	case "bigint", "int":
		n := new(big.Int)
		n.SetString(arg.Value, 10)
		return n
	// `boolean` is the spelling the compiler's ABI carries; `bool` is the
	// alias some frontends use. Accept both (R-248).
	case "bool", "boolean":
		return arg.Value == "true"
	default:
		return arg.Value
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: go-sdk-tool <input.json>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	var artifact runar.RunarArtifact
	if err := json.Unmarshal(input.Artifact, &artifact); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading artifact: %v\n", err)
		os.Exit(1)
	}

	args := make([]interface{}, len(input.ConstructorArgs))
	for i, a := range input.ConstructorArgs {
		args[i] = convertArg(a)
	}

	contract := runar.NewRunarContract(&artifact, args)
	if input.Inscription != nil {
		// N-043: a refused attach is a RESULT, not a crash — exit non-zero with
		// the reason on stderr so the runner can compare the refusal verdict
		// across all seven tiers.
		if _, err := contract.WithInscription(&runar.Inscription{
			ContentType: input.Inscription.ContentType,
			Data:        input.Inscription.Data,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}
	if input.WalletDeploy != nil {
		// R-062: a refusal is a RESULT, not a crash — exit non-zero with the
		// reason on stderr so the runner can compare the verdict across all
		// seven tiers.
		wp := runar.NewWalletProvider(runar.WalletProviderOptions{
			Wallet: stubWallet{},
			Basket: "conformance",
		})
		contract.Connect(wp, nil)
		satoshis := input.WalletDeploy.Satoshis
		if satoshis <= 0 {
			satoshis = 1
		}
		if _, err := contract.DeployWithWallet(&runar.DeployWithWalletOptions{
			Satoshis:           satoshis,
			AcknowledgeUnsound: input.WalletDeploy.AcknowledgeUnsound,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}

	fmt.Print(contract.GetLockingScript())
}
