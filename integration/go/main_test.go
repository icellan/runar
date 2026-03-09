//go:build integration

package integration

import (
	"fmt"
	"os"
	"testing"

	"runar-integration/helpers"
)

func TestMain(m *testing.M) {
	nodeType := helpers.NodeType()
	fmt.Fprintf(os.Stderr, "Integration tests using node type: %s\n", nodeType)

	if !helpers.IsNodeAvailable() {
		fmt.Fprintln(os.Stderr, "Regtest node not running. Skipping integration tests.")
		if helpers.IsTeranode() {
			fmt.Fprintln(os.Stderr, "Start with: cd integration && ./teranode.sh start")
		} else {
			fmt.Fprintln(os.Stderr, "Start with: cd integration && ./regtest.sh start")
		}
		os.Exit(0)
	}

	// Mine initial blocks so coinbase UTXOs mature (100 block maturity).
	// On Teranode regtest, GenesisActivationHeight=10000 (hardcoded in go-chaincfg),
	// so we need height > 10000 for post-Genesis rules. The teranode.sh start script
	// pre-mines these blocks, but we check and top up if needed.
	currentHeight, err := helpers.GetBlockCount()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get block count: %v\n", err)
		os.Exit(1)
	}

	targetHeight := 101 // SV Node: genesis at height 1
	if helpers.IsTeranode() {
		targetHeight = 10_101 // regtest genesis at 10000 + 101 for coinbase maturity
	}

	blocksNeeded := targetHeight - currentHeight
	if blocksNeeded > 0 {
		fmt.Fprintf(os.Stderr, "Mining %d blocks (current height: %d, target: %d)...\n", blocksNeeded, currentHeight, targetHeight)
		if err := helpers.Mine(blocksNeeded); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to mine initial blocks: %v\n", err)
			os.Exit(1)
		}
	}

	os.Exit(m.Run())
}
