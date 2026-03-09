package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func newNFT(owner runar.PubKey) *SimpleNFT {
	return &SimpleNFT{
		Owner:    owner,
		TokenId:  runar.ByteString("unique-nft-001"),
		Metadata: runar.ByteString("ipfs://QmTest"),
	}
}

func TestSimpleNFT_Transfer(t *testing.T) {
	alice := runar.PubKey("alice_pubkey_33bytes_placeholder!")
	bob := runar.PubKey("bob___pubkey_33bytes_placeholder!")
	c := newNFT(alice)
	c.Transfer(runar.MockSig(), bob, 1000)
	if len(c.Outputs()) != 1 {
		t.Fatalf("expected 1 output, got %d", len(c.Outputs()))
	}
}

func TestSimpleNFT_Burn(t *testing.T) {
	alice := runar.PubKey("alice_pubkey_33bytes_placeholder!")
	c := newNFT(alice)
	c.Burn(runar.MockSig())
	if len(c.Outputs()) != 0 {
		t.Errorf("expected 0 outputs after burn, got %d", len(c.Outputs()))
	}
}

func TestSimpleNFT_Compile(t *testing.T) {
	if err := runar.CompileCheck("NFTExample.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
