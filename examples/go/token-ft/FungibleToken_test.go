package contract

import (
	"testing"
	"runar"
)

var (
	alice   = runar.PubKey("alice_pubkey_33bytes_placeholder!")
	bob     = runar.PubKey("bob___pubkey_33bytes_placeholder!")
	tokenId = runar.ByteString("test-token-001")
)

func newToken(owner runar.PubKey, balance runar.Bigint) *FungibleToken {
	return &FungibleToken{Owner: owner, Balance: balance, TokenId: tokenId}
}

func TestFungibleToken_Transfer(t *testing.T) {
	c := newToken(alice, 100)
	c.Transfer(runar.MockSig(), bob, 30, 1000)
	out := c.Outputs()
	if len(out) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(out))
	}
	if out[0].Values[0] != bob {
		t.Error("output[0] owner should be bob")
	}
	if out[0].Values[1] != runar.Bigint(30) {
		t.Errorf("output[0] balance: expected 30, got %v", out[0].Values[1])
	}
	if out[1].Values[1] != runar.Bigint(70) {
		t.Errorf("output[1] balance: expected 70, got %v", out[1].Values[1])
	}
}

func TestFungibleToken_Transfer_ZeroAmount_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	newToken(alice, 100).Transfer(runar.MockSig(), bob, 0, 1000)
}

func TestFungibleToken_Send(t *testing.T) {
	c := newToken(alice, 100)
	c.Send(runar.MockSig(), bob, 1000)
	if len(c.Outputs()) != 1 {
		t.Fatalf("expected 1 output, got %d", len(c.Outputs()))
	}
}

func TestFungibleToken_Merge(t *testing.T) {
	c := newToken(alice, 50)
	c.Merge(runar.MockSig(), 200, 1000)
	if len(c.Outputs()) != 1 {
		t.Fatalf("expected 1 output, got %d", len(c.Outputs()))
	}
}

func TestFungibleToken_Merge_LessThanBalance_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	newToken(alice, 100).Merge(runar.MockSig(), 50, 1000)
}

func TestFungibleToken_Compile(t *testing.T) {
	if err := runar.CompileCheck("FungibleTokenExample.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
