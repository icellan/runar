package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

var (
	alice   = runar.Alice.PubKey
	bob     = runar.Bob.PubKey
	tokenId = runar.ByteString("test-token-001")
)

func aliceSig() runar.Sig { return runar.SignTestMessage(runar.Alice.PrivKey) }

func newToken(owner runar.PubKey, balance runar.Bigint) *FungibleToken {
	return &FungibleToken{Owner: owner, Balance: balance, MergeBalance: 0, TokenId: tokenId}
}

func TestFungibleToken_Transfer(t *testing.T) {
	c := newToken(alice, 100)
	c.Transfer(aliceSig(), bob, 30, 1000)
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
	newToken(alice, 100).Transfer(aliceSig(), bob, 0, 1000)
}

func TestFungibleToken_Send(t *testing.T) {
	c := newToken(alice, 100)
	c.Send(aliceSig(), bob, 1000)
	if len(c.Outputs()) != 1 {
		t.Fatalf("expected 1 output, got %d", len(c.Outputs()))
	}
}

func TestFungibleToken_Merge(t *testing.T) {
	c := newToken(alice, 50)
	// allPrevouts = 72 zero bytes (two 36-byte zero outpoints),
	// consistent with mock ExtractHashPrevouts and ExtractOutpoint.
	allPrevouts := runar.ByteString(make([]byte, 72))
	c.Merge(aliceSig(), 150, allPrevouts, 1000)
	out := c.Outputs()
	if len(out) != 1 {
		t.Fatalf("expected 1 output, got %d", len(out))
	}
	// ExtractOutpoint returns 36 zero bytes == first outpoint, so we're input 0:
	// balance slot gets myBalance (50), mergeBalance slot gets otherBalance (150).
	if out[0].Values[1] != runar.Bigint(50) {
		t.Errorf("output balance: expected 50, got %v", out[0].Values[1])
	}
	if out[0].Values[2] != runar.Bigint(150) {
		t.Errorf("output mergeBalance: expected 150, got %v", out[0].Values[2])
	}
}

func TestFungibleToken_Merge_NegativeOtherBalance_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	allPrevouts := runar.ByteString(make([]byte, 72))
	newToken(alice, 100).Merge(aliceSig(), -1, allPrevouts, 1000)
}

func TestFungibleToken_Merge_TamperedPrevouts_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for tampered prevouts")
		}
	}()
	tampered := make([]byte, 72)
	for i := range tampered {
		tampered[i] = 0xff
	}
	newToken(alice, 30).Merge(aliceSig(), 70, runar.ByteString(tampered), 1000)
}

func TestFungibleToken_Merge_PreExistingMergeBalance(t *testing.T) {
	c := &FungibleToken{Owner: alice, Balance: 20, MergeBalance: 10, TokenId: tokenId}
	allPrevouts := runar.ByteString(make([]byte, 72))
	c.Merge(aliceSig(), 50, allPrevouts, 1000)
	out := c.Outputs()
	if len(out) != 1 {
		t.Fatalf("expected 1 output, got %d", len(out))
	}
	// myBalance = 20 + 10 = 30
	if out[0].Values[1] != runar.Bigint(30) {
		t.Errorf("output balance: expected 30, got %v", out[0].Values[1])
	}
	if out[0].Values[2] != runar.Bigint(50) {
		t.Errorf("output mergeBalance: expected 50, got %v", out[0].Values[2])
	}
}

func TestFungibleToken_Transfer_ExactBalance(t *testing.T) {
	c := newToken(alice, 100)
	c.Transfer(aliceSig(), bob, 100, 1000)
	out := c.Outputs()
	if len(out) != 1 {
		t.Fatalf("expected 1 output, got %d", len(out))
	}
	if out[0].Values[1] != runar.Bigint(100) {
		t.Errorf("output[0] balance: expected 100, got %v", out[0].Values[1])
	}
}

func TestFungibleToken_Transfer_UsesMergeBalance(t *testing.T) {
	c := &FungibleToken{Owner: alice, Balance: 60, MergeBalance: 40, TokenId: tokenId}
	c.Transfer(aliceSig(), bob, 80, 1000)
	out := c.Outputs()
	if len(out) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(out))
	}
	if out[0].Values[1] != runar.Bigint(80) {
		t.Errorf("output[0] balance: expected 80, got %v", out[0].Values[1])
	}
	if out[1].Values[1] != runar.Bigint(20) {
		t.Errorf("output[1] balance: expected 20, got %v", out[1].Values[1])
	}
}

func TestFungibleToken_Send_UsesMergeBalance(t *testing.T) {
	c := &FungibleToken{Owner: alice, Balance: 60, MergeBalance: 40, TokenId: tokenId}
	c.Send(aliceSig(), bob, 1000)
	out := c.Outputs()
	if len(out) != 1 {
		t.Fatalf("expected 1 output, got %d", len(out))
	}
	if out[0].Values[1] != runar.Bigint(100) {
		t.Errorf("output balance: expected 100, got %v", out[0].Values[1])
	}
}

func TestFungibleToken_Compile(t *testing.T) {
	if err := runar.CompileCheck("FungibleTokenExample.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
