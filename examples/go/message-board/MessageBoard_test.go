package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func newBoard() *MessageBoard {
	return &MessageBoard{
		Message: runar.ByteString(""),
		Owner:   runar.Alice.PubKey,
	}
}

func TestMessageBoard_Post(t *testing.T) {
	b := newBoard()
	b.Post(runar.ByteString("hello"))
	if string(b.Message) != "hello" {
		t.Errorf("expected Message='hello', got %q", b.Message)
	}
}

func TestMessageBoard_PostMultiple(t *testing.T) {
	b := newBoard()
	b.Post(runar.ByteString("first"))
	b.Post(runar.ByteString("second"))
	if string(b.Message) != "second" {
		t.Errorf("expected Message='second', got %q", b.Message)
	}
}

func TestMessageBoard_Burn(t *testing.T) {
	b := newBoard()
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	b.Burn(sig)
}

func TestMessageBoard_BurnWrongKey_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong signature")
		}
	}()
	b := newBoard()
	sig := runar.SignTestMessage(runar.Bob.PrivKey)
	b.Burn(sig)
}

func TestMessageBoard_Compile(t *testing.T) {
	if err := runar.CompileCheck("MessageBoard.runar.go"); err != nil {
		t.Fatalf("Runar compile check failed: %v", err)
	}
}

func TestMessageBoard_OwnerUnchanged(t *testing.T) {
	b := newBoard()
	originalOwner := b.Owner
	b.Post(runar.ByteString("test"))
	if string(b.Owner) != string(originalOwner) {
		t.Error("expected Owner to remain unchanged after post")
	}
}

func TestMessageBoard_EmptyInitialMessage(t *testing.T) {
	b := &MessageBoard{Message: runar.ByteString(""), Owner: runar.Alice.PubKey}
	if string(b.Message) != "" {
		t.Errorf("expected empty message, got %q", b.Message)
	}
}

func TestMessageBoard_PostToEmpty(t *testing.T) {
	b := &MessageBoard{Message: runar.ByteString(""), Owner: runar.Alice.PubKey}
	b.Post(runar.ByteString("48656c6c6f"))
	if string(b.Message) != "48656c6c6f" {
		t.Errorf("expected '48656c6c6f', got %q", b.Message)
	}
}
