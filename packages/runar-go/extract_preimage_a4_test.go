package runar

import (
	"bytes"
	"testing"
)

// A-4: the Go SDK used to omit extractHashPrevouts / extractOutpoint /
// extractScriptCode / extractHashSequence (the four preimage fields other
// tiers already stubbed). Native merge tests could not even compile.
func TestA4_PreimageExtractorsExist(t *testing.T) {
	pre := SigHashPreimage(make([]byte, 181))
	if got := ExtractHashPrevouts(pre); len(got) != 32 {
		t.Fatalf("ExtractHashPrevouts len = %d, want 32", len(got))
	}
	if got := ExtractHashSequence(pre); len(got) != 32 {
		t.Fatalf("ExtractHashSequence len = %d, want 32", len(got))
	}
	if got := ExtractOutpoint(pre); len(got) != 36 {
		t.Fatalf("ExtractOutpoint len = %d, want 36", len(got))
	}
	_ = ExtractScriptCode(pre)
	if got := ExtractSequence(pre); got != 0xfffffffe {
		t.Fatalf("ExtractSequence = %d, want 0xfffffffe", got)
	}
	zeros := ByteString(make([]byte, 72))
	if !bytes.Equal([]byte(ExtractHashPrevouts(pre)), []byte(Hash256(zeros))) {
		t.Fatal("ExtractHashPrevouts must match Hash256(72 zero bytes) in test mode")
	}
}
