package runar

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestSha256Compress_ABC(t *testing.T) {
	state, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	block, _ := hex.DecodeString("6162638000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000018")
	expected := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	result := Sha256Compress(ByteString(state), ByteString(block))
	got := hex.EncodeToString([]byte(result))
	if got != expected {
		t.Fatalf("Sha256Compress(IV, padded abc)\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestSha256Compress_Empty(t *testing.T) {
	state, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	block, _ := hex.DecodeString("8000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	result := Sha256Compress(ByteString(state), ByteString(block))
	got := hex.EncodeToString([]byte(result))
	if got != expected {
		t.Fatalf("Sha256Compress(IV, padded empty)\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestSha256Finalize_ABC(t *testing.T) {
	state, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	remaining := []byte("abc")
	expected := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	result := Sha256Finalize(ByteString(state), ByteString(remaining), 24)
	got := hex.EncodeToString([]byte(result))
	if got != expected {
		t.Fatalf("Sha256Finalize(IV, abc, 24)\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestSha256Finalize_Empty(t *testing.T) {
	state, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	result := Sha256Finalize(ByteString(state), ByteString(""), 0)
	got := hex.EncodeToString([]byte(result))
	if got != expected {
		t.Fatalf("Sha256Finalize(IV, empty, 0)\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestSha256Finalize_CrossVerify(t *testing.T) {
	iv, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	messages := []string{"", "abc", "hello world"}
	for _, msg := range messages {
		t.Run(msg, func(t *testing.T) {
			finalized := Sha256Finalize(ByteString(iv), ByteString(msg), int64(len(msg)*8))
			hashed := Sha256Hash(ByteString(msg))
			if finalized != hashed {
				t.Fatalf("Sha256Finalize != Sha256Hash for %q\n  finalize: %x\n  hash:     %x",
					msg, []byte(finalized), []byte(hashed))
			}
		})
	}
}

// F-142: the compiled script accepts 0..119 bytes of `remaining` (its
// two-block path pads to 120) and aborts on more. Proves the boundary lengths
// equal standard SHA-256 over a chained state and that 120 is refused instead
// of returning a digest the chain never reproduces. Does not prove anything
// about the compiled script itself.
func f142ChainedState() (ByteString, []byte) {
	iv, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	first := make([]byte, 64)
	for i := range first {
		first[i] = byte(i)
	}
	return Sha256Compress(ByteString(iv), ByteString(first)), first
}

func TestSha256Finalize_BoundaryLengthsMatchStandardSha256(t *testing.T) {
	state, first := f142ChainedState()
	for _, n := range []int{0, 1, 55, 56, 63, 64, 65, 100, 118, 119} {
		tail := make([]byte, n)
		for i := range tail {
			tail[i] = byte(0xA0 + i)
		}
		got := Sha256Finalize(state, ByteString(tail), int64((64+n)*8))
		want := Sha256Hash(ByteString(append(append([]byte(nil), first...), tail...)))
		if got != want {
			t.Fatalf("remaining len %d: got %x want %x", n, []byte(got), []byte(want))
		}
	}
}

func TestSha256Finalize_Refuses120Bytes(t *testing.T) {
	state, _ := f142ChainedState()
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(fmt.Sprint(r), "Sha256Finalize: remaining must be 0-119 bytes") {
			t.Fatalf("expected refusal panic for 120-byte remaining, got %v", r)
		}
	}()
	got := Sha256Finalize(state, ByteString(make([]byte, 120)), 184*8)
	t.Fatalf("120-byte remaining returned %x; the compiled script aborts", []byte(got))
}
