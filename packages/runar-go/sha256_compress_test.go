package runar

import (
	"encoding/hex"
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
