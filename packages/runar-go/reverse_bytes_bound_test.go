package runar

import (
	"strings"
	"testing"
)

// Since D12 BM-F3 every compiler's reverseBytes ends in OP_0 OP_EQUALVERIFY,
// so the script ABORTS on an input longer than 520 bytes. The native mock
// must refuse the same input rather than reverse it in full.
func TestReverseBytesBound(t *testing.T) {
	for _, n := range []int{0, 1, 520} {
		src := make([]byte, n)
		for i := range src {
			src[i] = byte(i)
		}
		got := []byte(ReverseBytes(ByteString(src)))
		if len(got) != n {
			t.Fatalf("ReverseBytes(%d B) returned %d bytes", n, len(got))
		}
		for i := range src {
			if got[i] != src[n-1-i] {
				t.Fatalf("ReverseBytes(%d B) wrong at %d", n, i)
			}
		}
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("ReverseBytes(521 B) must panic, the script aborts")
		}
		if !strings.Contains(r.(string), "520") {
			t.Fatalf("panic does not name the 520-byte bound: %v", r)
		}
	}()
	ReverseBytes(ByteString(make([]byte, 521)))
}
