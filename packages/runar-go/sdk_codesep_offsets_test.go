package runar

import (
	"reflect"
	"testing"
)

// Issue #42: terminal-method sighash subscript byte-walker.
//
// The on-chain script trims its sighash subscript at the method's
// OP_CODESEPARATOR. findCodesepOffsets must recover the true byte position by
// walking the script, correctly skipping push-data (which may itself contain a
// 0xab byte) and all BSV push opcodes.

func TestFindCodesepOffsets_RealBytePosition(t *testing.T) {
	// 51            OP_1
	// 02 ab cd      push 2 bytes (0xab inside push-data, must be ignored)
	// ab            OP_CODESEPARATOR  <- real, byte offset 4
	// ac            OP_CHECKSIG
	got := findCodesepOffsets("5102abcdabac")
	want := []int{4}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findCodesepOffsets = %v, want %v (must skip 0xab inside push-data)", got, want)
	}
}

func TestFindCodesepOffsets_PushData1(t *testing.T) {
	// 4c (OP_PUSHDATA1) 02 (len) abab (data, contains 0xab) ab (real codesep)
	got := findCodesepOffsets("4c02ababab")
	want := []int{4}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findCodesepOffsets = %v, want %v", got, want)
	}
}

func TestSighashSubscriptTrimmedAtRealCodesepBytePosition(t *testing.T) {
	// Issue #42: the user-sig subscript for a stateful terminal method
	// (e.g. Auction.close) must be trimmed at the real on-chain codesep byte
	// position recovered by findCodesepOffsets — even when push-data contains a
	// stray 0xab byte.
	fullScript := "5102abcdabac" // real codesep at byte index 4
	offsets := findCodesepOffsets(fullScript)
	if len(offsets) != 1 || offsets[0] != 4 {
		t.Fatalf("expected codesep at byte 4, got %v", offsets)
	}
	codeSepIdx := offsets[0]

	subscript := fullScript
	if codeSepIdx >= 0 {
		subscript = subscript[(codeSepIdx+1)*2:]
	}
	if subscript != "ac" {
		t.Fatalf("subscript = %q, want %q (only OP_CHECKSIG after the codesep)", subscript, "ac")
	}
}
