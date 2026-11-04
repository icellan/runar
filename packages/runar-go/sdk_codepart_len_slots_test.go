package runar

// N-051 (TaffyTail) — deploy-time `codePartLenSlots`.
//
// The compiler emits the SIZE(_codePart) pin as an EQUALITY (9c) always. When
// a variable-width readonly constructor arg is baked into the code part the
// compiler cannot know the deployed length, so it records the 4-byte length
// field as a `codePartLenSlots` entry and the SDK writes the deployed length
// (inscription envelope included) into it. The reference data is the TS
// compiler's TaffyTailVault artifact (fold OFF) and the TS SDK's output for it.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type taffyTailExpected struct {
	ConstructorArgs  []string `json:"constructorArgs"`
	CodePartLenSlots []struct {
		ByteOffset int `json:"byteOffset"`
	} `json:"codePartLenSlots"`
	CodePartHex string `json:"codePartHex"`
	CodePartLen int    `json:"codePartLen"`
	Inscription struct {
		ContentType string `json:"contentType"`
		Data        string `json:"data"`
	} `json:"inscription"`
	InscribedCodePartHex string `json:"inscribedCodePartHex"`
	InscribedCodePartLen int    `json:"inscribedCodePartLen"`
	LockingScriptHex     string `json:"lockingScriptHex"`
}

func loadTaffyTail(t *testing.T) (*RunarArtifact, *taffyTailExpected) {
	t.Helper()
	raw, err := os.ReadFile("testdata/taffytail-vault-artifact.json")
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(raw, &art); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	raw, err = os.ReadFile("testdata/taffytail-vault-expected.json")
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}
	var exp taffyTailExpected
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatalf("parse expected: %v", err)
	}
	return &art, &exp
}

func newTaffyTail(art *RunarArtifact, exp *taffyTailExpected) *RunarContract {
	args := make([]interface{}, len(exp.ConstructorArgs))
	for i, a := range exp.ConstructorArgs {
		args[i] = a
	}
	return NewRunarContract(art, args)
}

func TestN051_ArtifactParsesCodePartLenSlots(t *testing.T) {
	art, _ := loadTaffyTail(t)
	if len(art.CodePartLenSlots) != 1 || art.CodePartLenSlots[0].ByteOffset != 947 {
		t.Fatalf("codePartLenSlots = %+v, want [{ByteOffset:947}]", art.CodePartLenSlots)
	}
}

func TestN051_BuildPatchesDeployedCodePartLength(t *testing.T) {
	art, exp := loadTaffyTail(t)
	c := newTaffyTail(art, exp)

	if got := c.getCodePartHex(); got != exp.CodePartHex {
		t.Fatalf("code part diverges from the TS SDK: %s", firstHexDiff(got, exp.CodePartHex))
	}
	if n := len(exp.CodePartHex) / 2; n != exp.CodePartLen {
		t.Fatalf("fixture inconsistent: %d vs %d", n, exp.CodePartLen)
	}
	if got := c.GetLockingScript(); got != exp.LockingScriptHex {
		t.Fatalf("locking script diverges from the TS SDK: %s", firstHexDiff(got, exp.LockingScriptHex))
	}
	// The pin in the built code is an equality on the built length.
	pins := decodeExactCodePartLenPins(c.buildCodeScript())
	if len(pins) != 1 || pins[0] != exp.CodePartLen {
		t.Fatalf("decoded pins %v, want [%d]", pins, exp.CodePartLen)
	}
}

func TestN051_InscriptionPatchedIntoDeployTimePin(t *testing.T) {
	art, exp := loadTaffyTail(t)
	c := newTaffyTail(art, exp)

	if _, err := c.WithInscription(&Inscription{ContentType: exp.Inscription.ContentType, Data: exp.Inscription.Data}); err != nil {
		t.Fatalf("a deploy-time pin is patched to the inscribed length; the attach must be accepted: %v", err)
	}
	if got := c.getCodePartHex(); got != exp.InscribedCodePartHex {
		t.Fatalf("inscribed code part diverges from the TS SDK: %s", firstHexDiff(got, exp.InscribedCodePartHex))
	}
	if n := len(c.getCodePartHex()) / 2; n != exp.InscribedCodePartLen {
		t.Fatalf("inscribed code part is %d bytes, want %d", n, exp.InscribedCodePartLen)
	}
	pins := decodeExactCodePartLenPins(c.buildCodeScript())
	if len(pins) != 1 || pins[0] != exp.InscribedCodePartLen {
		t.Fatalf("decoded pins %v, want [%d]", pins, exp.InscribedCodePartLen)
	}
}

func TestN051_CorruptedSlotOffsetRefused(t *testing.T) {
	art, exp := loadTaffyTail(t)
	art.CodePartLenSlots[0].ByteOffset = 946 // one byte off the length field
	c := newTaffyTail(art, exp)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("a slot that does not point at a length field must be refused")
		}
		msg := ""
		switch v := r.(type) {
		case error:
			msg = v.Error()
		case string:
			msg = v
		}
		if !strings.Contains(msg, "does not point at a verify_code_part_len length field") {
			t.Fatalf("refused for the wrong reason: %v", r)
		}
	}()
	_ = c.GetLockingScript()
}

func TestN051_MatchesArtifactChecksDeployedLengthField(t *testing.T) {
	art, exp := loadTaffyTail(t)
	if !mustMatchesArtifact(t, art, exp.LockingScriptHex) {
		t.Fatalf("MatchesArtifact must accept the honestly deployed TaffyTail locking script")
	}

	// The length field sits at template 947 + the growth of the slots before
	// it (only the `owner` pubkey at 465: 34 bytes for a 1-byte placeholder).
	at := (947 + 33) * 2
	if exp.LockingScriptHex[at-2:at] != "04" || exp.LockingScriptHex[at+8:at+14] != "819c69" {
		t.Fatalf("test offset does not address the pin field")
	}
	tampered := exp.LockingScriptHex[:at] + "ffff0000" + exp.LockingScriptHex[at+8:]
	if mustMatchesArtifact(t, art, tampered) {
		t.Fatalf("MatchesArtifact must reject a script whose code-part length field is not the code-part length")
	}

	// A truncated trailing segment must not match either.
	opRet := FindLastOpReturn(exp.LockingScriptHex)
	short := exp.LockingScriptHex[:opRet-2] + exp.LockingScriptHex[opRet:]
	if mustMatchesArtifact(t, art, short) {
		t.Fatalf("MatchesArtifact must reject a code part shorter than the template")
	}
}

func firstHexDiff(got, want string) string {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			lo := i - 10
			if lo < 0 {
				lo = 0
			}
			hi := i + 10
			if hi > n {
				hi = n
			}
			return fmt.Sprintf("first diff at byte %d: got ...%s... want ...%s...", i/2, got[lo:hi], want[lo:hi])
		}
	}
	return fmt.Sprintf("lengths differ: got %d bytes, want %d", len(got)/2, len(want)/2)
}
