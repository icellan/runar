package compiler

// N-051 (TaffyTail) — the SIZE(_codePart) pin is ALWAYS an equality.
//
// A stateful contract with a variable-length state section authenticates the
// spender-supplied _codePart witness with the nine-byte run
//
//	76 | 04 LL LL LL LL | 81 | cmp | 69
//	OP_DUP  <len LE32>    OP_BIN2NUM  cmp  OP_VERIFY
//
// When a readonly constructor arg of variable width (a ByteString, a bigint)
// is baked into the code part the compiler cannot know the deployed length.
// It used to emit cmp = a2 (OP_GREATERTHANOREQUAL), a lower bound, which lets
// a stranger claim a _codePart TRUNCATED at a 0x6a byte inside the baked value
// and plant attacker code in the continuation. The fix: cmp is always 9c
// (OP_NUMEQUAL) and the length field is recorded as a codePartLenSlots entry
// the SDK fills with the deployed length.

import (
	"encoding/json"
	"strings"
	"testing"
)

const taffyTailVaultSource = `import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

class TaffyTailVault extends StatefulSmartContract {
  message: ByteString;
  readonly tag: ByteString;
  readonly owner: PubKey;

  constructor(message: ByteString, tag: ByteString, owner: PubKey) {
    super(message, tag, owner);
    this.message = message;
    this.tag = tag;
    this.owner = owner;
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }

  public post(next: ByteString, claimedTag: ByteString) {
    assert(claimedTag === this.tag);
    this.addOutput(extractAmount(this.txPreimage), next);
  }
}
`

// Control: the same shape with only FIXED-width readonly args. The pin is
// exact at compile time, so no deploy-time slot is recorded.
const fixedWidthVaultSource = `import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

class FixedWidthVault extends StatefulSmartContract {
  message: ByteString;
  readonly owner: PubKey;

  constructor(message: ByteString, owner: PubKey) {
    super(message, owner);
    this.message = message;
    this.owner = owner;
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }

  public post(next: ByteString) {
    this.addOutput(extractAmount(this.txPreimage), next);
  }
}
`

// The TS reference compiler's script for TaffyTailVault, fold OFF. Its
// codePartLenSlots is [{"byteOffset":959}].
const taffyTailVaultTSScript = "61ab76009c63757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad69768254947f7701007e8101419d01687f7782012c947f758258947f6d00ac67519d7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f77686868577982760446050000819c6952947b7c7f517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f776868685679827700947f77517f7c01007e8176014c9f637f6776014c9c6375516776014d9c63755267014e9d5468687f7c01007e817f680088547a008878820134947f77587f7581557a5679016a7e7c8276014c9f635280517f757c7e67760200019f635280517f75014c7c7e7c7e6776030000019f635480527f75014d7c7e7c7e675580547f75014e7c7e7c7e6868687e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f7587777768"

const taffyTailVaultTSCodePartLenSlot = 959

func compileN051OrFatal(t *testing.T, source, fileName string) *Artifact {
	t.Helper()
	result := CompileFromSourceStrWithResult(source, fileName, CompileOptions{DisableConstantFolding: true})
	if !result.Success {
		t.Fatalf("compilation of %s failed: %v", fileName, result.Diagnostics)
	}
	return result.Artifact
}

// pinRuns returns the BYTE offset of the 4-byte length field of every
// verify_code_part_len run (either comparison opcode) in a script. It walks
// decodeScriptOps, so a run hidden inside a pushed payload is never reported:
// the five opcodes must be OP_DUP, a 4-byte direct push (whose payload is the
// length field), OP_BIN2NUM, cmp, OP_VERIFY.
func pinRuns(t *testing.T, script string) (equality, lowerBound []int) {
	t.Helper()
	ops := decodeScriptOps(t, script)
	for i := 0; i+5 <= len(ops); i++ {
		if ops[i].code != 0x76 || ops[i+1].code != 0x04 || ops[i+2].code != 0x81 || ops[i+4].code != 0x69 {
			continue
		}
		switch ops[i+3].code {
		case 0x9c:
			equality = append(equality, ops[i+1].offset+1)
		case 0xa2:
			lowerBound = append(lowerBound, ops[i+1].offset+1)
		}
	}
	return
}

// hasOpSequence reports whether seq appears as consecutive opcodes (push
// payloads skipped by decodeScriptOps), so a hex substring that straddles a
// nibble boundary or sits inside pushed data is not a match.
func hasOpSequence(ops []scriptOp, seq ...byte) bool {
	for i := 0; i+len(seq) <= len(ops); i++ {
		ok := true
		for j, c := range seq {
			if ops[i+j].code != c {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// Proves hasOpSequence is opcode-aligned where strings.Contains(hex,
// "81a269") was not: the crafted scripts contain the substring yet no
// OP_BIN2NUM OP_GREATERTHANOREQUAL OP_VERIFY opcode run. Does not prove
// anything about what the compiler emits.
func TestHasOpSequence_RejectsNibbleAndPushDataMatches(t *testing.T) {
	const needle = "81a269"
	crafted := map[string]string{
		"inside push data": "0481a26900", // PUSH4 [81 a2 69 00]
		"nibble straddle":  "f81a2690",   // opcodes f8 1a 26 90: "81a269" spans bytes
	}
	for name, h := range crafted {
		if !strings.Contains(h, needle) {
			t.Fatalf("%s: crafted hex must fool the old substring check", name)
		}
		if hasOpSequence(decodeScriptOps(t, h), 0x81, 0xa2, 0x69) {
			t.Errorf("%s: %s must not be reported as containing the opcode run", name, h)
		}
	}
	if !hasOpSequence(decodeScriptOps(t, "5281a26951"), 0x81, 0xa2, 0x69) {
		t.Errorf("genuine opcode run must be found")
	}
}

// N-357: proves pinRuns only reports verify_code_part_len runs that are real
// opcodes: the nine bytes 76 04 LL LL LL LL 81 9c 69 hidden inside a pushed
// payload are not a pin, while the same run at opcode level is, and is
// reported at the BYTE offset of its length field (what codePartLenSlots
// records). Does not prove anything about what the compiler emits.
func TestPinRuns_IgnoresPushDataAndReportsByteOffsets(t *testing.T) {
	for name, c := range map[string]struct{ cmp, kind string }{
		"equality":    {"9c", "eq"},
		"lower bound": {"a2", "lb"},
	} {
		r := "7604aabbccdd81" + c.cmp + "69"
		hidden := "09" + r // PUSH9 [run]
		eq, lb := pinRuns(t, hidden)
		if len(eq) != 0 || len(lb) != 0 {
			t.Errorf("%s inside push data: pinRuns = %v / %v, want none", name, eq, lb)
		}
		eq, lb = pinRuns(t, "51"+r) // OP_1 then the genuine run
		got := eq
		if c.kind == "lb" {
			got = lb
		}
		if len(got) != 1 || got[0] != 3 {
			t.Errorf("%s genuine run: pinRuns = %v / %v, want one hit at byte offset 3", name, eq, lb)
		}
	}
}

func TestN051_TaffyTail_PinIsEqualityWithDeployTimeSlot(t *testing.T) {
	art := compileN051OrFatal(t, taffyTailVaultSource, "TaffyTailVault.runar.ts")

	equality, lowerBound := pinRuns(t, art.Script)
	if len(lowerBound) != 0 {
		t.Fatalf("script still carries a lower-bound (81 a2 69) pin at byte offset(s) %v", lowerBound)
	}
	if hasOpSequence(decodeScriptOps(t, art.Script), 0x81, 0xa2, 0x69) {
		t.Fatalf("script still contains the OP_BIN2NUM OP_GREATERTHANOREQUAL OP_VERIFY sequence")
	}
	if len(equality) != 1 {
		t.Fatalf("expected exactly one equality pin, found %d at %v", len(equality), equality)
	}

	if len(art.CodePartLenSlots) != 1 || art.CodePartLenSlots[0].ByteOffset != equality[0] {
		t.Fatalf("codePartLenSlots = %+v, want [{ByteOffset:%d}] (the pin's length field)",
			art.CodePartLenSlots, equality[0])
	}

	// Byte-identical with the TS reference compiler.
	if art.Script != taffyTailVaultTSScript {
		t.Fatalf("script diverges from the TS reference: %s", describeDivergence(art.Script, taffyTailVaultTSScript))
	}
	if art.CodePartLenSlots[0].ByteOffset != taffyTailVaultTSCodePartLenSlot {
		t.Fatalf("codePartLenSlots byteOffset = %d, TS reference has %d",
			art.CodePartLenSlots[0].ByteOffset, taffyTailVaultTSCodePartLenSlot)
	}

	// JSON shape: one key per entry, serialized right after codeSepIndexSlots.
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	js := string(raw)
	if !strings.Contains(js, `"codePartLenSlots":[{"byteOffset":959}]`) {
		t.Fatalf("artifact JSON lacks codePartLenSlots [{\"byteOffset\":959}]")
	}
	const sepKey = `"codeSepIndexSlots":`
	sep := strings.Index(js, sepKey)
	lenSlots := strings.Index(js, `"codePartLenSlots":`)
	if sep < 0 || lenSlots < sep {
		t.Fatalf("codePartLenSlots must be serialized after codeSepIndexSlots")
	}
	// Only the codeSepIndexSlots array (and its trailing comma) may sit between.
	between := strings.TrimSuffix(js[sep+len(sepKey):lenSlots], ",")
	var arr []map[string]int
	if err := json.Unmarshal([]byte(between), &arr); err != nil {
		t.Fatalf("a key sits between codeSepIndexSlots and codePartLenSlots: %s", between)
	}
}

func TestN051_FixedWidthReadonlyArgs_KeepNoSlot(t *testing.T) {
	art := compileN051OrFatal(t, fixedWidthVaultSource, "FixedWidthVault.runar.ts")

	equality, lowerBound := pinRuns(t, art.Script)
	if len(lowerBound) != 0 {
		t.Fatalf("unexpected lower-bound pin at %v", lowerBound)
	}
	if len(equality) == 0 {
		t.Fatalf("control contract carries no SIZE(_codePart) pin; it no longer exercises the exact path")
	}
	if len(art.CodePartLenSlots) != 0 {
		t.Fatalf("an exact compile-time pin must not record a codePartLenSlots entry, got %+v", art.CodePartLenSlots)
	}
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	if strings.Contains(string(raw), "codePartLenSlots") {
		t.Fatalf("codePartLenSlots must be omitted when empty")
	}
}
