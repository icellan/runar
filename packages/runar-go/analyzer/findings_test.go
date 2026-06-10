package analyzer

import (
	"strings"
	"testing"
)

// containsCode reports whether the report has at least one finding with the given code.
func containsCode(r AnalyzerReport, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// hasFindingMessage reports whether the report has at least one finding with the
// given code whose Message contains substr.
func hasFindingMessage(r AnalyzerReport, code, substr string) bool {
	for _, f := range r.Findings {
		if f.Code == code && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func TestInvalidTerminalStack_EmptyScript(t *testing.T) {
	r, err := AnalyzeScript("")
	if err != nil {
		t.Fatal(err)
	}
	if !containsCode(r, "INVALID_TERMINAL_STACK") {
		t.Fatalf("expected INVALID_TERMINAL_STACK, got %+v", r.Findings)
	}
	if r.ScriptSize != 0 || r.Script != "" {
		t.Errorf("unexpected scriptSize/script: %d %q", r.ScriptSize, r.Script)
	}
	if r.Summary.TotalPaths != 0 {
		t.Errorf("expected totalPaths=0, got %d", r.Summary.TotalPaths)
	}
}

func TestStackUnderflow(t *testing.T) {
	// OP_2DUP requires 2 stack items. Inside an IF/ELSE both arms
	// produce balanced depth so no INCONSISTENT_BRANCH_DEPTH, and
	// the inner stack analysis runs at initialDepth=0 — meaning
	// underflow is NOT reported per §8.2 (the locking-script
	// convention treats below-zero as draws from unlocking).
	//
	// To exercise STACK_UNDERFLOW we need a path that starts with
	// initialDepth > 0 AND an opcode whose pops exceed the current
	// depth. With initialDepth=1, OP_3DUP needs 3 items but only 1
	// is present.
	ops := []Opcode{
		{Offset: 0, Opcode: 0x6f, Name: "OP_3DUP", Size: 1},
	}
	res := analyzeStackLinear(ops, 1)
	found := false
	for _, f := range res.findings {
		if f.Code == "STACK_UNDERFLOW" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected STACK_UNDERFLOW from analyzeStackLinear, got %+v", res.findings)
	}
}

func TestUnbalancedIfEndif_StrayElse(t *testing.T) {
	r, err := AnalyzeScript("67") // OP_ELSE alone
	if err != nil {
		t.Fatal(err)
	}
	if !containsCode(r, "UNBALANCED_IF_ENDIF") {
		t.Fatalf("expected UNBALANCED_IF_ENDIF, got %+v", r.Findings)
	}
	if len(r.Paths) != 0 {
		t.Fatalf("expected zero paths after structural error, got %d", len(r.Paths))
	}
}

func TestUnbalancedIfEndif_StrayEndif(t *testing.T) {
	r, _ := AnalyzeScript("68")
	if !containsCode(r, "UNBALANCED_IF_ENDIF") {
		t.Fatalf("expected UNBALANCED_IF_ENDIF, got %+v", r.Findings)
	}
}

func TestUnbalancedIfEndif_Unclosed(t *testing.T) {
	r, _ := AnalyzeScript("63") // OP_IF, no ENDIF
	if !containsCode(r, "UNBALANCED_IF_ENDIF") {
		t.Fatalf("expected UNBALANCED_IF_ENDIF, got %+v", r.Findings)
	}
	// Message format check.
	for _, f := range r.Findings {
		if f.Code == "UNBALANCED_IF_ENDIF" {
			if !strings.Contains(f.Message, "OP_IF at offset 0 has no matching OP_ENDIF") {
				t.Errorf("bad message: %q", f.Message)
			}
		}
	}
}

func TestUnconditionallySucceeds(t *testing.T) {
	// OP_NOP — no verification opcode at all.
	r, _ := AnalyzeScript("61")
	if !containsCode(r, "UNCONDITIONALLY_SUCCEEDS") {
		t.Fatalf("expected UNCONDITIONALLY_SUCCEEDS, got %+v", r.Findings)
	}
}

func TestNoSigCheck(t *testing.T) {
	// OP_VERIFY but no CHECKSIG — has verification but no sig check.
	r, _ := AnalyzeScript("69")
	if !containsCode(r, "NO_SIG_CHECK") {
		t.Fatalf("expected NO_SIG_CHECK, got %+v", r.Findings)
	}
	// Should NOT raise UNCONDITIONALLY_SUCCEEDS — OP_VERIFY counts
	// as a verification opcode per §7.5.
	if containsCode(r, "UNCONDITIONALLY_SUCCEEDS") {
		t.Errorf("unexpected UNCONDITIONALLY_SUCCEEDS — OP_VERIFY is a verification opcode")
	}
}

func TestChecksigResultDropped(t *testing.T) {
	// OP_CHECKSIG OP_DROP.
	r, _ := AnalyzeScript("ac75")
	if !containsCode(r, "CHECKSIG_RESULT_DROPPED") {
		t.Fatalf("expected CHECKSIG_RESULT_DROPPED, got %+v", r.Findings)
	}
}

func TestCodeSeparatorPresent(t *testing.T) {
	r, _ := AnalyzeScript("ab")
	if !containsCode(r, "CODESEPARATOR_PRESENT") {
		t.Fatalf("expected CODESEPARATOR_PRESENT, got %+v", r.Findings)
	}
}

func TestInefficientPush_Pushdata1(t *testing.T) {
	// OP_PUSHDATA1 with 1-byte payload (0x4c 0x01 0xaa).
	r, _ := AnalyzeScript("4c01aa")
	if !containsCode(r, "INEFFICIENT_PUSH") {
		t.Fatalf("expected INEFFICIENT_PUSH, got %+v", r.Findings)
	}
}

func TestInefficientPush_Pushdata2(t *testing.T) {
	// OP_PUSHDATA2 with 1-byte payload (0x4d 0x01 0x00 0xaa).
	r, _ := AnalyzeScript("4d0100aa")
	if !containsCode(r, "INEFFICIENT_PUSH") {
		t.Fatalf("expected INEFFICIENT_PUSH, got %+v", r.Findings)
	}
}

func TestInefficientPush_Pushdata4(t *testing.T) {
	// OP_PUSHDATA4 with 1-byte payload (0x4e 0x01 0x00 0x00 0x00 0xaa).
	r, _ := AnalyzeScript("4e01000000aa")
	if !containsCode(r, "INEFFICIENT_PUSH") {
		t.Fatalf("expected INEFFICIENT_PUSH, got %+v", r.Findings)
	}
}

func TestInconsistentBranchDepth_WithoutElse(t *testing.T) {
	// OP_IF OP_DUP OP_ENDIF — body pushes net +1 with no ELSE.
	// Surrounded by ops to give the IF an item to consume.
	r, _ := AnalyzeScript("63767668") // OP_IF OP_DUP OP_DUP OP_ENDIF
	if !containsCode(r, "INCONSISTENT_BRANCH_DEPTH") {
		t.Fatalf("expected INCONSISTENT_BRANCH_DEPTH, got %+v", r.Findings)
	}
}

func TestInconsistentBranchDepth_WithElse(t *testing.T) {
	// OP_IF OP_DUP OP_ELSE OP_ENDIF — THEN delta +1, ELSE delta 0.
	r, _ := AnalyzeScript("63766768")
	if !containsCode(r, "INCONSISTENT_BRANCH_DEPTH") {
		t.Fatalf("expected INCONSISTENT_BRANCH_DEPTH, got %+v", r.Findings)
	}
}

func TestPathsTruncated(t *testing.T) {
	// 9 IF/NOTIF opcodes → 2^9 = 512 paths > 256.
	// Build OP_IF*9 + OP_ENDIF*9 = nested IFs.
	var sb strings.Builder
	for i := 0; i < 9; i++ {
		sb.WriteString("63") // OP_IF
	}
	for i := 0; i < 9; i++ {
		sb.WriteString("68") // OP_ENDIF
	}
	r, _ := AnalyzeScript(sb.String())
	if !containsCode(r, "PATHS_TRUNCATED") {
		t.Fatalf("expected PATHS_TRUNCATED, got %+v", r.Findings)
	}
	if r.Summary.TotalPaths != 256 {
		t.Errorf("expected totalPaths capped at 256, got %d", r.Summary.TotalPaths)
	}
}

func TestLargeScript(t *testing.T) {
	// Construct 500_001-byte script of OP_NOPs.
	var sb strings.Builder
	for i := 0; i < 500_001; i++ {
		sb.WriteString("61")
	}
	r, err := AnalyzeScript(sb.String())
	if err != nil {
		t.Fatal(err)
	}
	if !containsCode(r, "LARGE_SCRIPT") {
		t.Fatalf("expected LARGE_SCRIPT, got summary findings only: %+v", r.Findings)
	}
	if r.Summary.ScriptSizeBytes != 500_001 {
		t.Errorf("expected 500001, got %d", r.Summary.ScriptSizeBytes)
	}
}

func TestFormatKilobytes(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		// Spec example: 1024 → "1.0", 1500 → "1.5".
		{1024, "1.0"},
		{1500, "1.5"},
		// Golden fixtures.
		{1328100, "1297.0"},
		{872248, "851.8"},
	}
	for _, c := range cases {
		got := formatKilobytes(c.n)
		if got != c.want {
			t.Errorf("formatKilobytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestCollapseRawScriptSpans_Empty(t *testing.T) {
	ops := []Opcode{
		{Offset: 0, Opcode: 0x76, Name: "OP_DUP", Size: 1},
		{Offset: 1, Opcode: 0xac, Name: "OP_CHECKSIG", Size: 1},
	}
	out := collapseRawScriptSpans(ops, nil)
	if len(out) != 2 {
		t.Errorf("expected unchanged length 2, got %d", len(out))
	}
}

func TestCollapseRawScriptSpans_Single(t *testing.T) {
	ops := []Opcode{
		{Offset: 0, Opcode: 0x76, Name: "OP_DUP", Size: 1},
		{Offset: 1, Opcode: 0x77, Name: "OP_NIP", Size: 1},
		{Offset: 2, Opcode: 0x78, Name: "OP_OVER", Size: 1},
		{Offset: 3, Opcode: 0xac, Name: "OP_CHECKSIG", Size: 1},
	}
	spans := []RawScriptSpan{{Offset: 1, Length: 2, InArity: 1, OutArity: 2}}
	out := collapseRawScriptSpans(ops, spans)
	if len(out) != 3 {
		t.Fatalf("expected 3 entries (DUP, RAW_SPAN, CHECKSIG), got %d", len(out))
	}
	if !out[1].IsRawSpan || out[1].Name != "RAW_SPAN" || out[1].Size != 2 {
		t.Errorf("middle entry not a proper RAW_SPAN: %+v", out[1])
	}
	if out[1].RawSpanArity != [2]int{1, 2} {
		t.Errorf("arity mismatch: %v", out[1].RawSpanArity)
	}
}

func TestPushEncoding_DirectPush(t *testing.T) {
	// PUSH_3 + 3 data bytes.
	r, err := AnalyzeScript("03aabbcc")
	if err != nil {
		t.Fatal(err)
	}
	if r.ScriptSize != 4 {
		t.Errorf("scriptSize: %d", r.ScriptSize)
	}
	// Should NOT emit INEFFICIENT_PUSH for direct pushes.
	if containsCode(r, "INEFFICIENT_PUSH") {
		t.Errorf("direct push should not be inefficient")
	}
}

func TestOpcodeName_Unknown(t *testing.T) {
	if got := opcodeName(0x62); got != "OP_UNKNOWN(0x62)" {
		t.Errorf("got %q", got)
	}
	if got := opcodeName(0x89); got != "OP_UNKNOWN(0x89)" {
		t.Errorf("got %q", got)
	}
}

func TestNormalizeHex(t *testing.T) {
	got := normalizeHex(" Ab\tcD\n")
	if got != "abcd" {
		t.Errorf("normalize: %q", got)
	}
}

func TestPathsTruncated_LargeBranches(t *testing.T) {
	// Spec v1.2: numBranches=33 has 2^33 true paths, so PATHS_TRUNCATED
	// MUST be emitted (the prior 1.1 JS-shift quirk silently skipped it).
	// numBranches < 53 → exact-count message form.
	var sb strings.Builder
	for i := 0; i < 33; i++ {
		sb.WriteString("63") // OP_IF
	}
	for i := 0; i < 33; i++ {
		sb.WriteString("68") // OP_ENDIF
	}
	r, _ := AnalyzeScript(sb.String())
	if !containsCode(r, "PATHS_TRUNCATED") {
		t.Errorf("with numBranches=33, expected PATHS_TRUNCATED finding")
	}
	if r.Summary.TotalPaths != 256 {
		t.Errorf("expected totalPaths=256 (capped at MAX_PATHS), got %d", r.Summary.TotalPaths)
	}
	wantSubstr := "Script has 33 branch points (2^33 = 8589934592 paths)"
	if !hasFindingMessage(r, "PATHS_TRUNCATED", wantSubstr) {
		t.Errorf("PATHS_TRUNCATED message missing substring %q", wantSubstr)
	}
}

func TestPathsTruncated_VeryLargeBranches_Symbolic(t *testing.T) {
	// Spec v1.2: numBranches >= 53 renders the count symbolically as
	// "more than 2^53 paths" to avoid overflowing JS safe integers.
	var sb strings.Builder
	for i := 0; i < 53; i++ {
		sb.WriteString("63")
	}
	for i := 0; i < 53; i++ {
		sb.WriteString("68")
	}
	r, _ := AnalyzeScript(sb.String())
	if !containsCode(r, "PATHS_TRUNCATED") {
		t.Errorf("with numBranches=53, expected PATHS_TRUNCATED finding")
	}
	wantSubstr := "Script has 53 branch points (more than 2^53 paths)"
	if !hasFindingMessage(r, "PATHS_TRUNCATED", wantSubstr) {
		t.Errorf("PATHS_TRUNCATED message missing substring %q", wantSubstr)
	}
}
