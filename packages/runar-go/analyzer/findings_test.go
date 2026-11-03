package analyzer

import (
	"fmt"
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

// F-234: OP_2DROP pops the CHECKSIG result as surely as OP_DROP does, so
// `OP_CHECKSIG OP_2DROP OP_1` used to verify clean. Proves the immediate
// OP_2DROP form is flagged with the spec §5.1 message and that OP_NIP (which
// removes the item BELOW the result) is not. Does not prove that longer
// discard sequences (OP_SWAP OP_NIP, OP_TOALTSTACK, ...) are caught: the rule
// only looks at the next opcode.
func TestChecksigResultDroppedBy2Drop(t *testing.T) {
	cases := []struct{ hex, want string }{
		{"0000ac6d51", "OP_CHECKSIG result is dropped by OP_2DROP — signature check has no effect"},
		{"000000ae6d51", "OP_CHECKMULTISIG result is dropped by OP_2DROP — signature check has no effect"},
	}
	for _, c := range cases {
		r, _ := AnalyzeScript(c.hex)
		var got []Finding
		for _, f := range r.Findings {
			if f.Code == "CHECKSIG_RESULT_DROPPED" {
				got = append(got, f)
			}
		}
		if len(got) != 1 || got[0].Message != c.want || got[0].Severity != SeverityWarning || !got[0].HasOffset {
			t.Fatalf("%s: expected one CHECKSIG_RESULT_DROPPED %q, got %+v", c.hex, c.want, r.Findings)
		}
	}
	if r, _ := AnalyzeScript("0000ac6d51"); r.Findings[0].Offset != 2 || r.Findings[0].Opcode != "OP_CHECKSIG" {
		t.Fatalf("expected offset 2 / OP_CHECKSIG, got %+v", r.Findings)
	}
	// OP_0 OP_0 OP_CHECKSIG OP_NIP — the result survives on top; not flagged.
	if r, _ := AnalyzeScript("0000ac77"); containsCode(r, "CHECKSIG_RESULT_DROPPED") {
		t.Fatalf("OP_NIP must not be flagged, got %+v", r.Findings)
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
		// Golden fixtures (conformance/analyzer/{ec-demo,schnorr-zkp}) —
		// pinned here so the tie-rounding fix below is proven not to move
		// them: neither size lands on an exact .5 tie at the tenths digit.
		{1328100, "1297.0"},
		{872248, "851.8"},
		{1337343, "1306.0"},
		{877253, "856.7"},
	}
	for _, c := range cases {
		got := formatKilobytes(c.n)
		if got != c.want {
			t.Errorf("formatKilobytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestFormatKilobytesBreaksTiesLikeJsNotHalfToEven(t *testing.T) {
	// 500992/1024 = 489.25 exactly (1024 is a power of two, so the
	// division has no floating-point error). Scaled by 10 that is 4892.5 —
	// an exact tie at the tenths digit. JS Number.prototype.toFixed(1)
	// does not use round-half-to-even: per spec it picks the integer n for
	// which n/10 - x is closest to zero, and on a tie picks the LARGER n.
	// Verified live: node -e "console.log((500992/1024).toFixed(1))" ->
	// "489.3". math.RoundToEven rounds 4892.5 down to 4892 (already even),
	// producing the wrong "489.2".
	got := formatKilobytes(500992)
	if got != "489.3" {
		t.Errorf("formatKilobytes(500992) = %q, want %q", got, "489.3")
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

// chronicleOps are the seven Chronicle opcodes the compiler emits, with the
// (pops, pushes) the @bsv/sdk interpreter (Spend.ts) gives them.
var chronicleOps = []struct {
	b      string
	name   string
	pops   int
	pushes int
}{
	{"8d", "OP_2MUL", 1, 1},
	{"8e", "OP_2DIV", 1, 1},
	{"b3", "OP_SUBSTR", 3, 1},
	{"b4", "OP_LEFT", 2, 1},
	{"b5", "OP_RIGHT", 2, 1},
	{"b6", "OP_LSHIFTNUM", 2, 1},
	{"b7", "OP_RSHIFTNUM", 2, 1},
}

// TestChronicleOpcodes_NamesAndEffects (F-131) proves the Chronicle opcodes
// are named per spec §4.1 and modelled with their real stack effect, in the
// lookup and in the observable report (underflow message, stackDepthAtEnd,
// maxStackDepth). It does not prove runtime semantics (the analyzer is
// static) and does not re-derive the arities from the interpreter.
func TestChronicleOpcodes_NamesAndEffects(t *testing.T) {
	for _, c := range chronicleOps {
		ops, err := parseScript(c.b)
		if err != nil || len(ops) != 1 {
			t.Fatalf("%s: parse: %v", c.b, err)
		}
		if ops[0].Name != c.name {
			t.Errorf("0x%s: name %q, want %q", c.b, ops[0].Name, c.name)
		}
		if p, q := stackEffect(ops[0]); p != c.pops || q != c.pushes {
			t.Errorf("%s: effect (%d,%d), want (%d,%d)", c.name, p, q, c.pops, c.pushes)
		}

		// OP_DROP empties a stack of known depth 1, then the opcode needs `pops` items.
		dropThen, _ := parseScript("75" + c.b)
		lin := analyzeStackLinear(dropThen, 1)
		want := fmt.Sprintf("%s requires %d stack item(s) but only 0 available", c.name, c.pops)
		found := false
		for _, f := range lin.findings {
			if f.Code == "STACK_UNDERFLOW" && f.Message == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: missing underflow %q in %+v", c.name, want, lin.findings)
		}

		// `pops` pushes of OP_1 then the opcode leave exactly `pushes` items.
		r, err := AnalyzeScript(strings.Repeat("51", c.pops) + c.b)
		if err != nil {
			t.Fatalf("%s: analyze: %v", c.name, err)
		}
		if r.Paths[0].StackDepthAtEnd != c.pushes || r.Summary.MaxStackDepth != c.pushes {
			t.Errorf("%s: depthAtEnd=%d maxStackDepth=%d, want %d", c.name,
				r.Paths[0].StackDepthAtEnd, r.Summary.MaxStackDepth, c.pushes)
		}
	}

	// A genuinely unknown byte keeps the OP_UNKNOWN name and (0,0) effect.
	ops, _ := parseScript("b8")
	if ops[0].Name != "OP_UNKNOWN(0xb8)" {
		t.Errorf("0xb8 name %q", ops[0].Name)
	}
	if p, q := stackEffect(ops[0]); p != 0 || q != 0 {
		t.Errorf("0xb8 effect (%d,%d), want (0,0)", p, q)
	}
}

func TestNormalizeHex(t *testing.T) {
	got := normalizeHex(" Ab\tcD\n")
	if got != "abcd" {
		t.Errorf("normalize: %q", got)
	}
}

func TestNormalizeHexStripsJsWhitespaceSet(t *testing.T) {
	// normalizeHex only matched a handful of ASCII whitespace runes
	// (space, tab, \n, \r, \v, \f) and passed every other rune through
	// unchanged. JS's /\s/g (what the TS reference strips) additionally
	// matches NBSP (U+00A0) and ZERO WIDTH NO-BREAK SPACE / BOM (U+FEFF),
	// among other Unicode whitespace. Verified against the live TS
	// analyzer: both inputs below normalize to "76a988ac".
	got := normalizeHex("76\u00a0a9\u00a088\u00a0ac")
	if got != "76a988ac" {
		t.Errorf("normalize (NBSP): %q", got)
	}
	got = normalizeHex("\ufeff76a988ac")
	if got != "76a988ac" {
		t.Errorf("normalize (BOM): %q", got)
	}
}

func TestNormalizeHexDoesNotStripC0Separators(t *testing.T) {
	// U+001C-U+001F are not matched by JS /\s/g, so the TS reference keeps
	// them in the normalized string (and then rejects them as non-hex
	// characters — verified live: the TS analyzer throws "Invalid hex
	// character" on this exact input). normalizeHex must not strip them
	// either.
	got := normalizeHex("76\u001ca9")
	if got != "76\u001ca9" {
		t.Errorf("normalize (C0 separator): %q, want kept", got)
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
