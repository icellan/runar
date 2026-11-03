package compiler

// F-259 — an unrolled loop body's opcodes map to the body statement's line,
// not to the `for` line.
//
// Before the fix lowerLoop lowered every body binding without updating
// currentSourceLoc, so every opcode of every unrolled iteration inherited the
// enclosing loop binding's location (the `for` line).
//
// Convention (same in all 7 tiers): each body binding's own location is used
// while it lowers; a body binding without one keeps the loop's location. The
// per-iteration iteration-variable push stays on the `for` line.
//
// What this proves: end to end through CompileFromSourceStrWithResult on the
// Go surface of examples/go/bounded-loop, every body op of all five unrolled
// iterations maps to the body line and column, and only the five
// iteration-variable pushes (OP_0..OP_4) map to the `for` line.
//
// What this does not prove: anything about the other tiers, nested loops, or
// body bindings the ANF lowerer leaves without a location. It equates ASM
// token index with opcodeIndex, which holds for this contract (no raw_bytes
// spans).

import (
	"os"
	"strings"
	"testing"
)

func TestF259_SourceMap_LoopBodyOpsMapToBodyLine(t *testing.T) {
	const fileName = "BoundedLoop.runar.go"
	srcBytes, err := os.ReadFile("../../../examples/go/bounded-loop/" + fileName)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	src := string(srcBytes)
	result := CompileFromSourceStrWithResult(src, fileName,
		CompileOptions{IncludeSourceMap: true, DisableConstantFolding: true})
	if !result.Success {
		t.Fatalf("compile failed: %v", result.Diagnostics)
	}
	if result.Artifact.SourceMapData == nil {
		t.Fatalf("no source map in artifact")
	}
	lines := strings.Split(src, "\n")
	find := func(needle, anchor string) (int, int) {
		for i, l := range lines {
			if strings.Contains(l, needle) {
				return i + 1, strings.Index(l, anchor)
			}
		}
		t.Fatalf("needle %q not in source", needle)
		return 0, 0
	}
	forLine, forCol := find("for i :=", "for")
	bodyLine, bodyCol := find("sum = sum + start + i", "sum")

	asm := strings.Fields(result.ScriptAsm)
	iterPushes := map[int]string{1: "OP_0", 9: "OP_1", 17: "OP_2", 25: "OP_3", 33: "OP_4"}
	for idx, code := range iterPushes {
		if idx >= len(asm) || asm[idx] != code {
			t.Fatalf("expected %s at opcode %d; asm=%s", code, idx, result.ScriptAsm)
		}
	}

	seen := 0
	for _, m := range result.Artifact.SourceMapData.Mappings {
		if m.OpcodeIndex < 1 || m.OpcodeIndex > 39 {
			continue
		}
		seen++
		wantLine, wantCol := bodyLine, bodyCol
		if _, ok := iterPushes[m.OpcodeIndex]; ok {
			wantLine, wantCol = forLine, forCol
		}
		if m.Line != wantLine || m.Column != wantCol {
			t.Errorf("opcodeIndex %d (%s) mapped to %d:%d, want %d:%d",
				m.OpcodeIndex, asm[m.OpcodeIndex], m.Line, m.Column, wantLine, wantCol)
		}
	}
	if seen != 39 {
		t.Errorf("expected 39 loop-op mappings, got %d", seen)
	}
}
