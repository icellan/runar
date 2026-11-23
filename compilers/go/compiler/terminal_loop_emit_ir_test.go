package compiler

import (
	"path/filepath"
	"strings"
	"testing"
)

// Terminal-loop parity: the source-to-IR path (`runar-go --emit-ir`,
// CompileSourceToIR) must refuse a terminal StatefulSmartContract method whose
// lowered ANF does not end in a terminal assert, exactly like the hex path
// (CompileFromProgram -> checkIRFrontendRules) and the other six tiers. Before
// the fix --emit-ir exited 0 on these shapes while --hex refused them.
func TestCompileSourceToIR_RefusesTerminalStatefulMethodWithoutTerminalAssert(t *testing.T) {
	for _, name := range []string{
		"N547-ts-stateful-terminal-loop-end.runar.ts",
		"N548-ts-stateful-terminal-if-no-else.runar.ts",
		"N549-ts-stateful-terminal-binding-after-assert.runar.ts",
	} {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join("..", "..", "..", "conformance", "negatives", name)
			_, err := CompileSourceToIR(src, CompileOptions{DisableConstantFolding: true})
			if err == nil {
				t.Fatalf("CompileSourceToIR accepted %s; want the terminal-assert refusal", name)
			}
			if !strings.Contains(err.Error(), "public method 'close' must end with an assert() call") {
				t.Fatalf("CompileSourceToIR(%s) refused with the wrong diagnostic: %v", name, err)
			}
		})
	}
}

// Control: the accepted sibling (loop followed by the terminal assert) still
// lowers to IR.
func TestCompileSourceToIR_AcceptsTerminalLoopFollowedByAssert(t *testing.T) {
	src := filepath.Join("..", "..", "..", "conformance", "tests", "stateful-terminal-loop", "StatefulTerminalLoop.runar.ts")
	if _, err := CompileSourceToIR(src, CompileOptions{DisableConstantFolding: true}); err != nil {
		t.Fatalf("CompileSourceToIR refused the accepted sibling: %v", err)
	}
}
