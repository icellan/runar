package compiler

import (
	"strings"
	"testing"
)

// TestBigintBigOps_CompileIdenticalToInt64 confirms that a Go contract
// written in terms of BigintBig operator helpers compiles to the same
// Bitcoin Script as an identical contract written against int64
// operators. The helpers exist so that contract authors can type fields
// as *big.Int (BigintBig) — something Go disallows with plain `<` / `==`
// / `%` — without any on-chain divergence.
//
// If these two artifacts ever drift, the helper-rewrite path in
// compilers/go/frontend/parser_gocontract.go has introduced a
// BinaryExpr mismatch: both paths should produce the same bin_op ANF
// nodes, which fold to the same Script bytes.
func TestBigintBigOps_CompileIdenticalToInt64(t *testing.T) {
	int64Source := `package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type Compare struct {
	runar.SmartContract
	Limit runar.Bigint ` + "`runar:\"readonly\"`" + `
	Floor runar.Bigint ` + "`runar:\"readonly\"`" + `
}

func (c *Compare) Unlock(x runar.Bigint, y runar.Bigint) {
	runar.Assert(x < c.Limit)
	runar.Assert(x <= c.Limit)
	runar.Assert(y > c.Floor)
	runar.Assert(y >= c.Floor)
	runar.Assert(x == y)
	runar.Assert(x+y == c.Limit-c.Floor)
	runar.Assert(x*y != 0)
	runar.Assert(x%c.Limit == y/c.Limit)
}
`

	bigSource := `package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type Compare struct {
	runar.SmartContract
	Limit runar.BigintBig ` + "`runar:\"readonly\"`" + `
	Floor runar.BigintBig ` + "`runar:\"readonly\"`" + `
}

func (c *Compare) Unlock(x runar.BigintBig, y runar.BigintBig) {
	runar.Assert(runar.BigintBigLess(x, c.Limit))
	runar.Assert(runar.BigintBigLessEq(x, c.Limit))
	runar.Assert(runar.BigintBigGreater(y, c.Floor))
	runar.Assert(runar.BigintBigGreaterEq(y, c.Floor))
	runar.Assert(runar.BigintBigEqual(x, y))
	runar.Assert(runar.BigintBigEqual(runar.BigintBigAdd(x, y), runar.BigintBigSub(c.Limit, c.Floor)))
	runar.Assert(runar.BigintBigNotEqual(runar.BigintBigMul(x, y), runar.Bigint(0)))
	runar.Assert(runar.BigintBigEqual(runar.BigintBigMod(x, c.Limit), runar.BigintBigDiv(y, c.Limit)))
}
`

	opts := CompileOptions{DisableConstantFolding: true}

	intResult := CompileFromSourceStrWithResult(int64Source, "Compare.runar.go", opts)
	if !intResult.Success {
		t.Fatalf("int64 source compile failed: %s", diagSummary(intResult))
	}
	bigResult := CompileFromSourceStrWithResult(bigSource, "Compare.runar.go", opts)
	if !bigResult.Success {
		t.Fatalf("BigintBig source compile failed: %s", diagSummary(bigResult))
	}

	if intResult.Artifact == nil || bigResult.Artifact == nil {
		t.Fatal("expected non-nil artifacts from both compiles")
	}

	if intResult.Artifact.Script != bigResult.Artifact.Script {
		t.Errorf("script hex diverged between int64 and BigintBig sources\n  int64:     %s\n  BigintBig: %s",
			intResult.Artifact.Script, bigResult.Artifact.Script)
	}
	if intResult.Artifact.ASM != bigResult.Artifact.ASM {
		t.Errorf("ASM diverged between int64 and BigintBig sources\n  int64:     %s\n  BigintBig: %s",
			intResult.Artifact.ASM, bigResult.Artifact.ASM)
	}
}

func diagSummary(r *CompileResult) string {
	msgs := make([]string, 0, len(r.Diagnostics))
	for _, d := range r.Diagnostics {
		msgs = append(msgs, d.Message)
	}
	return strings.Join(msgs, "; ")
}
