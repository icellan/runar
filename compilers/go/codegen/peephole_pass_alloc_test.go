package codegen

import (
	"runtime"
	"testing"
	"unsafe"
)

// A peephole pass over a multi-million-op program (bn254-pairing lowers to a
// ~9.4 MB script) must not grow its output by repeated append: for large
// slices Go grows by ~1.25x, so a pass allocated ~5x its output and kept the
// old and new backing arrays live together. That pushed one bn254-pairing
// compile past 8 GB RSS and OOM-killed the 7 GiB CI runner. One pass should
// allocate about one output's worth.
func TestApplyOnePass_AllocatesAboutOneOutput(t *testing.T) {
	const n = 200_000
	ops := make([]StackOp, n)
	for i := range ops {
		// No window matches a run of OP_ADDs, so the pass copies every op.
		ops[i] = opcodeOp("OP_ADD")
	}
	one := uint64(n) * uint64(unsafe.Sizeof(StackOp{}))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out, changed := applyOnePass(ops)
	runtime.ReadMemStats(&after)

	if changed || len(out) != n {
		t.Fatalf("pass changed=%v len=%d, want an unchanged copy of %d ops", changed, len(out), n)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > one+one/4 {
		t.Fatalf("one pass over %d ops allocated %d bytes, want <= %d (1.25x one output of %d)", n, got, one+one/4, one)
	}
}

// Every pass used to allocate a fresh output, so a program that needs many
// passes allocated passes x output and kept the GC heap growing. The driver
// should reuse its buffers: total allocation stays a few outputs no matter how
// many passes run.
func TestOptimizeStackOps_ReusesBuffersAcrossPasses(t *testing.T) {
	const n, depth = 200_000, 20
	ops := make([]StackOp, 0, n+4*depth)
	for i := 0; i < n; i++ {
		ops = append(ops, opcodeOp("OP_ADD"))
	}
	// depth levels of `dup swap <inner> swap drop`: a pass collapses the
	// innermost `swap swap`, the next pass the `dup drop` it exposes, so the
	// optimizer needs 2*depth passes to empty it.
	for i := 0; i < depth; i++ {
		ops = append(ops, StackOp{Op: "dup"}, StackOp{Op: "swap"})
	}
	for i := 0; i < depth; i++ {
		ops = append(ops, StackOp{Op: "swap"}, StackOp{Op: "drop"})
	}
	one := uint64(len(ops)) * uint64(unsafe.Sizeof(StackOp{}))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out := OptimizeStackOps(ops)
	runtime.ReadMemStats(&after)

	if len(out) != n {
		t.Fatalf("optimized to %d ops, want the %d OP_ADDs", len(out), n)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 4*one {
		t.Fatalf("%d passes over %d ops allocated %d bytes, want <= %d (4x one input of %d)", 2*depth, len(ops), got, 4*one, one)
	}
}
