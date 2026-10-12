package main

// runar-compiler-go debug — minimal ScriptVM step-through debugger.
//
// Wraps packages/runar-go's ScriptVM (which itself wraps the BSV SDK
// interpreter) to expose a non-interactive trace-print equivalent of the
// TypeScript `runar debug` command. Each opcode is executed and its
// post-execution stack is printed.
//
// Usage:
//
//	runar-compiler-go debug --script <hex> [--unlock <hex>] [--max-stack-bytes <n>]
//	runar-compiler-go debug --artifact <path> [--unlock <hex>]
//
// G-6 (audits/cross-language-completeness-20260514.md §5.1).

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	runar "github.com/icellan/runar/packages/runar-go"
)

// sourceMapping is one entry of an artifact's `sourceMap.mappings` array —
// see packages/runar-ir-schema/src/artifact.ts's SourceMapping and its
// mirror packages/runar-testing/src/source-map.ts (TS `runar debug`'s
// resolver, which this type and sourceMapResolver below port).
type sourceMapping struct {
	OpcodeIndex int    `json:"opcodeIndex"`
	SourceFile  string `json:"sourceFile"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
}

// sourceMapResolver maps a sequential opcode step index to the nearest
// source location at or before it, mirroring
// packages/runar-testing/src/source-map.ts's SourceMapResolver.resolve:
// binary search over mappings sorted by OpcodeIndex for the largest
// OpcodeIndex <= the queried index.
type sourceMapResolver struct {
	sorted []sourceMapping
}

func newSourceMapResolver(mappings []sourceMapping) *sourceMapResolver {
	sorted := make([]sourceMapping, len(mappings))
	copy(sorted, mappings)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].OpcodeIndex < sorted[j].OpcodeIndex })
	return &sourceMapResolver{sorted: sorted}
}

func (r *sourceMapResolver) resolve(opcodeIndex int) (sourceMapping, bool) {
	lo, hi := 0, len(r.sorted)-1
	var best *sourceMapping
	for lo <= hi {
		mid := (lo + hi) / 2
		if r.sorted[mid].OpcodeIndex <= opcodeIndex {
			best = &r.sorted[mid]
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if best == nil {
		return sourceMapping{}, false
	}
	return *best, true
}

// runDebug parses the `debug` subcommand's flags and prints a per-opcode
// trace of the loaded script. Returns a wrapper error only if the inputs
// are malformed; a script that *legitimately* fails (e.g. OP_VERIFY on
// false) is reported on its final-status line and then exits 1 (F-221).
func runDebug() error {
	fs := flag.NewFlagSet("debug", flag.ExitOnError)
	scriptHex := fs.String("script", "", "locking-script hex (required unless --artifact is used)")
	unlockHex := fs.String("unlock", "", "unlocking-script hex (default: empty)")
	artifactPath := fs.String("artifact", "", "compiled artifact JSON path (uses its 'script' field as locking hex)")
	maxStackBytes := fs.Int("max-stack-bytes", 32, "max bytes of each stack element to print (0 = full)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: runar-compiler-go debug [--script <hex> | --artifact <path>] [--unlock <hex>] [--max-stack-bytes <n>]")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Executes a Bitcoin Script step-by-step via the BSV SDK interpreter,")
		fmt.Fprintln(fs.Output(), "printing the main stack after each opcode. Each line:")
		fmt.Fprintln(fs.Output(), "  step=<n>  ctx=<unlocking|locking>  offset=<byte>  op=<name>  stack=[...]")
		fmt.Fprintln(fs.Output())
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	// N-235 (mirrors F-386, landed for Rust in debug_subcommand.rs):
	// --script and --artifact are alternatives (see the usage string
	// above), but one used to silently win over the other with no
	// diagnostic. Refuse the ambiguous combination explicitly instead.
	if *scriptHex != "" && *artifactPath != "" {
		return fmt.Errorf("--script and --artifact are mutually exclusive; pass exactly one")
	}

	locking := *scriptHex
	var resolver *sourceMapResolver
	if locking == "" && *artifactPath != "" {
		bytes, err := os.ReadFile(*artifactPath)
		if err != nil {
			return fmt.Errorf("read artifact: %w", err)
		}
		var art struct {
			Script    string `json:"script"`
			SourceMap *struct {
				Mappings []sourceMapping `json:"mappings"`
			} `json:"sourceMap"`
		}
		if err := json.Unmarshal(bytes, &art); err != nil {
			return fmt.Errorf("parse artifact JSON: %w", err)
		}
		locking = art.Script
		if art.SourceMap != nil && len(art.SourceMap.Mappings) > 0 {
			resolver = newSourceMapResolver(art.SourceMap.Mappings)
		}
	}
	if locking == "" {
		fs.Usage()
		return fmt.Errorf("--script or --artifact is required")
	}

	vm := runar.NewScriptVM(runar.VMOptions{})
	if err := vm.LoadHex(*unlockHex, locking); err != nil {
		return err
	}

	stepN := 0
	for step := vm.Step(); step != nil; step = vm.Step() {
		stepN++
		line := fmt.Sprintf("step=%d  ctx=%s  offset=%d  op=%s  stack=%s",
			stepN, step.Context, step.Offset, step.Opcode,
			formatStack(step.MainStack, *maxStackBytes))
		// Source location: resolve against the opcode's sequential step
		// index (0-based), matching the TS debugger's
		// `resolver.resolve(opcodeCounter - 1)` where opcodeCounter counts
		// every stepped opcode starting at 1 (packages/runar-cli/src/commands/debug.ts).
		if resolver != nil {
			if loc, ok := resolver.resolve(stepN - 1); ok {
				line += fmt.Sprintf("  src=%s:%d:%d", loc.SourceFile, loc.Line, loc.Column)
			}
		}
		fmt.Println(line)
		if step.Error != "" {
			fmt.Printf("  error: %s\n", step.Error)
		}
	}
	if stepN == 0 {
		// An empty locking script with no unlocking script yields no trace;
		// surface that explicitly rather than silently exiting.
		fmt.Println("(no opcodes executed)")
	}

	status := "fail"
	if vm.IsSuccess() {
		status = "pass"
	}
	fmt.Printf("final: %s  ops=%d  stack=%s\n", status, stepN, formatStack(vm.Stack(), *maxStackBytes))
	if !vm.IsSuccess() {
		os.Exit(1)
	}
	return nil
}

// formatStack renders a stack as "[hex1, hex2, ...]" with per-element
// truncation. Top of stack appears last (matches the upstream interpreter's
// bottom-first convention and the TS ScriptVM's display order).
func formatStack(stack [][]byte, maxBytes int) string {
	if len(stack) == 0 {
		return "[]"
	}
	parts := make([]string, len(stack))
	for i, e := range stack {
		s := hex.EncodeToString(e)
		if maxBytes > 0 && len(e) > maxBytes {
			s = hex.EncodeToString(e[:maxBytes]) + fmt.Sprintf("…(+%d)", len(e)-maxBytes)
		}
		if s == "" {
			s = "<empty>"
		}
		parts[i] = s
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
