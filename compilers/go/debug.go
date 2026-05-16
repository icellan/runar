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
	"strings"

	runar "github.com/icellan/runar/packages/runar-go"
)

// runDebug parses the `debug` subcommand's flags and prints a per-opcode
// trace of the loaded script. Returns a wrapper error only if the inputs
// are malformed; a script that *legitimately* fails (e.g. OP_VERIFY on
// false) is reported as a non-zero final-status line, not as an error.
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

	locking := *scriptHex
	if locking == "" && *artifactPath != "" {
		bytes, err := os.ReadFile(*artifactPath)
		if err != nil {
			return fmt.Errorf("read artifact: %w", err)
		}
		var art struct {
			Script string `json:"script"`
		}
		if err := json.Unmarshal(bytes, &art); err != nil {
			return fmt.Errorf("parse artifact JSON: %w", err)
		}
		locking = art.Script
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
		fmt.Printf("step=%d  ctx=%s  offset=%d  op=%s  stack=%s\n",
			stepN, step.Context, step.Offset, step.Opcode,
			formatStack(step.MainStack, *maxStackBytes))
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
