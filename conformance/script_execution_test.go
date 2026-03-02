package conformance

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
)

// compileRúnar invokes the TypeScript compiler to produce hex for a conformance
// contract with baked constructor args.  The args are passed as JSON.
func compileRúnar(contractName string, argsJSON string) (string, error) {
	// Use node to invoke the compiler from the runar-testing package
	// (where runar-compiler is a resolved dependency).
	code := fmt.Sprintf(`
const { compile } = require('./packages/runar-compiler/dist/index.js');
const fs = require('fs');
const src = fs.readFileSync('conformance/tests/%s/%s.runar.ts', 'utf-8');
const args = JSON.parse('%s', (k,v) => typeof v === 'string' && /^-?\d+$/.test(v) ? BigInt(v) : v);
const r = compile(src, { fileName: '%s.runar.ts', constructorArgs: args });
if (!r.success || !r.scriptHex) { process.exit(1); }
process.stdout.write(r.scriptHex);
`, contractName, contractName, argsJSON, contractName)

	cmd := exec.Command("node", "-e", code)
	cmd.Dir = ".." // project root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("compilation failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// buildUnlockingScript builds a simple unlocking script that pushes each
// bigint arg onto the stack.
func buildUnlockingScript(args ...int64) string {
	var sb strings.Builder
	for _, arg := range args {
		sb.WriteString(encodePushInt(arg))
	}
	return sb.String()
}

// encodePushInt encodes a script number push as hex.
func encodePushInt(n int64) string {
	if n == 0 {
		return "00" // OP_0
	}
	if n >= 1 && n <= 16 {
		return fmt.Sprintf("%02x", 0x50+n)
	}
	if n == -1 {
		return "4f" // OP_1NEGATE
	}

	negative := n < 0
	abs := n
	if negative {
		abs = -abs
	}

	var bytes []byte
	for abs > 0 {
		bytes = append(bytes, byte(abs&0xff))
		abs >>= 8
	}

	last := bytes[len(bytes)-1]
	if last&0x80 != 0 {
		if negative {
			bytes = append(bytes, 0x80)
		} else {
			bytes = append(bytes, 0x00)
		}
	} else if negative {
		bytes[len(bytes)-1] = last | 0x80
	}

	// Push data encoding
	if len(bytes) <= 75 {
		return fmt.Sprintf("%02x", len(bytes)) + hex.EncodeToString(bytes)
	}
	return fmt.Sprintf("4c%02x", len(bytes)) + hex.EncodeToString(bytes)
}

// encodePushBool encodes a boolean push as hex.
func encodePushBool(b bool) string {
	if b {
		return "51" // OP_1
	}
	return "00" // OP_0
}

// executeScript runs unlocking+locking scripts through the Go BSV SDK interpreter.
func executeScript(lockingHex, unlockingHex string) error {
	locking, err := script.NewFromHex(lockingHex)
	if err != nil {
		return fmt.Errorf("invalid locking script hex: %w", err)
	}
	unlocking, err := script.NewFromHex(unlockingHex)
	if err != nil {
		return fmt.Errorf("invalid unlocking script hex: %w", err)
	}

	eng := interpreter.NewEngine()
	return eng.Execute(
		interpreter.WithScripts(locking, unlocking),
		interpreter.WithAfterGenesis(),
		interpreter.WithForkID(),
	)
}

// ---------------------------------------------------------------------------
// Pure computation tests
// ---------------------------------------------------------------------------

func TestArithmetic_ScriptExecution(t *testing.T) {
	// 3+7=10, 3-7=-4, 3*7=21, 3/7=0 → result = 10+(-4)+21+0 = 27
	lockingHex, err := compileRúnar("arithmetic", `{"target":"27"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	unlockingHex := buildUnlockingScript(3, 7)
	if err := executeScript(lockingHex, unlockingHex); err != nil {
		t.Fatalf("execution failed: %v", err)
	}
}

func TestArithmetic_ScriptExecution_Fail(t *testing.T) {
	lockingHex, err := compileRúnar("arithmetic", `{"target":"0"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	unlockingHex := buildUnlockingScript(3, 7)
	if err := executeScript(lockingHex, unlockingHex); err == nil {
		t.Fatal("expected script failure but execution succeeded")
	}
}

func TestBooleanLogic_ScriptExecution(t *testing.T) {
	lockingHex, err := compileRúnar("boolean-logic", `{"threshold":"2"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// verify(5, 3, false)
	unlockingHex := buildUnlockingScript(5, 3) + encodePushBool(false)
	if err := executeScript(lockingHex, unlockingHex); err != nil {
		t.Fatalf("execution failed: %v", err)
	}
}

func TestIfElse_ScriptExecution(t *testing.T) {
	lockingHex, err := compileRúnar("if-else", `{"limit":"10"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// check(15, true) → 15+10=25 > 0
	unlockingHex := buildUnlockingScript(15) + encodePushBool(true)
	if err := executeScript(lockingHex, unlockingHex); err != nil {
		t.Fatalf("execution failed: %v", err)
	}
}

func TestBoundedLoop_ScriptExecution(t *testing.T) {
	// sum = (3+0)+(3+1)+(3+2)+(3+3)+(3+4) = 25
	lockingHex, err := compileRúnar("bounded-loop", `{"expectedSum":"25"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	unlockingHex := buildUnlockingScript(3)
	if err := executeScript(lockingHex, unlockingHex); err != nil {
		t.Fatalf("execution failed: %v", err)
	}
}
