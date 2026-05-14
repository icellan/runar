package runar

import "testing"

// ---------------------------------------------------------------------------
// One-shot execution
// ---------------------------------------------------------------------------

// TestScriptVM_ExecuteHex_Arithmetic runs "OP_2 OP_3 OP_ADD OP_5 OP_EQUAL"
// (hex 5253935587) — 2 + 3 == 5 — and expects a truthy result.
func TestScriptVM_ExecuteHex_Arithmetic(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	res, err := vm.ExecuteHex("5253935587")
	if err != nil {
		t.Fatalf("ExecuteHex returned wrapper error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %q", res.Error)
	}
	if len(res.Stack) != 1 {
		t.Fatalf("expected 1 stack item, got %d: %x", len(res.Stack), res.Stack)
	}
	if len(res.Stack[0]) != 1 || res.Stack[0][0] != 0x01 {
		t.Errorf("expected truthy [01] on top, got %x", res.Stack[0])
	}
	if res.OpsExecuted != 5 {
		t.Errorf("expected 5 ops executed, got %d", res.OpsExecuted)
	}
}

// TestScriptVM_ExecuteHex_Failure runs "OP_2 OP_3 OP_EQUAL" (5253 87) —
// 2 == 3 is false — and expects a non-successful result with a clean-stack
// failure (top of stack is false / empty).
func TestScriptVM_ExecuteHex_Failure(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	res, err := vm.ExecuteHex("525387")
	if err != nil {
		t.Fatalf("ExecuteHex returned wrapper error: %v", err)
	}
	if res.Success {
		t.Fatalf("expected failure for 2 == 3, got success with stack %x", res.Stack)
	}
}

// TestScriptVM_Execute_UnlockingAndLocking executes a split unlocking +
// locking pair: unlocking pushes OP_5, locking checks "dup, 5, equal".
func TestScriptVM_Execute_UnlockingAndLocking(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	// unlocking: OP_5            -> 55
	// locking:   OP_5 OP_EQUAL   -> 5587
	res, err := vm.Execute([]byte{0x55}, []byte{0x55, 0x87})
	if err != nil {
		t.Fatalf("Execute returned wrapper error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got error: %q", res.Error)
	}
}

// TestScriptVM_ExecuteHex_InvalidHex rejects malformed hex with a wrapper
// error (not a VMResult).
func TestScriptVM_ExecuteHex_InvalidHex(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	if _, err := vm.ExecuteHex("xyz"); err == nil {
		t.Fatal("expected an error for invalid hex input")
	}
}

// ---------------------------------------------------------------------------
// Step mode (debugger API)
// ---------------------------------------------------------------------------

// TestScriptVM_StepMode walks "OP_2 OP_3 OP_ADD OP_5 OP_EQUAL" one opcode at
// a time and asserts the opcode names and intermediate stack depths.
func TestScriptVM_StepMode(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	if err := vm.LoadHex("", "5253935587"); err != nil {
		t.Fatalf("LoadHex failed: %v", err)
	}

	wantOpcodes := []string{"OP_2", "OP_3", "OP_ADD", "OP_5", "OP_EQUAL"}
	wantDepth := []int{1, 2, 1, 2, 1} // main-stack depth after each opcode

	var seen []string
	for i := 0; ; i++ {
		step := vm.Step()
		if step == nil {
			break
		}
		if i >= len(wantOpcodes) {
			t.Fatalf("more steps than expected; extra opcode %q", step.Opcode)
		}
		if step.Opcode != wantOpcodes[i] {
			t.Errorf("step %d: expected opcode %q, got %q", i, wantOpcodes[i], step.Opcode)
		}
		if len(step.MainStack) != wantDepth[i] {
			t.Errorf("step %d (%s): expected main-stack depth %d, got %d",
				i, step.Opcode, wantDepth[i], len(step.MainStack))
		}
		if step.Context != "locking" {
			t.Errorf("step %d: expected context 'locking', got %q", i, step.Context)
		}
		seen = append(seen, step.Opcode)
	}

	if len(seen) != len(wantOpcodes) {
		t.Fatalf("expected %d steps, got %d: %v", len(wantOpcodes), len(seen), seen)
	}
	if !vm.IsComplete() {
		t.Error("expected IsComplete() == true after walking the whole trace")
	}
	if !vm.IsSuccess() {
		t.Error("expected IsSuccess() == true for 2 + 3 == 5")
	}
	if vm.PC() != 5 {
		t.Errorf("expected PC() == 5 after stepping, got %d", vm.PC())
	}
}

// TestScriptVM_StepMode_ContextTransition confirms the cursor reports the
// "unlocking" context for opcodes from the unlocking script and "locking"
// for the locking script.
func TestScriptVM_StepMode_ContextTransition(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	// unlocking: OP_5 (55), locking: OP_5 OP_EQUAL (5587)
	if err := vm.LoadHex("55", "5587"); err != nil {
		t.Fatalf("LoadHex failed: %v", err)
	}

	step1 := vm.Step()
	if step1 == nil || step1.Context != "unlocking" {
		t.Fatalf("step 1: expected unlocking context, got %+v", step1)
	}
	step2 := vm.Step()
	if step2 == nil || step2.Context != "locking" {
		t.Fatalf("step 2: expected locking context, got %+v", step2)
	}
	step3 := vm.Step()
	if step3 == nil || step3.Context != "locking" {
		t.Fatalf("step 3: expected locking context, got %+v", step3)
	}
	if vm.Step() != nil {
		t.Error("expected nil after the final opcode")
	}
}

// TestScriptVM_Step_NothingLoaded returns nil when Step is called before any
// Load/Execute.
func TestScriptVM_Step_NothingLoaded(t *testing.T) {
	vm := NewScriptVM(VMOptions{})
	if vm.Step() != nil {
		t.Error("expected Step() == nil when nothing is loaded")
	}
	if vm.IsComplete() {
		t.Error("expected IsComplete() == false when nothing is loaded")
	}
}
