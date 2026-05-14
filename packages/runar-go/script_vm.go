package runar

// Bitcoin Script virtual machine for off-chain testing and debugging.
//
// This is a thin wrapper around the bsv-blockchain go-sdk script interpreter
// (github.com/bsv-blockchain/go-sdk/script/interpreter). It does NOT
// re-implement Bitcoin Script — the upstream interpreter does all execution.
// The wrapper records an execution trace via the interpreter's Debugger hook
// so it can expose the same step-mode debugger API as the TypeScript
// ScriptVM in packages/runar-testing/src/vm/script-vm.ts:
//
//	vm := NewScriptVM(VMOptions{})
//	res, _ := vm.ExecuteHex("76a9...")          // one-shot execution
//	vm.LoadHex(unlockingHex, lockingHex)        // step-mode: load...
//	for step := vm.Step(); step != nil; step = vm.Step() { ... }
//
// Scripts are run post-genesis (BSV re-enabled opcodes — OP_CAT, OP_MUL,
// OP_SPLIT, etc. — which Rúnar codegen relies on are available).

import (
	"encoding/hex"
	"fmt"

	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
)

// VMResult is the outcome of a full script execution.
type VMResult struct {
	// Success is true when the script ran to completion and left a truthy
	// value on top of the stack.
	Success bool
	// Stack is the final main stack, bottom element first.
	Stack [][]byte
	// AltStack is the final alt stack, bottom element first.
	AltStack [][]byte
	// Error is the interpreter error string, or "" on success.
	Error string
	// OpsExecuted is the number of opcode steps the interpreter ran.
	OpsExecuted int
	// MaxStackDepth is the deepest the main stack reached during execution.
	MaxStackDepth int
}

// StepResult is the outcome of executing a single opcode in step mode.
type StepResult struct {
	// Offset is the byte offset of the opcode within its script.
	Offset int
	// Opcode is the opcode name (e.g. "OP_ADD", "OP_DUP").
	Opcode string
	// MainStack is the main stack after this opcode, bottom element first.
	MainStack [][]byte
	// AltStack is the alt stack after this opcode, bottom element first.
	AltStack [][]byte
	// Error is set if this opcode caused the script to fail.
	Error string
	// Context is "unlocking" or "locking" — which script is executing.
	Context string
}

// VMOptions configures a ScriptVM. All fields are optional; the zero value
// is a usable post-genesis VM.
type VMOptions struct {
	// ForkID enables BSV sighash fork-id semantics. Off by default — pure
	// script execution (no transaction context) does not need it.
	ForkID bool
}

// ScriptVM executes Bitcoin Script bytes via the go-sdk interpreter and
// records a step trace for debugger-style inspection.
type ScriptVM struct {
	opts VMOptions

	// Step-mode state, populated by Load* and walked by Step.
	trace   []StepResult
	result  *VMResult
	pc      int
	loaded  bool
}

// NewScriptVM creates a ScriptVM with the given options.
func NewScriptVM(opts VMOptions) *ScriptVM {
	return &ScriptVM{opts: opts}
}

// ---------------------------------------------------------------------------
// One-shot execution
// ---------------------------------------------------------------------------

// Execute runs the unlocking script followed by the locking script and
// returns the final VM state. A nil/empty unlocking script is allowed
// (equivalent to executing the locking script alone).
func (vm *ScriptVM) Execute(unlocking, locking []byte) (*VMResult, error) {
	trace, result, err := vm.run(unlocking, locking)
	if err != nil {
		// A script that legitimately fails (e.g. OP_VERIFY on false) is not
		// a wrapper error — it is reported via VMResult.Error / Success=false.
		_ = err
	}
	vm.trace = trace
	vm.result = result
	vm.pc = 0
	vm.loaded = true
	return result, nil
}

// ExecuteHex runs a single hex-encoded script (as the locking script, with
// an empty unlocking script) and returns the final VM state.
func (vm *ScriptVM) ExecuteHex(scriptHex string) (*VMResult, error) {
	b, err := hex.DecodeString(scriptHex)
	if err != nil {
		return nil, fmt.Errorf("ScriptVM.ExecuteHex: invalid hex: %w", err)
	}
	return vm.Execute(nil, b)
}

// ---------------------------------------------------------------------------
// Step mode (debugger API)
// ---------------------------------------------------------------------------

// Load prepares the VM to step through the unlocking + locking scripts.
// The interpreter runs the scripts immediately and the resulting trace is
// walked one opcode at a time by Step.
func (vm *ScriptVM) Load(unlocking, locking []byte) error {
	trace, result, _ := vm.run(unlocking, locking)
	vm.trace = trace
	vm.result = result
	vm.pc = 0
	vm.loaded = true
	return nil
}

// LoadHex prepares the VM to step through hex-encoded unlocking + locking
// scripts.
func (vm *ScriptVM) LoadHex(unlockingHex, lockingHex string) error {
	u, err := hex.DecodeString(unlockingHex)
	if err != nil {
		return fmt.Errorf("ScriptVM.LoadHex: invalid unlocking hex: %w", err)
	}
	l, err := hex.DecodeString(lockingHex)
	if err != nil {
		return fmt.Errorf("ScriptVM.LoadHex: invalid locking hex: %w", err)
	}
	return vm.Load(u, l)
}

// Step executes the next opcode and returns its StepResult, or nil when the
// script has finished (or nothing is loaded).
func (vm *ScriptVM) Step() *StepResult {
	if !vm.loaded || vm.pc >= len(vm.trace) {
		return nil
	}
	step := vm.trace[vm.pc]
	vm.pc++
	return &step
}

// PC returns the current step cursor (number of opcodes stepped so far).
func (vm *ScriptVM) PC() int { return vm.pc }

// IsComplete reports whether stepping has reached the end of the trace.
func (vm *ScriptVM) IsComplete() bool {
	return vm.loaded && vm.pc >= len(vm.trace)
}

// IsSuccess reports whether the loaded script executed successfully.
func (vm *ScriptVM) IsSuccess() bool {
	return vm.result != nil && vm.result.Success
}

// Stack returns the current main stack (after the last stepped opcode, or
// the final stack if stepping is complete / one-shot Execute was used).
func (vm *ScriptVM) Stack() [][]byte {
	if vm.pc > 0 && vm.pc <= len(vm.trace) {
		return vm.trace[vm.pc-1].MainStack
	}
	if vm.result != nil {
		return vm.result.Stack
	}
	return nil
}

// AltStack returns the current alt stack, mirroring Stack.
func (vm *ScriptVM) AltStack() [][]byte {
	if vm.pc > 0 && vm.pc <= len(vm.trace) {
		return vm.trace[vm.pc-1].AltStack
	}
	if vm.result != nil {
		return vm.result.AltStack
	}
	return nil
}

// Context returns "unlocking" or "locking" — which script the cursor is in.
func (vm *ScriptVM) Context() string {
	if vm.pc > 0 && vm.pc <= len(vm.trace) {
		return vm.trace[vm.pc-1].Context
	}
	return ""
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

func (vm *ScriptVM) run(unlocking, locking []byte) ([]StepResult, *VMResult, error) {
	unlockingScript := bsvscript.NewFromBytes(unlocking)
	lockingScript := bsvscript.NewFromBytes(locking)

	rec := &recordingDebugger{}

	execOpts := []interpreter.ExecutionOptionFunc{
		interpreter.WithScripts(lockingScript, unlockingScript),
		interpreter.WithAfterGenesis(),
		interpreter.WithDebugger(rec),
	}
	if vm.opts.ForkID {
		execOpts = append(execOpts, interpreter.WithForkID())
	}

	err := interpreter.NewEngine().Execute(execOpts...)

	result := &VMResult{
		Stack:         rec.finalStack,
		AltStack:      rec.finalAltStack,
		OpsExecuted:   len(rec.trace),
		MaxStackDepth: rec.maxStackDepth,
	}
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		if len(rec.trace) > 0 {
			rec.trace[len(rec.trace)-1].Error = err.Error()
		}
	} else {
		result.Success = rec.success
	}
	return rec.trace, result, err
}

// recordingDebugger implements interpreter.Debugger and snapshots VM state
// after each opcode so the wrapper can replay it as a step trace.
type recordingDebugger struct {
	trace         []StepResult
	finalStack    [][]byte
	finalAltStack [][]byte
	maxStackDepth int
	success       bool

	// pendingOpcode / pendingOffset / pendingContext carry per-opcode info
	// captured at BeforeStep (when State.Opcode() points at the opcode about
	// to run) into AfterStep (when the resulting stacks are observable).
	pendingOpcode  string
	pendingOffset  int
	pendingContext string
	havePending    bool
}

func cloneStack(s [][]byte) [][]byte {
	out := make([][]byte, len(s))
	for i, e := range s {
		cp := make([]byte, len(e))
		copy(cp, e)
		out[i] = cp
	}
	return out
}

// contextFor maps the interpreter's script index to a human-readable name.
// With WithScripts(locking, unlocking) the interpreter runs the unlocking
// script first (index 0) then the locking script (index 1).
func contextFor(scriptIdx int) string {
	if scriptIdx == 0 {
		return "unlocking"
	}
	return "locking"
}

func (d *recordingDebugger) BeforeStep(s *interpreter.State) {
	d.pendingOpcode = s.Opcode().Name()
	d.pendingOffset = s.OpcodeIdx
	d.pendingContext = contextFor(s.ScriptIdx)
	d.havePending = true
}

func (d *recordingDebugger) AfterStep(s *interpreter.State) {
	mainStack := cloneStack(s.DataStack)
	altStack := cloneStack(s.AltStack)
	if depth := len(s.DataStack) + len(s.AltStack); depth > d.maxStackDepth {
		d.maxStackDepth = depth
	}
	step := StepResult{
		MainStack: mainStack,
		AltStack:  altStack,
	}
	if d.havePending {
		step.Offset = d.pendingOffset
		step.Opcode = d.pendingOpcode
		step.Context = d.pendingContext
		d.havePending = false
	}
	d.trace = append(d.trace, step)
	d.finalStack = mainStack
	d.finalAltStack = altStack
}

// AfterSuccess / AfterError only record the pass/fail bit. The final stacks
// are taken from the last AfterStep snapshot — by the time these callbacks
// fire the interpreter's clean-stack CheckErrorCondition has already popped
// the result element, so State.DataStack here is post-pop and not what a
// caller wants to inspect.
func (d *recordingDebugger) AfterSuccess(*interpreter.State) {
	d.success = true
}

func (d *recordingDebugger) AfterError(*interpreter.State, error) {
	d.success = false
}

// Remaining Debugger callbacks are unused by the recorder.
func (d *recordingDebugger) BeforeExecute(*interpreter.State)            {}
func (d *recordingDebugger) AfterExecute(*interpreter.State)             {}
func (d *recordingDebugger) BeforeExecuteOpcode(*interpreter.State)      {}
func (d *recordingDebugger) AfterExecuteOpcode(*interpreter.State)       {}
func (d *recordingDebugger) BeforeScriptChange(*interpreter.State)       {}
func (d *recordingDebugger) AfterScriptChange(*interpreter.State)        {}
func (d *recordingDebugger) BeforeStackPush(*interpreter.State, []byte)  {}
func (d *recordingDebugger) AfterStackPush(*interpreter.State, []byte)   {}
func (d *recordingDebugger) BeforeStackPop(*interpreter.State)           {}
func (d *recordingDebugger) AfterStackPop(*interpreter.State, []byte)    {}
