// Package analyzer implements the Rúnar Bitcoin Script static analyzer.
//
// The analyzer is a pure-Go port of the cross-tier specification at
// spec/script-analyzer-format.md. It reads a hex-encoded locking script
// and emits a structured report (findings + spending paths + summary)
// that is byte-identical with the goldens at
// conformance/analyzer/<fixture>/expected-analyzer-report.json.
package analyzer

// Severity enumerates the three finding severities. The lower the
// numeric value, the earlier the finding sorts.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Finding is the per-issue record emitted by every analyzer pass.
//
// Optional fields use Go's natural zero values plus a separate "Has*"
// boolean so that the canonical JSON marshaller in this package can
// drop them when absent (the spec mandates omission rather than null).
type Finding struct {
	Severity  Severity
	Code      string
	Message   string
	Offset    int
	HasOffset bool
	Opcode    string
	HasOpcode bool
	Path      string
	HasPath   bool
}

// ExecutionPath is a single enumerated spending path.
type ExecutionPath struct {
	ID              int
	Description     string
	BranchChoices   []bool
	Reachable       bool
	HasCheckSig     bool
	StackDepthAtEnd int
}

// Summary is the per-script roll-up.
type Summary struct {
	TotalPaths           int
	ReachablePaths       int
	PathsWithCheckSig    int
	PathsWithoutCheckSig int
	MaxStackDepth        int
	ScriptSizeBytes      int
}

// AnalyzerReport is the top-level result.
type AnalyzerReport struct {
	Script     string
	ScriptSize int
	Findings   []Finding
	Paths      []ExecutionPath
	Summary    Summary
}

// RawScriptSpan describes a contiguous span of script bytes that should
// be treated as an opaque "raw script" emission with the given arity.
// Spec §12.
type RawScriptSpan struct {
	Offset   int
	Length   int
	InArity  int
	OutArity int
}

// AnalyzeOptions controls optional analyzer behaviour.
type AnalyzeOptions struct {
	RawScriptSpans []RawScriptSpan
}

// Opcode is a single parsed script step (real opcode or synthetic
// raw-span placeholder).
type Opcode struct {
	// Offset is the byte position in the normalized script. For the
	// synthetic raw-span step this is span.Offset.
	Offset int
	// Opcode is the raw byte value, or -1 for the synthetic raw-span
	// step (so it can never collide with any real opcode comparison).
	Opcode int
	// Name is the canonical opcode name from §4 (e.g. "OP_DUP",
	// "PUSH_20", "OP_UNKNOWN(0x62)", "RAW_SPAN").
	Name string
	// Size is the total number of script bytes consumed by this opcode
	// (1 for non-push, 1+len for direct push, 1+lenBytes+len for
	// pushdata*, span.Length for the synthetic step).
	Size int
	// Data holds the payload bytes for push opcodes; nil otherwise.
	Data []byte
	// PushEncoding classifies push-style ops: "direct", "pushdata1",
	// "pushdata2", "pushdata4", "opN", or "" for non-push.
	PushEncoding string
	// RawSpanArity carries (in, out) for the synthetic RAW_SPAN step.
	RawSpanArity [2]int
	// IsRawSpan flags the synthetic step.
	IsRawSpan bool
}

// Opcode bytes referenced explicitly by the algorithm.
const (
	opIf                 = 0x63
	opNotIf              = 0x64
	opElse               = 0x67
	opEndIf              = 0x68
	opVerify             = 0x69
	opReturn             = 0x6a
	opDrop               = 0x75
	opEqualVerify        = 0x88
	opNumEqualVerify     = 0x9d
	opCodeSeparator      = 0xab
	opCheckSig           = 0xac
	opCheckSigVerify     = 0xad
	opCheckMultiSig      = 0xae
	opCheckMultiSigVerify = 0xaf
)

// Hardcoded thresholds (spec §14).
const (
	maxPaths             = 256
	largeScriptThreshold = 500_000
)
