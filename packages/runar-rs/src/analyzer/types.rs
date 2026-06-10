//! Core types for the Bitcoin Script static analyzer.
//!
//! See `spec/script-analyzer-format.md` (NORMATIVE). Field naming and
//! optionality follow §3 of the spec.

/// Push-encoding kind for a parsed opcode. `OpN` includes OP_0, OP_1NEGATE,
/// OP_1..OP_16 (no embedded data). `Direct` is a 0x01..0x4b length-prefixed
/// push. The `pushdataN` variants carry the encoding kind but the data is
/// already attached to the [`ParsedOp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushEncoding {
    OpN,
    Direct,
    Pushdata1,
    Pushdata2,
    Pushdata4,
}

/// A single parsed opcode with byte-offset, canonical name, and optional
/// push payload / arity sidecar (for raw-span synthetic steps).
#[derive(Debug, Clone)]
pub struct ParsedOp {
    /// Byte offset within the original (normalized) script.
    pub offset: usize,
    /// Raw opcode byte. `-1` (i.e. encoded as i32) for the synthetic
    /// `RAW_SPAN` step. Stored as i16 because no real opcode exceeds u8
    /// and the sentinel is negative.
    pub opcode: i16,
    /// Canonical name per spec §4.
    pub name: String,
    /// Size of this opcode (opcode byte + length prefix + data).
    pub size: usize,
    /// Push payload data if this is a push opcode.
    pub data: Option<Vec<u8>>,
    /// Push encoding classification if this is a push opcode.
    pub push_encoding: Option<PushEncoding>,
    /// For pushdataN, the declared (not actual) data length — used by
    /// `INEFFICIENT_PUSH` analysis.
    pub declared_data_length: Option<usize>,
    /// For the synthetic `RAW_SPAN`, the `(inArity, outArity)` pair.
    pub raw_span_arity: Option<(i64, i64)>,
}

impl ParsedOp {
    pub fn is_checksig_family(&self) -> bool {
        matches!(self.opcode, 0xac..=0xaf)
    }
}

/// One range produced by a `raw_script` ANF node. Used by
/// `collapseRawScriptSpans` (spec §12).
#[derive(Debug, Clone)]
pub struct RawScriptSpan {
    pub offset: usize,
    pub length: usize,
    pub in_arity: i64,
    pub out_arity: i64,
}

/// Optional input to the public analyzer entry.
#[derive(Debug, Clone, Default)]
pub struct AnalyzeOptions {
    pub raw_script_spans: Vec<RawScriptSpan>,
}

/// Severity assigned per finding code per spec §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Severity::Error => 0,
            Severity::Warning => 1,
            Severity::Info => 2,
        }
    }
}

/// A single analyzer finding. Optional fields are `None` when absent and
/// MUST be omitted from JSON output (never serialized as `null`).
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub offset: Option<usize>,
    pub opcode: Option<String>,
    pub path: Option<String>,
}

/// One enumerated execution path.
#[derive(Debug, Clone)]
pub struct ExecutionPath {
    pub id: usize,
    pub description: String,
    pub branch_choices: Vec<bool>,
    pub reachable: bool,
    pub has_check_sig: bool,
    pub stack_depth_at_end: i64,
}

/// Summary statistics (per spec §3.4).
#[derive(Debug, Clone)]
pub struct Summary {
    pub total_paths: usize,
    pub reachable_paths: usize,
    pub paths_with_check_sig: usize,
    pub paths_without_check_sig: usize,
    pub max_stack_depth: i64,
    pub script_size_bytes: usize,
}

/// Top-level analyzer result. Tier emitter MUST serialize keys in §3.1
/// order.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub script: String,
    pub script_size: usize,
    pub findings: Vec<Finding>,
    pub paths: Vec<ExecutionPath>,
    pub summary: Summary,
}

/// Public error type from `analyze_script`.
#[derive(Debug, Clone)]
pub enum AnalyzerError {
    InvalidHex(String),
}

impl std::fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalyzerError::InvalidHex(s) => write!(f, "invalid hex: {}", s),
        }
    }
}

impl std::error::Error for AnalyzerError {}
