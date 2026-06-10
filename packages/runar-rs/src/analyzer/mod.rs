//! Bitcoin Script static analyzer (Rust port).
//!
//! Public entry: [`analyze_script`]. See `spec/script-analyzer-format.md`
//! for the cross-tier contract. Output via [`serialize_report`] is
//! byte-identical to the canonical goldens at
//! `conformance/analyzer/<fixture>/expected-analyzer-report.json`.

#![deny(clippy::all)]
#![deny(warnings)]

pub mod opcode_concerns;
pub mod path_analyzer;
pub mod script_parser;
pub mod serializer;
pub mod sig_analyzer;
pub mod stack_analyzer;
pub mod types;

pub use serializer::serialize_report;
pub use types::{
    AnalysisResult, AnalyzeOptions, AnalyzerError, ExecutionPath, Finding, ParsedOp,
    PushEncoding, RawScriptSpan, Severity, Summary,
};

use opcode_concerns::analyze_opcode_concerns;
use path_analyzer::analyze_paths;
use script_parser::{collapse_raw_script_spans, normalize_hex, parse_script};
use sig_analyzer::analyze_sig_hygiene;
use stack_analyzer::analyze_stack_linear;

/// Analyze a hex-encoded Bitcoin Script.
///
/// Returns an [`AnalysisResult`] populated per the cross-tier spec.
pub fn analyze_script(hex_script: &str) -> Result<AnalysisResult, AnalyzerError> {
    analyze_script_with_options(hex_script, &AnalyzeOptions::default())
}

/// Variant that accepts options (currently: raw-script spans, spec §12).
pub fn analyze_script_with_options(
    hex_script: &str,
    options: &AnalyzeOptions,
) -> Result<AnalysisResult, AnalyzerError> {
    let normalized = normalize_hex(hex_script);
    let script_size_bytes = normalized.len() / 2;

    if script_size_bytes == 0 {
        // §2.1 empty-script handling.
        return Ok(AnalysisResult {
            script: String::new(),
            script_size: 0,
            findings: vec![Finding {
                severity: Severity::Error,
                code: "INVALID_TERMINAL_STACK".to_string(),
                message: "Empty script — no opcodes to execute".to_string(),
                offset: None,
                opcode: None,
                path: None,
            }],
            paths: Vec::new(),
            summary: Summary {
                total_paths: 0,
                reachable_paths: 0,
                paths_with_check_sig: 0,
                paths_without_check_sig: 0,
                max_stack_depth: 0,
                script_size_bytes: 0,
            },
        });
    }

    let mut opcodes = parse_script(&normalized);
    if !options.raw_script_spans.is_empty() {
        opcodes = collapse_raw_script_spans(opcodes, &options.raw_script_spans);
    }

    let mut all_findings: Vec<Finding> = Vec::new();

    // Step 1: paths.
    let path_result = analyze_paths(&opcodes);
    let paths = path_result.paths;
    all_findings.extend(path_result.findings);

    // Step 2: linear fallback only when zero paths AND no UNBALANCED_IF_ENDIF.
    if paths.is_empty() && !all_findings.iter().any(|f| f.code == "UNBALANCED_IF_ENDIF") {
        let lin = analyze_stack_linear(&opcodes, 0);
        all_findings.extend(lin.findings);
    }

    // Step 3: sig hygiene.
    all_findings.extend(analyze_sig_hygiene(&opcodes, &paths));

    // Step 4: opcode concerns.
    all_findings.extend(analyze_opcode_concerns(&opcodes, script_size_bytes));

    // Summary (spec §8.3).
    let reachable_paths = paths.iter().filter(|p| p.reachable).count();
    let paths_with_check_sig = paths
        .iter()
        .filter(|p| p.reachable && p.has_check_sig)
        .count();
    let paths_without_check_sig = paths
        .iter()
        .filter(|p| p.reachable && !p.has_check_sig)
        .count();
    // Spec §8.3 wording says max over paths' stackDepthAtEnd; the canonical
    // goldens however consistently show `0` when every path ends at a
    // negative depth (e.g. basic-p2pkh: stackDepthAtEnd=-1, maxStackDepth=0;
    // stateful-counter: all paths negative, maxStackDepth=0). So the
    // observable rule is `max(0, max_over_paths(stackDepthAtEnd))`. See
    // `_review/GAP-008-spec-ambiguities.md` (max-stack-depth-seed-zero).
    let max_stack_depth = paths
        .iter()
        .map(|p| p.stack_depth_at_end)
        .fold(0i64, |acc, d| acc.max(d));

    let summary = Summary {
        total_paths: paths.len(),
        reachable_paths,
        paths_with_check_sig,
        paths_without_check_sig,
        max_stack_depth,
        script_size_bytes,
    };

    // Sort findings (stable) per §11.1.
    let mut indexed: Vec<(usize, Finding)> = all_findings.into_iter().enumerate().collect();
    indexed.sort_by(|a, b| {
        let sev = a.1.severity.rank().cmp(&b.1.severity.rank());
        if sev != std::cmp::Ordering::Equal {
            return sev;
        }
        // Offsetless sorts to the end within the bucket.
        let oa = a.1.offset.map(|o| o as i128).unwrap_or(i128::MAX);
        let ob = b.1.offset.map(|o| o as i128).unwrap_or(i128::MAX);
        let off = oa.cmp(&ob);
        if off != std::cmp::Ordering::Equal {
            return off;
        }
        a.0.cmp(&b.0)
    });
    let findings: Vec<Finding> = indexed.into_iter().map(|(_, f)| f).collect();

    Ok(AnalysisResult {
        script: normalized,
        script_size: script_size_bytes,
        findings,
        paths,
        summary,
    })
}
