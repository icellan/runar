//! Pass 2/3: branch matching + path enumeration + per-path findings.
//! See spec §7.

use super::stack_analyzer::{analyze_stack_linear, stack_effect};
use super::types::{ExecutionPath, Finding, ParsedOp, Severity};

#[derive(Debug, Clone)]
struct OpenFrame {
    if_index: usize,
    else_index: i64, // -1 means no ELSE
    is_notif: bool,
}

#[derive(Debug, Clone)]
struct ClosedBranch {
    if_index: usize,
    else_index: i64,
    endif_index: usize,
}

pub struct PathAnalysis {
    pub paths: Vec<ExecutionPath>,
    pub findings: Vec<Finding>,
}

/// Top-level `analyzePaths` per spec §7.
pub fn analyze_paths(opcodes: &[ParsedOp]) -> PathAnalysis {
    let mut findings: Vec<Finding> = Vec::new();

    // 1. Branch matching (spec §7.1).
    let mut open: Vec<OpenFrame> = Vec::new();
    let mut closed: Vec<ClosedBranch> = Vec::new();
    let mut had_structural_error = false;

    for (i, op) in opcodes.iter().enumerate() {
        match op.opcode {
            0x63 | 0x64 => {
                open.push(OpenFrame {
                    if_index: i,
                    else_index: -1,
                    is_notif: op.opcode == 0x64,
                });
            }
            0x67 => {
                if let Some(top) = open.last_mut() {
                    top.else_index = i as i64;
                } else {
                    findings.push(Finding {
                        severity: Severity::Error,
                        code: "UNBALANCED_IF_ENDIF".to_string(),
                        message: "OP_ELSE without matching OP_IF".to_string(),
                        offset: Some(op.offset),
                        opcode: Some(op.name.clone()),
                        path: None,
                    });
                    had_structural_error = true;
                }
            }
            0x68 => {
                if let Some(frame) = open.pop() {
                    closed.push(ClosedBranch {
                        if_index: frame.if_index,
                        else_index: frame.else_index,
                        endif_index: i,
                    });
                } else {
                    findings.push(Finding {
                        severity: Severity::Error,
                        code: "UNBALANCED_IF_ENDIF".to_string(),
                        message: "OP_ENDIF without matching OP_IF".to_string(),
                        offset: Some(op.offset),
                        opcode: Some(op.name.clone()),
                        path: None,
                    });
                    had_structural_error = true;
                }
            }
            _ => {}
        }
    }
    for frame in &open {
        let op = &opcodes[frame.if_index];
        findings.push(Finding {
            severity: Severity::Error,
            code: "UNBALANCED_IF_ENDIF".to_string(),
            message: format!(
                "{} at offset {} has no matching OP_ENDIF",
                op.name, op.offset
            ),
            offset: Some(op.offset),
            opcode: Some(op.name.clone()),
            path: None,
        });
        had_structural_error = true;
        let _ = frame.is_notif;
    }
    if had_structural_error {
        return PathAnalysis {
            paths: Vec::new(),
            findings,
        };
    }

    let if_indices: Vec<usize> = opcodes
        .iter()
        .enumerate()
        .filter_map(|(i, op)| {
            if op.opcode == 0x63 || op.opcode == 0x64 {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    let num_branches = if_indices.len();

    let mut paths: Vec<ExecutionPath> = Vec::new();
    let mut per_path_findings: Vec<Finding> = Vec::new();

    if num_branches == 0 {
        let collected: Vec<ParsedOp> = opcodes
            .iter()
            .filter(|op| !matches!(op.opcode, 0x63 | 0x64 | 0x67 | 0x68))
            .cloned()
            .collect();
        let path = build_path(0, "linear (no branches)".to_string(), Vec::new(), &collected);
        emit_path_findings(&path, &collected, &mut per_path_findings);
        paths.push(path);
    } else {
        // For num_branches >= 53, 2^num_branches overflows the JS
        // safe-integer range used by the canonical TS reference, so we
        // render the count symbolically as "more than 2^53 paths" instead
        // of an exact decimal. (Spec v1.2.)
        const LARGE_BRANCH_THRESHOLD: usize = 53;
        let use_exact_count = num_branches < LARGE_BRANCH_THRESHOLD;
        let limit: u64 = if use_exact_count {
            let exact: u64 = 1u64 << num_branches;
            exact.min(256)
        } else {
            256
        };

        let truncated = if use_exact_count {
            (1u64 << num_branches) > 256
        } else {
            true
        };
        if truncated {
            let paths_clause = if use_exact_count {
                let exact: u64 = 1u64 << num_branches;
                format!("2^{} = {} paths", num_branches, exact)
            } else {
                format!("more than 2^{} paths", LARGE_BRANCH_THRESHOLD)
            };
            per_path_findings.push(Finding {
                severity: Severity::Warning,
                code: "PATHS_TRUNCATED".to_string(),
                message: format!(
                    "Script has {} branch points ({}); analysis truncated to the first 256. Consider reducing branching or splitting the contract into smaller spending paths.",
                    num_branches, paths_clause
                ),
                offset: None,
                opcode: None,
                path: None,
            });
        }

        for combo in 0..limit {
            // `combo` is bounded by 256, so bits at positions >= 8 are
            // mathematically always 0. We explicitly clamp to b < 31 to
            // match the canonical TS reference, where JS `>>` would
            // otherwise mask the shift count to 5 bits and wrap.
            let mut choices: Vec<bool> = Vec::with_capacity(num_branches);
            for b in 0..num_branches {
                let bit = if b < 31 { (combo >> (b as u32)) & 1 } else { 0 };
                choices.push(bit == 1);
            }
            let description = describe_path(&choices, &if_indices, opcodes);
            let collected = collect_per_path_opcodes(opcodes, &choices, &closed);
            let path = build_path(combo as usize, description, choices, &collected);
            emit_path_findings(&path, &collected, &mut per_path_findings);
            paths.push(path);
        }
    }

    // Branch-depth checks (spec §7.6).
    let mut branch_depth_findings: Vec<Finding> = Vec::new();
    for branch in &closed {
        let endif_op = &opcodes[branch.endif_index];
        if branch.else_index < 0 {
            if range_contains_nested_if(opcodes, branch.if_index + 1, branch.endif_index) {
                continue;
            }
            let delta = flat_delta(opcodes, branch.if_index + 1, branch.endif_index);
            if delta != 0 {
                branch_depth_findings.push(Finding {
                    severity: Severity::Warning,
                    code: "INCONSISTENT_BRANCH_DEPTH".to_string(),
                    message: format!(
                        "OP_IF body has net stack delta {}; without an OP_ELSE the depth after OP_ENDIF depends on the branch condition",
                        delta
                    ),
                    offset: Some(endif_op.offset),
                    opcode: Some("OP_ENDIF".to_string()),
                    path: None,
                });
            }
        } else {
            let else_idx = branch.else_index as usize;
            if range_contains_nested_if(opcodes, branch.if_index + 1, else_idx)
                || range_contains_nested_if(opcodes, else_idx + 1, branch.endif_index)
            {
                continue;
            }
            let t_delta = flat_delta(opcodes, branch.if_index + 1, else_idx);
            let e_delta = flat_delta(opcodes, else_idx + 1, branch.endif_index);
            if t_delta != e_delta {
                branch_depth_findings.push(Finding {
                    severity: Severity::Warning,
                    code: "INCONSISTENT_BRANCH_DEPTH".to_string(),
                    message: format!(
                        "IF/ELSE branches leave different stack depths (THEN: {}, ELSE: {}) — code after OP_ENDIF will see a depth that depends on which branch ran",
                        t_delta, e_delta
                    ),
                    offset: Some(endif_op.offset),
                    opcode: Some("OP_ENDIF".to_string()),
                    path: None,
                });
            }
        }
    }

    findings.extend(per_path_findings);
    findings.extend(branch_depth_findings);

    PathAnalysis { paths, findings }
}

fn range_contains_nested_if(opcodes: &[ParsedOp], start: usize, end: usize) -> bool {
    for op in opcodes.iter().take(end).skip(start) {
        if op.opcode == 0x63 || op.opcode == 0x64 {
            return true;
        }
    }
    false
}

fn flat_delta(opcodes: &[ParsedOp], start: usize, end: usize) -> i64 {
    let mut delta = 0i64;
    for op in opcodes.iter().take(end).skip(start) {
        if op.opcode == 0x67 || op.opcode == 0x68 {
            continue;
        }
        let (pops, pushes) = stack_effect(op);
        delta += pushes - pops;
    }
    delta
}

fn describe_path(choices: &[bool], if_indices: &[usize], opcodes: &[ParsedOp]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(choices.len());
    for (i, &choice) in choices.iter().enumerate() {
        let op = &opcodes[if_indices[i]];
        let label = if op.opcode == 0x64 { "NOTIF" } else { "IF" };
        parts.push(format!(
            "{}[{}] at {}",
            label,
            if choice { "true" } else { "false" },
            op.offset
        ));
    }
    parts.join(" -> ")
}

/// Collect per-path opcodes (spec §7.4). IF/NOTIF/ELSE/ENDIF themselves
/// are NOT included. The `choices` vector is consumed in TRAVERSAL order:
/// only IFs actually visited consume a choice. IFs in skipped bodies are
/// never reached.
fn collect_per_path_opcodes(
    opcodes: &[ParsedOp],
    choices: &[bool],
    branches: &[ClosedBranch],
) -> Vec<ParsedOp> {
    let mut by_if: std::collections::HashMap<usize, (i64, usize)> =
        std::collections::HashMap::with_capacity(branches.len());
    for b in branches {
        by_if.insert(b.if_index, (b.else_index, b.endif_index));
    }
    let mut out: Vec<ParsedOp> = Vec::new();
    let mut choice_pos = 0usize;
    walk_range(opcodes, 0, opcodes.len(), &by_if, choices, &mut choice_pos, &mut out);
    out
}

/// Walk a half-open opcode range `[start, end)`, emitting opcodes for the
/// taken half of each IF/NOTIF. Shared choice counter is advanced in
/// traversal order.
fn walk_range(
    opcodes: &[ParsedOp],
    start: usize,
    end: usize,
    by_if: &std::collections::HashMap<usize, (i64, usize)>,
    choices: &[bool],
    choice_pos: &mut usize,
    out: &mut Vec<ParsedOp>,
) {
    let mut i = start;
    while i < end {
        let op = &opcodes[i];
        match op.opcode {
            0x63 | 0x64 => {
                let (else_idx, endif_idx) = match by_if.get(&i) {
                    Some(&v) => v,
                    None => {
                        i += 1;
                        continue;
                    }
                };
                let choice = if *choice_pos < choices.len() {
                    choices[*choice_pos]
                } else {
                    true
                };
                *choice_pos += 1;
                if choice {
                    let end_of_then = if else_idx >= 0 {
                        else_idx as usize
                    } else {
                        endif_idx
                    };
                    walk_range(opcodes, i + 1, end_of_then, by_if, choices, choice_pos, out);
                } else if else_idx >= 0 {
                    let else_start = else_idx as usize + 1;
                    walk_range(opcodes, else_start, endif_idx, by_if, choices, choice_pos, out);
                }
                i = endif_idx + 1;
            }
            0x67 | 0x68 => {
                // Defensive — shouldn't be hit unless the range is malformed.
                i += 1;
            }
            _ => {
                out.push(op.clone());
                i += 1;
            }
        }
    }
}

fn build_path(
    id: usize,
    description: String,
    branch_choices: Vec<bool>,
    collected: &[ParsedOp],
) -> ExecutionPath {
    let lin = analyze_stack_linear(collected, 0);
    let has_check_sig = collected.iter().any(|op| op.is_checksig_family());
    ExecutionPath {
        id,
        description,
        branch_choices,
        reachable: true,
        has_check_sig,
        stack_depth_at_end: lin.depth_at_end,
    }
}

fn emit_path_findings(path: &ExecutionPath, collected: &[ParsedOp], findings: &mut Vec<Finding>) {
    let lin = analyze_stack_linear(collected, 0);
    for mut f in lin.findings.into_iter() {
        f.path = Some(path.description.clone());
        findings.push(f);
    }

    if !collected.is_empty() {
        let has_verifier = collected.iter().any(|op| {
            matches!(
                op.opcode,
                0x69 | 0x6a | 0x88 | 0x9d | 0xac | 0xad | 0xae | 0xaf
            )
        });
        if !has_verifier {
            findings.push(Finding {
                severity: Severity::Warning,
                code: "UNCONDITIONALLY_SUCCEEDS".to_string(),
                message: "Execution path has no verification opcode — any unlocking input will satisfy it".to_string(),
                offset: None,
                opcode: None,
                path: Some(path.description.clone()),
            });
        }
    }
}
