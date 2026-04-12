//! Rúnar Artifact -- the final compiled output of a Rúnar compiler.
//!
//! This is what gets consumed by wallets, SDKs, and deployment tooling.

use serde::{Deserialize, Serialize};

use crate::codegen::emit::{CodeSepIndexSlot, ConstructorSlot, SourceMapping};
use crate::ir::{ANFProgram, ANFProperty, ANFSyntheticArrayLevel};

// ---------------------------------------------------------------------------
// ABI types
// ---------------------------------------------------------------------------

/// Metadata attached to an expanded FixedArray ABI/state entry so the
/// SDK can flatten/unflatten nested JS arrays back into the underlying
/// synthetic scalar slots. Mirrors the TS `fixedArray` annotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedArrayAbiInfo {
    #[serde(rename = "elementType")]
    pub element_type: String,
    pub length: usize,
    #[serde(rename = "syntheticNames")]
    pub synthetic_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(rename = "fixedArray", skip_serializing_if = "Option::is_none")]
    pub fixed_array: Option<FixedArrayAbiInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIConstructor {
    pub params: Vec<ABIParam>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIMethod {
    pub name: String,
    pub params: Vec<ABIParam>,
    #[serde(rename = "isPublic")]
    pub is_public: bool,
    #[serde(rename = "isTerminal", skip_serializing_if = "Option::is_none")]
    pub is_terminal: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABI {
    pub constructor: ABIConstructor,
    pub methods: Vec<ABIMethod>,
}

// ---------------------------------------------------------------------------
// State fields
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub index: usize,
    #[serde(rename = "initialValue", skip_serializing_if = "Option::is_none")]
    pub initial_value: Option<serde_json::Value>,
    #[serde(rename = "fixedArray", skip_serializing_if = "Option::is_none")]
    pub fixed_array: Option<FixedArrayAbiInfo>,
}

// ---------------------------------------------------------------------------
// Source map
// ---------------------------------------------------------------------------

/// Source-level debug mappings (opcode index to source location).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMapData {
    pub mappings: Vec<SourceMapping>,
}

/// Optional IR snapshots for debugging / conformance checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRDebug {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anf: Option<ANFProgram>,
}

// ---------------------------------------------------------------------------
// Top-level artifact
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunarArtifact {
    pub version: String,
    #[serde(rename = "compilerVersion")]
    pub compiler_version: String,
    #[serde(rename = "contractName")]
    pub contract_name: String,
    pub abi: ABI,
    pub script: String,
    pub asm: String,
    #[serde(rename = "sourceMap", skip_serializing_if = "Option::is_none")]
    pub source_map: Option<SourceMapData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ir: Option<IRDebug>,
    #[serde(rename = "stateFields", skip_serializing_if = "Vec::is_empty")]
    pub state_fields: Vec<StateField>,
    #[serde(rename = "constructorSlots", skip_serializing_if = "Vec::is_empty", default)]
    pub constructor_slots: Vec<ConstructorSlot>,
    #[serde(rename = "codeSepIndexSlots", skip_serializing_if = "Vec::is_empty", default)]
    pub code_sep_index_slots: Vec<CodeSepIndexSlot>,
    #[serde(rename = "codeSeparatorIndex", skip_serializing_if = "Option::is_none")]
    pub code_separator_index: Option<usize>,
    #[serde(rename = "codeSeparatorIndices", skip_serializing_if = "Option::is_none")]
    pub code_separator_indices: Option<Vec<usize>>,
    #[serde(rename = "buildTimestamp")]
    pub build_timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anf: Option<ANFProgram>,
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

const SCHEMA_VERSION: &str = "runar-v0.4.4";
const COMPILER_VERSION: &str = "0.4.4-rust";

/// Build a RunarArtifact from the compilation products.
pub fn assemble_artifact(
    program: &ANFProgram,
    script_hex: &str,
    script_asm: &str,
    constructor_slots: Vec<ConstructorSlot>,
    code_sep_index_slots: Vec<CodeSepIndexSlot>,
    code_separator_index: i64,
    code_separator_indices: Vec<usize>,
    include_anf: bool,
    source_mappings: Vec<SourceMapping>,
) -> RunarArtifact {
    // Build constructor params from properties, excluding those with initializers
    // (properties with default values are not constructor parameters).
    // Group contiguous synthetic FixedArray leaves back into a single
    // FixedArray-typed ABI param via the iterative regrouper.
    let ctor_entries: Vec<RegroupEntry> = program
        .properties
        .iter()
        .filter(|p| p.initial_value.is_none())
        .map(regroup_entry_from_property)
        .collect();
    let ctor_regrouped = regroup_synthetic_runs(ctor_entries);
    let constructor_params: Vec<ABIParam> = ctor_regrouped
        .iter()
        .map(|e| ABIParam {
            name: e.name.clone(),
            param_type: e.r#type.clone(),
            fixed_array: e.fixed_array.clone(),
        })
        .collect();

    // Build state fields for stateful contracts.
    // Index = property position (matching constructor arg order), not sequential mutable index.
    let state_entries: Vec<RegroupEntry> = program
        .properties
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.readonly)
        .map(|(i, p)| {
            let mut e = regroup_entry_from_property(p);
            e.index = Some(i);
            e
        })
        .collect();
    let state_regrouped = regroup_synthetic_runs(state_entries);
    let state_fields: Vec<StateField> = state_regrouped
        .iter()
        .map(|e| StateField {
            name: e.name.clone(),
            field_type: e.r#type.clone(),
            index: e.index.unwrap_or(0),
            initial_value: e.initial_value.clone(),
            fixed_array: e.fixed_array.clone(),
        })
        .collect();
    let is_stateful = !state_fields.is_empty();

    // Build method ABIs (exclude constructor — it's in abi.constructor, not methods)
    let methods: Vec<ABIMethod> = program
        .methods
        .iter()
        .filter(|m| m.name != "constructor")
        .map(|m| {
            // For stateful contracts, mark public methods without _changePKH as terminal
            let is_terminal = if is_stateful && m.is_public {
                let has_change = m.params.iter().any(|p| p.name == "_changePKH");
                if !has_change { Some(true) } else { None }
            } else {
                None
            };
            ABIMethod {
                name: m.name.clone(),
                params: m
                    .params
                    .iter()
                    .map(|p| ABIParam {
                        name: p.name.clone(),
                        param_type: p.param_type.clone(),
                        fixed_array: None,
                    })
                    .collect(),
                is_public: m.is_public,
                is_terminal,
            }
        })
        .collect();

    // Timestamp
    let now = chrono_lite_utc_now();

    let cs_index = if code_separator_index >= 0 {
        Some(code_separator_index as usize)
    } else {
        None
    };
    let cs_indices = if code_separator_indices.is_empty() {
        None
    } else {
        Some(code_separator_indices)
    };

    let anf = if include_anf {
        Some(program.clone())
    } else {
        None
    };

    let source_map = if source_mappings.is_empty() {
        None
    } else {
        Some(SourceMapData {
            mappings: source_mappings,
        })
    };

    let ir = if include_anf {
        Some(IRDebug {
            anf: Some(program.clone()),
        })
    } else {
        None
    };

    RunarArtifact {
        version: SCHEMA_VERSION.to_string(),
        compiler_version: COMPILER_VERSION.to_string(),
        contract_name: program.contract_name.clone(),
        abi: ABI {
            constructor: ABIConstructor {
                params: constructor_params,
            },
            methods,
        },
        script: script_hex.to_string(),
        asm: script_asm.to_string(),
        source_map,
        ir,
        state_fields,
        constructor_slots,
        code_sep_index_slots,
        code_separator_index: cs_index,
        code_separator_indices: cs_indices,
        build_timestamp: now,
        anf,
    }
}

/// Simple UTC timestamp without pulling in the full chrono crate.
fn chrono_lite_utc_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Convert epoch seconds to a rough ISO-8601 string.
    // This is a simplified implementation; for production use chrono.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to Y-M-D (simplified leap-year-aware calculation)
    let (year, month, day) = epoch_days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil date algorithm from Howard Hinnant
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

// ---------------------------------------------------------------------------
// FixedArray regrouping
// ---------------------------------------------------------------------------
//
// Pass 3b expands FixedArray properties into scalar siblings. The assembler
// re-groups contiguous synthetic runs back into a single `fixedArray`-tagged
// ABI/state entry so SDK callers see the declared array shape.
//
// Grouping is marker-driven: every participating entry must carry a
// `synthetic_array_chain` attached at expansion time. Hand-named properties
// with underscore suffixes will never match and remain as scalars.
//
// The regrouper runs iteratively: each pass collapses one level of the
// innermost FixedArray (popping one entry off the end of every chain) and
// wraps the resulting group's type in an extra FixedArray layer. Repeat until
// no entry has any remaining chain.

#[derive(Debug, Clone)]
struct RegroupEntry {
    name: String,
    r#type: String,
    chain: Vec<ANFSyntheticArrayLevel>,
    initial_value: Option<serde_json::Value>,
    fixed_array: Option<FixedArrayAbiInfo>,
    index: Option<usize>,
}

fn regroup_entry_from_property(prop: &ANFProperty) -> RegroupEntry {
    RegroupEntry {
        name: prop.name.clone(),
        r#type: prop.prop_type.clone(),
        chain: prop
            .synthetic_array_chain
            .as_ref()
            .map(|c| c.clone())
            .unwrap_or_default(),
        initial_value: prop.initial_value.clone(),
        fixed_array: None,
        index: None,
    }
}

/// Iteratively regroup synthetic FixedArray runs until no entry has any
/// remaining chain.
fn regroup_synthetic_runs(entries: Vec<RegroupEntry>) -> Vec<RegroupEntry> {
    let mut current = entries;
    for _ in 0..1024 {
        let (out, changed) = regroup_one_pass(current);
        current = out;
        if !changed {
            return current;
        }
    }
    panic!("regroup_synthetic_runs: exceeded iteration cap (pathological chain nesting?)");
}

/// Run one pass of the iterative regrouper.
fn regroup_one_pass(entries: Vec<RegroupEntry>) -> (Vec<RegroupEntry>, bool) {
    let mut out: Vec<RegroupEntry> = Vec::with_capacity(entries.len());
    let mut changed = false;
    let mut i = 0;
    while i < entries.len() {
        let entry = &entries[i];
        let chain_len = entry.chain.len();
        if chain_len == 0 {
            out.push(entry.clone());
            i += 1;
            continue;
        }
        let marker = &entry.chain[chain_len - 1];
        if marker.index != 0 {
            out.push(entry.clone());
            i += 1;
            continue;
        }

        // Greedily extend: every follower shares the same innermost
        // `{base, length}`, carries the expected index k, and has the
        // identical current `type`.
        let mut run_indices: Vec<usize> = vec![i];
        let mut k = 1usize;
        let mut j = i + 1;
        while j < entries.len() && k < marker.length {
            let next = &entries[j];
            if next.chain.is_empty() {
                break;
            }
            let m2 = &next.chain[next.chain.len() - 1];
            if m2.base != marker.base
                || m2.length != marker.length
                || m2.index != k
                || next.r#type != entry.r#type
            {
                break;
            }
            run_indices.push(j);
            k += 1;
            j += 1;
        }

        if run_indices.len() != marker.length {
            // Partial/broken run — leave as-is.
            out.push(entry.clone());
            i += 1;
            continue;
        }

        let inner_type = entry.r#type.clone();
        let grouped_type = format!("FixedArray<{}, {}>", inner_type, marker.length);

        // Collect synthetic names — leaves contribute their own name,
        // already-grouped children contribute their `synthetic_names`.
        let mut synthetic_names: Vec<String> = Vec::new();
        for &idx in &run_indices {
            let e = &entries[idx];
            if let Some(fa) = &e.fixed_array {
                synthetic_names.extend(fa.synthetic_names.iter().cloned());
            } else {
                synthetic_names.push(e.name.clone());
            }
        }

        // Collapse initial values into a JSON array when every child has one.
        let all_have_init = run_indices.iter().all(|&idx| entries[idx].initial_value.is_some());
        let collapsed_init: Option<serde_json::Value> = if all_have_init {
            Some(serde_json::Value::Array(
                run_indices
                    .iter()
                    .map(|&idx| entries[idx].initial_value.clone().unwrap())
                    .collect(),
            ))
        } else {
            None
        };

        let mut new_chain = entry.chain.clone();
        new_chain.pop();

        let grouped = RegroupEntry {
            name: marker.base.clone(),
            r#type: grouped_type,
            chain: new_chain,
            initial_value: collapsed_init,
            fixed_array: Some(FixedArrayAbiInfo {
                element_type: inner_type,
                length: marker.length,
                synthetic_names,
            }),
            index: entries[run_indices[0]].index,
        };

        out.push(grouped);
        i = j;
        changed = true;
    }
    (out, changed)
}
