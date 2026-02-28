//! TSOP Artifact -- the final compiled output of a TSOP compiler.
//!
//! This is what gets consumed by wallets, SDKs, and deployment tooling.

use serde::{Deserialize, Serialize};

use crate::ir::ANFProgram;

// ---------------------------------------------------------------------------
// ABI types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
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
}

// ---------------------------------------------------------------------------
// Top-level artifact
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TSOPArtifact {
    pub version: String,
    #[serde(rename = "compilerVersion")]
    pub compiler_version: String,
    #[serde(rename = "contractName")]
    pub contract_name: String,
    pub abi: ABI,
    pub script: String,
    pub asm: String,
    #[serde(rename = "stateFields", skip_serializing_if = "Vec::is_empty")]
    pub state_fields: Vec<StateField>,
    #[serde(rename = "buildTimestamp")]
    pub build_timestamp: String,
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

const SCHEMA_VERSION: &str = "tsop-v0.1.0";
const COMPILER_VERSION: &str = "0.1.0-rust";

/// Build a TSOPArtifact from the compilation products.
pub fn assemble_artifact(
    program: &ANFProgram,
    script_hex: &str,
    script_asm: &str,
) -> TSOPArtifact {
    // Build constructor params from properties
    let constructor_params: Vec<ABIParam> = program
        .properties
        .iter()
        .map(|p| ABIParam {
            name: p.name.clone(),
            param_type: p.prop_type.clone(),
        })
        .collect();

    // Build method ABIs
    let methods: Vec<ABIMethod> = program
        .methods
        .iter()
        .map(|m| ABIMethod {
            name: m.name.clone(),
            params: m
                .params
                .iter()
                .map(|p| ABIParam {
                    name: p.name.clone(),
                    param_type: p.param_type.clone(),
                })
                .collect(),
            is_public: m.is_public,
        })
        .collect();

    // Build state fields for stateful contracts
    let mut state_fields = Vec::new();
    let mut index = 0;
    for prop in &program.properties {
        if !prop.readonly {
            state_fields.push(StateField {
                name: prop.name.clone(),
                field_type: prop.prop_type.clone(),
                index,
            });
            index += 1;
        }
    }

    // Timestamp
    let now = chrono_lite_utc_now();

    TSOPArtifact {
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
        state_fields,
        build_timestamp: now,
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

fn epoch_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
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
