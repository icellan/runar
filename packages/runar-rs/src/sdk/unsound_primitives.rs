//! R-062 / CL-BUG-105 — deploy-time gate on builtins the project does not claim
//! are sound.
//!
//! The compiler refuses to emit a script reaching `verifySP1FRI` unless the
//! author wrote `@acknowledgeUnsoundSP1FriVerifier` or the invoker passed
//! `--acknowledge-unsound-sp1-fri` (R-012). That acknowledgement stopped at
//! whoever ran the compiler: the artifact handed on afterwards looked like any
//! other, carried no marker of the gap, and every SDK funded it in silence —
//! which is how an acknowledged proof-of-concept verifier reaches a
//! value-bearing deployment with no friction.
//!
//! The compiler now stamps `unsoundPrimitives` into the artifact. This guard is
//! the SDK half: the deploy path calls it BEFORE any signing or broadcast, and
//! the caller must name each listed primitive to proceed.
//!
//! Deploy only, deliberately. Spending an already-deployed contract is how
//! funds are RECOVERED from one, and refusing that would strand coins whose
//! risk was taken at deploy time. The friction belongs where the value first
//! enters.

use super::types::RunarArtifact;

/// `Err` unless every unsound primitive the artifact declares appears in
/// `acknowledged`.
pub fn assert_unsound_primitives_acknowledged(
    artifact: &RunarArtifact,
    acknowledged: &[String],
    context: &str,
) -> Result<(), String> {
    let declared = match artifact.unsound_primitives.as_ref() {
        None => return Ok(()),
        Some(d) if d.is_empty() => return Ok(()),
        Some(d) => d,
    };

    let missing: Vec<&String> = declared
        .iter()
        .filter(|p| !acknowledged.iter().any(|a| a == *p))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let names: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
    let quoted: Vec<String> = names.iter().map(|s| format!("\"{s}\".to_string()")).collect();
    Err(format!(
        "{context}: this artifact reaches {} builtin{} the compiler does not claim is sound: {}. \
         The compiler emitted it only because the gap was acknowledged at COMPILE time; \
         funding it is a second decision, and this SDK will not make it for you. \
         Set DeployOptions.acknowledge_unsound = vec![{}] to proceed",
        names.len(),
        if names.len() == 1 { "" } else { "s" },
        names.join(", "),
        quoted.join(", "),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::types::{Abi, AbiConstructor, RunarArtifact};

    fn artifact(unsound: Option<Vec<String>>) -> RunarArtifact {
        RunarArtifact {
            version: "runar-v1.0.0-rc.1".to_string(),
            contract_name: "Sp1Rollup".to_string(),
            parent_class: None,
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            asm: None,
            state_fields: None,
            constructor_slots: None,
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
            unsound_primitives: unsound,
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn ordinary_artifact_deploys_either_way() {
        for ack in [vec![], s(&["verifySP1FRI"])] {
            assert!(assert_unsound_primitives_acknowledged(&artifact(None), &ack, "Counter.deploy").is_ok());
            assert!(assert_unsound_primitives_acknowledged(&artifact(Some(vec![])), &ack, "Counter.deploy").is_ok());
        }
    }

    #[test]
    fn refuses_unacknowledged() {
        let err = assert_unsound_primitives_acknowledged(
            &artifact(Some(s(&["verifySP1FRI"]))),
            &[],
            "Sp1Rollup.deploy",
        )
        .unwrap_err();
        assert!(err.contains("verifySP1FRI"), "{err}");
        assert!(err.contains("Sp1Rollup.deploy"), "{err}");
        assert!(err.contains("acknowledge_unsound"), "{err}");
    }

    #[test]
    fn acknowledgement_must_name_every_primitive() {
        assert!(assert_unsound_primitives_acknowledged(
            &artifact(Some(s(&["verifySP1FRI"]))),
            &s(&["verifySP1FRI"]),
            "Sp1Rollup.deploy",
        )
        .is_ok());

        let err = assert_unsound_primitives_acknowledged(
            &artifact(Some(s(&["verifySP1FRI", "someFutureStub"]))),
            &s(&["verifySP1FRI"]),
            "Sp1Rollup.deploy",
        )
        .unwrap_err();
        assert!(err.contains("someFutureStub"), "{err}");

        assert!(assert_unsound_primitives_acknowledged(
            &artifact(Some(s(&["verifySP1FRI"]))),
            &s(&["somethingElse"]),
            "Sp1Rollup.deploy",
        )
        .is_err());
    }
}
