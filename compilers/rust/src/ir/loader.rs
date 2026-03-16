//! ANF IR loader — reads and validates ANF IR from JSON.

use std::fs;
use std::path::Path;

use super::{ANFBinding, ANFProgram, ANFValue};

/// Load an ANF IR program from a JSON file on disk.
pub fn load_ir(path: &Path) -> Result<ANFProgram, String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("reading IR file: {}", e))?;
    load_ir_from_str(&data)
}

/// Load an ANF IR program from a JSON string.
pub fn load_ir_from_str(json_str: &str) -> Result<ANFProgram, String> {
    let program: ANFProgram = serde_json::from_str(json_str)
        .map_err(|e| format!("invalid IR JSON: {}", e))?;
    validate_ir(&program)?;
    Ok(program)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Known ANF value kinds.
const KNOWN_KINDS: &[&str] = &[
    "load_param",
    "load_prop",
    "load_const",
    "bin_op",
    "unary_op",
    "call",
    "method_call",
    "if",
    "loop",
    "assert",
    "update_prop",
    "get_state_script",
    "check_preimage",
    "deserialize_state",
    "add_output",
    "add_raw_output",
    "array_literal",
];

fn kind_name(value: &ANFValue) -> &'static str {
    match value {
        ANFValue::LoadParam { .. } => "load_param",
        ANFValue::LoadProp { .. } => "load_prop",
        ANFValue::LoadConst { .. } => "load_const",
        ANFValue::BinOp { .. } => "bin_op",
        ANFValue::UnaryOp { .. } => "unary_op",
        ANFValue::Call { .. } => "call",
        ANFValue::MethodCall { .. } => "method_call",
        ANFValue::If { .. } => "if",
        ANFValue::Loop { .. } => "loop",
        ANFValue::Assert { .. } => "assert",
        ANFValue::UpdateProp { .. } => "update_prop",
        ANFValue::GetStateScript { .. } => "get_state_script",
        ANFValue::CheckPreimage { .. } => "check_preimage",
        ANFValue::DeserializeState { .. } => "deserialize_state",
        ANFValue::AddOutput { .. } => "add_output",
        ANFValue::AddRawOutput { .. } => "add_raw_output",
        ANFValue::ArrayLiteral { .. } => "array_literal",
    }
}

fn validate_ir(program: &ANFProgram) -> Result<(), String> {
    if program.contract_name.is_empty() {
        return Err("IR validation: contractName is required".into());
    }

    for (i, prop) in program.properties.iter().enumerate() {
        if prop.name.is_empty() {
            return Err(format!("IR validation: property[{}] has empty name", i));
        }
        if prop.prop_type.is_empty() {
            return Err(format!(
                "IR validation: property {} has empty type",
                prop.name
            ));
        }
    }

    for (i, method) in program.methods.iter().enumerate() {
        if method.name.is_empty() {
            return Err(format!("IR validation: method[{}] has empty name", i));
        }
        for (j, param) in method.params.iter().enumerate() {
            if param.name.is_empty() {
                return Err(format!(
                    "IR validation: method {} param[{}] has empty name",
                    method.name, j
                ));
            }
            if param.param_type.is_empty() {
                return Err(format!(
                    "IR validation: method {} param {} has empty type",
                    method.name, param.name
                ));
            }
        }
        validate_bindings(&method.body, &method.name)?;
    }

    Ok(())
}

fn validate_bindings(bindings: &[ANFBinding], method_name: &str) -> Result<(), String> {
    for (i, binding) in bindings.iter().enumerate() {
        if binding.name.is_empty() {
            return Err(format!(
                "IR validation: method {} binding[{}] has empty name",
                method_name, i
            ));
        }

        let kind = kind_name(&binding.value);
        if !KNOWN_KINDS.contains(&kind) {
            return Err(format!(
                "IR validation: method {} binding {} has unknown kind {:?}",
                method_name, binding.name, kind
            ));
        }

        // Validate nested bindings
        match &binding.value {
            ANFValue::If {
                then, else_branch, ..
            } => {
                validate_bindings(then, method_name)?;
                validate_bindings(else_branch, method_name)?;
            }
            ANFValue::Loop { body, .. } => {
                validate_bindings(body, method_name)?;
            }
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ANFMethod, ANFParam, ANFProgram, ANFProperty};

    // -----------------------------------------------------------------------
    // Valid minimal JSON
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_ir_minimal_valid() {
        let json = r#"{
            "contractName": "P2PKH",
            "properties": [
                { "name": "pubKeyHash", "type": "Ripemd160", "readonly": true }
            ],
            "methods": [
                {
                    "name": "unlock",
                    "params": [
                        { "name": "sig", "type": "Sig" },
                        { "name": "pubKey", "type": "PubKey" }
                    ],
                    "body": [
                        { "name": "_t0", "value": { "kind": "load_param", "name": "sig" } },
                        { "name": "_t1", "value": { "kind": "load_param", "name": "pubKey" } },
                        { "name": "_t2", "value": { "kind": "call", "func": "checkSig", "args": ["_t0", "_t1"] } },
                        { "name": "_t3", "value": { "kind": "assert", "value": "_t2" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let program = load_ir_from_str(json).expect("should parse valid minimal IR");
        assert_eq!(program.contract_name, "P2PKH");
        assert_eq!(program.properties.len(), 1);
        assert_eq!(program.properties[0].name, "pubKeyHash");
        assert_eq!(program.methods.len(), 1);
        assert_eq!(program.methods[0].name, "unlock");
        assert_eq!(program.methods[0].params.len(), 2);
        assert_eq!(program.methods[0].body.len(), 4);
    }

    #[test]
    fn test_load_ir_empty_methods_valid() {
        let json = r#"{
            "contractName": "Empty",
            "properties": [],
            "methods": [
                {
                    "name": "noop",
                    "params": [],
                    "body": [
                        { "name": "_t0", "value": { "kind": "load_const", "value": true } },
                        { "name": "_t1", "value": { "kind": "assert", "value": "_t0" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let program = load_ir_from_str(json).expect("should parse empty-properties IR");
        assert_eq!(program.contract_name, "Empty");
        assert!(program.properties.is_empty());
    }

    #[test]
    fn test_load_ir_load_const_types() {
        let json = r#"{
            "contractName": "ConstTest",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [],
                    "body": [
                        { "name": "_t0", "value": { "kind": "load_const", "value": 42 } },
                        { "name": "_t1", "value": { "kind": "load_const", "value": true } },
                        { "name": "_t2", "value": { "kind": "load_const", "value": "deadbeef" } },
                        { "name": "_t3", "value": { "kind": "assert", "value": "_t1" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let program = load_ir_from_str(json).expect("should parse various load_const types");
        let body = &program.methods[0].body;
        // Check int const
        if let ANFValue::LoadConst { value } = &body[0].value {
            assert_eq!(value.as_i64(), Some(42));
        } else {
            panic!("expected LoadConst for _t0");
        }
        // Check bool const
        if let ANFValue::LoadConst { value } = &body[1].value {
            assert_eq!(value.as_bool(), Some(true));
        } else {
            panic!("expected LoadConst for _t1");
        }
        // Check string const
        if let ANFValue::LoadConst { value } = &body[2].value {
            assert_eq!(value.as_str(), Some("deadbeef"));
        } else {
            panic!("expected LoadConst for _t2");
        }
    }

    // -----------------------------------------------------------------------
    // Validation errors
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_ir_empty_contract_name_error() {
        let json = r#"{
            "contractName": "",
            "properties": [],
            "methods": []
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("contractName is required"),
            "expected contractName error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_property_name_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [
                { "name": "", "type": "bigint", "readonly": true }
            ],
            "methods": []
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty name"),
            "expected empty name error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_property_type_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [
                { "name": "x", "type": "", "readonly": true }
            ],
            "methods": []
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty type"),
            "expected empty type error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_method_name_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                { "name": "", "params": [], "body": [], "isPublic": true }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty name"),
            "expected empty method name error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_param_name_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [{ "name": "", "type": "bigint" }],
                    "body": [],
                    "isPublic": true
                }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty name"),
            "expected empty param name error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_param_type_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [{ "name": "x", "type": "" }],
                    "body": [],
                    "isPublic": true
                }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty type"),
            "expected empty param type error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_binding_name_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [],
                    "body": [
                        { "name": "", "value": { "kind": "load_const", "value": 1 } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty name"),
            "expected empty binding name error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_invalid_json_error() {
        let json = "{ this is not valid json }";
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("invalid IR JSON"),
            "expected JSON parse error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_unknown_kind_in_json() {
        // serde(tag = "kind") will fail to deserialize an unknown kind variant
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [],
                    "body": [
                        { "name": "_t0", "value": { "kind": "unknown_kind_xyz" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        // serde rejects unrecognized "kind" tags at the deserialization level
        assert!(
            err.contains("invalid IR JSON"),
            "expected deserialization error for unknown kind, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // Round-trip: construct -> serialize -> load
    // -----------------------------------------------------------------------

    #[test]
    fn test_round_trip_serialize_deserialize() {
        let program = ANFProgram {
            contract_name: "RoundTrip".to_string(),
            properties: vec![ANFProperty {
                name: "count".to_string(),
                prop_type: "bigint".to_string(),
                readonly: false,
                initial_value: None,
            }],
            methods: vec![ANFMethod {
                name: "increment".to_string(),
                params: vec![ANFParam {
                    name: "amount".to_string(),
                    param_type: "bigint".to_string(),
                }],
                body: vec![
                    ANFBinding {
                        name: "_t0".to_string(),
                        value: ANFValue::LoadParam {
                            name: "amount".to_string(),
                        },
                    },
                    ANFBinding {
                        name: "_t1".to_string(),
                        value: ANFValue::LoadProp {
                            name: "count".to_string(),
                        },
                    },
                    ANFBinding {
                        name: "_t2".to_string(),
                        value: ANFValue::BinOp {
                            op: "+".to_string(),
                            left: "_t1".to_string(),
                            right: "_t0".to_string(),
                            result_type: Some("bigint".to_string()),
                        },
                    },
                    ANFBinding {
                        name: "_t3".to_string(),
                        value: ANFValue::UpdateProp {
                            name: "count".to_string(),
                            value: "_t2".to_string(),
                        },
                    },
                ],
                is_public: true,
            }],
        };

        let json = serde_json::to_string(&program).expect("serialization should succeed");
        let loaded = load_ir_from_str(&json).expect("round-trip load should succeed");

        assert_eq!(loaded.contract_name, "RoundTrip");
        assert_eq!(loaded.properties.len(), 1);
        assert_eq!(loaded.properties[0].name, "count");
        assert!(!loaded.properties[0].readonly);
        assert_eq!(loaded.methods.len(), 1);
        assert_eq!(loaded.methods[0].name, "increment");
        assert_eq!(loaded.methods[0].params.len(), 1);
        assert_eq!(loaded.methods[0].body.len(), 4);

        // Verify specific binding kinds survived the round-trip
        assert!(matches!(&loaded.methods[0].body[0].value, ANFValue::LoadParam { name } if name == "amount"));
        assert!(matches!(&loaded.methods[0].body[1].value, ANFValue::LoadProp { name } if name == "count"));
        assert!(matches!(&loaded.methods[0].body[2].value, ANFValue::BinOp { op, .. } if op == "+"));
        assert!(matches!(&loaded.methods[0].body[3].value, ANFValue::UpdateProp { name, .. } if name == "count"));
    }

    #[test]
    fn test_round_trip_with_initial_value() {
        let program = ANFProgram {
            contract_name: "InitTest".to_string(),
            properties: vec![ANFProperty {
                name: "value".to_string(),
                prop_type: "bigint".to_string(),
                readonly: true,
                initial_value: Some(serde_json::json!(100)),
            }],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![],
                body: vec![
                    ANFBinding {
                        name: "_t0".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::json!(true),
                        },
                    },
                    ANFBinding {
                        name: "_t1".to_string(),
                        value: ANFValue::Assert {
                            value: "_t0".to_string(),
                        },
                    },
                ],
                is_public: true,
            }],
        };

        let json = serde_json::to_string(&program).expect("serialization should succeed");
        let loaded = load_ir_from_str(&json).expect("round-trip load should succeed");

        assert_eq!(loaded.properties[0].initial_value, Some(serde_json::json!(100)));
    }

    #[test]
    fn test_round_trip_if_and_loop() {
        let program = ANFProgram {
            contract_name: "Nested".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "test".to_string(),
                params: vec![],
                body: vec![
                    ANFBinding {
                        name: "_cond".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::json!(true),
                        },
                    },
                    ANFBinding {
                        name: "_if".to_string(),
                        value: ANFValue::If {
                            cond: "_cond".to_string(),
                            then: vec![ANFBinding {
                                name: "_t".to_string(),
                                value: ANFValue::LoadConst {
                                    value: serde_json::json!(1),
                                },
                            }],
                            else_branch: vec![ANFBinding {
                                name: "_e".to_string(),
                                value: ANFValue::LoadConst {
                                    value: serde_json::json!(2),
                                },
                            }],
                        },
                    },
                    ANFBinding {
                        name: "_loop".to_string(),
                        value: ANFValue::Loop {
                            count: 5,
                            body: vec![ANFBinding {
                                name: "_lb".to_string(),
                                value: ANFValue::LoadConst {
                                    value: serde_json::json!(0),
                                },
                            }],
                            iter_var: "i".to_string(),
                        },
                    },
                ],
                is_public: true,
            }],
        };

        let json = serde_json::to_string(&program).expect("serialization should succeed");
        let loaded = load_ir_from_str(&json).expect("round-trip load should succeed");

        // Verify If survived
        if let ANFValue::If { cond, then, else_branch } = &loaded.methods[0].body[1].value {
            assert_eq!(cond, "_cond");
            assert_eq!(then.len(), 1);
            assert_eq!(else_branch.len(), 1);
        } else {
            panic!("expected If binding");
        }

        // Verify Loop survived
        if let ANFValue::Loop { count, body, iter_var } = &loaded.methods[0].body[2].value {
            assert_eq!(*count, 5);
            assert_eq!(body.len(), 1);
            assert_eq!(iter_var, "i");
        } else {
            panic!("expected Loop binding");
        }
    }

    // -----------------------------------------------------------------------
    // I9: loadIR — empty param type rejected
    // Method param with `type: ""` → Err result
    // -----------------------------------------------------------------------

    #[test]
    fn test_i9_load_ir_empty_param_type_rejected() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [{ "name": "x", "type": "" }],
                    "body": [
                        { "name": "_t0", "value": { "kind": "load_const", "value": true } },
                        { "name": "_t1", "value": { "kind": "assert", "value": "_t0" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let result = load_ir_from_str(json);
        assert!(
            result.is_err(),
            "method param with empty type should produce an Err; got: {:?}",
            result.ok()
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("empty type") || err.contains("type") || err.contains("param"),
            "error should mention empty type or param; got: {}",
            err
        );
    }
}
