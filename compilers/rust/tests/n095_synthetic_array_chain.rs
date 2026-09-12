//! N-095: the synthetic-array chain on `ANFProperty` is wire data, and the
//! wire is governed by `packages/runar-ir-schema/src/schemas/anf-ir.schema.json`.
//!
//! Rust used to serialize it as `__syntheticArrayChain`. The `__` prefix is a
//! TypeScript *AST* convention for compiler-internal annotations
//! (`PropertyNode.__syntheticArrayChain`); leaking it onto the ANF JSON was an
//! AST marker escaping its layer. Three tiers spelled the field three
//! different ways and `$defs.ANFProperty` is `additionalProperties: false`, so
//! every tier that emitted it failed its own schema, and no tier could read
//! another's. The settled spelling is Go's `syntheticArrayChain`.
//!
//! The field is load-bearing: the artifact assembler regroups the expanded
//! scalar leaves back into a single FixedArray state/ABI entry by reading the
//! chain off the ANF program, not off the AST. An ANF that loses it compiles
//! to byte-identical script but degrades the SDK's `state.grid` accessor into
//! four raw scalars.

use runar_compiler_rust::{compile_from_ir_str, compile_from_source_str, compile_source_str_to_ir};
use serde_json::Value;

const GRID_SOURCE: &str = r#"import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class Grid2x2 extends StatefulSmartContract {
  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public set00(v: bigint) {
    this.grid[0][0] = v;
    assert(true);
  }

  public set11(v: bigint) {
    this.grid[1][1] = v;
    assert(true);
  }
}
"#;

const SCALAR_SOURCE: &str = r#"import { StatefulSmartContract, assert } from 'runar-lang';

export class Counter extends StatefulSmartContract {
  count: bigint = 0n;

  constructor() {
    super();
  }

  public increment() {
    this.count = this.count + 1n;
    assert(true);
  }
}
"#;

fn emit_ir(source: &str, file_name: &str) -> Value {
    let program = compile_source_str_to_ir(source, Some(file_name)).expect("compile to IR");
    serde_json::to_value(&program).expect("serialize ANF")
}

/// Every key Rust writes on an ANFProperty must be one the cross-tier schema
/// declares. `$defs.ANFProperty` is `additionalProperties: false`, so an
/// undeclared key makes Rust's own ANF fail `validateANF`.
#[test]
fn emitted_property_keys_are_all_declared_in_the_schema() {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packages/runar-ir-schema/src/schemas/anf-ir.schema.json"
    );
    let schema: Value =
        serde_json::from_str(&std::fs::read_to_string(schema_path).expect("read ANF schema"))
            .expect("parse ANF schema");
    let def = &schema["$defs"]["ANFProperty"];
    assert_eq!(
        def["additionalProperties"],
        Value::Bool(false),
        "$defs.ANFProperty is no longer additionalProperties:false — this test's \
         premise (an undeclared key is a schema violation) no longer holds"
    );
    let allowed: Vec<&String> = def["properties"]
        .as_object()
        .expect("$defs.ANFProperty.properties")
        .keys()
        .collect();

    let ir = emit_ir(GRID_SOURCE, "Grid2x2.runar.ts");
    for prop in ir["properties"].as_array().expect("properties") {
        for key in prop.as_object().expect("property object").keys() {
            assert!(
                allowed.contains(&key),
                "emitted ANFProperty key {:?} is not declared in $defs.ANFProperty; \
                 allowed = {:?}",
                key,
                allowed
            );
        }
    }
}

/// Pins the spelling and the shape of every level.
#[test]
fn expanded_leaves_carry_the_camel_case_chain() {
    let ir = emit_ir(GRID_SOURCE, "Grid2x2.runar.ts");
    let props = ir["properties"].as_array().expect("properties");
    assert_eq!(props.len(), 4, "expected 4 expanded leaves");

    let want = [(0, 0), (0, 1), (1, 0), (1, 1)];
    for (i, prop) in props.iter().enumerate() {
        let obj = prop.as_object().expect("property object");
        assert!(
            !obj.contains_key("__syntheticArrayChain"),
            "leaf {i} still carries the AST-marker spelling `__syntheticArrayChain`"
        );
        assert!(
            !obj.contains_key("synthetic_array_chain"),
            "leaf {i} still carries the snake spelling `synthetic_array_chain`"
        );
        let chain = obj
            .get("syntheticArrayChain")
            .unwrap_or_else(|| panic!("leaf {i} has no `syntheticArrayChain` key: {obj:?}"))
            .as_array()
            .expect("chain is an array");
        assert_eq!(chain.len(), 2, "leaf {i}: a 2x2 grid nests twice");
        assert_eq!(chain[0]["base"], "grid", "leaf {i} outer base");
        assert_eq!(chain[0]["index"], want[i].0, "leaf {i} outer index");
        assert_eq!(chain[0]["length"], 2, "leaf {i} outer length");
        assert_eq!(chain[1]["index"], want[i].1, "leaf {i} inner index");
        assert_eq!(chain[1]["length"], 2, "leaf {i} inner length");
    }
}

/// Byte-neutrality control: a contract with no FixedArray must not grow the key.
#[test]
fn scalar_property_carries_no_chain() {
    let ir = emit_ir(SCALAR_SOURCE, "Counter.runar.ts");
    for prop in ir["properties"].as_array().expect("properties") {
        let obj = prop.as_object().expect("property object");
        assert!(
            !obj.keys().any(|k| k.to_lowercase().contains("synthetic")),
            "a FixedArray-free contract grew a synthetic-array key: {obj:?}"
        );
    }
}

/// The acceptance test: Rust's own ANF, fed back through `--ir`, must still
/// produce the regrouped `grid` state field rather than four raw scalars.
#[test]
fn self_ir_round_trip_still_regroups() {
    let ir = emit_ir(GRID_SOURCE, "Grid2x2.runar.ts");
    let ir_json = serde_json::to_string(&ir).expect("re-serialize ANF");

    let from_source = compile_from_source_str(GRID_SOURCE, Some("Grid2x2.runar.ts"))
        .expect("compile from source");
    let from_ir = compile_from_ir_str(&ir_json).expect("compile from IR");

    for (label, artifact) in [("source", &from_source), ("ir", &from_ir)] {
        assert_eq!(
            artifact.state_fields.len(),
            1,
            "{label}: expected 1 regrouped state field, got {:?}",
            artifact
                .state_fields
                .iter()
                .map(|f| &f.name)
                .collect::<Vec<_>>()
        );
        let sf = &artifact.state_fields[0];
        assert_eq!(sf.name, "grid", "{label}: state field name");
        let fa = sf
            .fixed_array
            .as_ref()
            .unwrap_or_else(|| panic!("{label}: state field carries no fixedArray metadata"));
        assert_eq!(
            fa.synthetic_names,
            vec!["grid__0__0", "grid__0__1", "grid__1__0", "grid__1__1"],
            "{label}: syntheticNames"
        );
    }

    assert_eq!(
        from_source.script, from_ir.script,
        "script diverged between source mode and IR mode"
    );
}

/// Cross-tier direction that mattered most in practice: an ANF produced by any
/// other tier under the settled spelling must regroup here too. Go's bytes are
/// the reference, so replay its exact shape.
#[test]
fn foreign_anf_with_the_settled_spelling_regroups() {
    let mut ir = emit_ir(GRID_SOURCE, "Grid2x2.runar.ts");
    // Re-key each chain through a plain JSON rebuild, i.e. exactly what a
    // foreign tier hands us: no Rust types involved.
    let props = ir["properties"].as_array().expect("properties").clone();
    let rebuilt: Vec<Value> = props
        .iter()
        .map(|p| {
            let obj = p.as_object().expect("property object");
            let mut out = serde_json::Map::new();
            out.insert("name".into(), obj["name"].clone());
            out.insert("type".into(), obj["type"].clone());
            out.insert("readonly".into(), obj["readonly"].clone());
            if let Some(v) = obj.get("initialValue") {
                out.insert("initialValue".into(), v.clone());
            }
            out.insert(
                "syntheticArrayChain".into(),
                obj["syntheticArrayChain"].clone(),
            );
            Value::Object(out)
        })
        .collect();
    ir["properties"] = Value::Array(rebuilt);

    let artifact = compile_from_ir_str(&serde_json::to_string(&ir).expect("serialize"))
        .expect("compile from foreign IR");
    assert_eq!(artifact.state_fields.len(), 1);
    assert_eq!(artifact.state_fields[0].name, "grid");
    assert!(artifact.state_fields[0].fixed_array.is_some());
}
