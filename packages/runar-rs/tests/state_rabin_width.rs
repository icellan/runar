//! F-035: `RabinPubKey` / `RabinSig` state fields are a bare 8-byte OP_NUM2BIN
//! word, exactly like `bigint`. Both are bigint aliases and every compiler
//! writes and reads them that way in the state section (the compiler is
//! canonical, user decision D2). The SDK width table omitted both, so they fell
//! to the push-data arm — which panics on an integer value in this tier.
//!
//! `RABIN_STATE_GOLDEN` is hand-derived and byte-identical across all seven
//! SDKs (the same three values are the `state-rabin` sdk-output fixture):
//!
//!   RabinPubKey 0x1234567890ABCDEF -> efcdab9078563412
//!   RabinSig    -1000000007        -> 07ca9a3b00000080
//!   bigint      3                  -> 0300000000000000
//!
//! Proves: the Rust codec writes and reads that layout. Does not prove the
//! script accepts it (packages/runar-testing f035-rabin-state-spend.test.ts).

use std::collections::HashMap;

use runar_lang::sdk::state::{deserialize_state, serialize_state};
use runar_lang::sdk::types::StateField;
use runar_lang::sdk::SdkValue;

const RABIN_STATE_GOLDEN: &str = concat!("efcdab9078563412", "07ca9a3b00000080", "0300000000000000");

fn field(name: &str, field_type: &str, index: usize) -> StateField {
    StateField {
        name: name.to_string(),
        field_type: field_type.to_string(),
        index,
        initial_value: None,
        fixed_array: None,
    }
}

fn rabin_fields() -> Vec<StateField> {
    vec![
        field("oracleKey", "RabinPubKey", 0),
        field("lastSig", "RabinSig", 1),
        field("count", "bigint", 2),
    ]
}

#[test]
fn rabin_state_fields_serialize_as_num2bin8() {
    let mut v: HashMap<String, SdkValue> = HashMap::new();
    v.insert("oracleKey".into(), SdkValue::BigInt(num_bigint::BigInt::from(0x1234567890ABCDEFi64)));
    v.insert("lastSig".into(), SdkValue::Int(-1000000007));
    v.insert("count".into(), SdkValue::Int(3));
    assert_eq!(serialize_state(&rabin_fields(), &v), RABIN_STATE_GOLDEN);
}

#[test]
fn rabin_state_fields_deserialize() {
    let back = deserialize_state(&rabin_fields(), RABIN_STATE_GOLDEN)
        .expect("refused the Rabin state golden");
    assert!(matches!(back["oracleKey"], SdkValue::Int(0x1234567890ABCDEF)), "{:?}", back["oracleKey"]);
    assert!(matches!(back["lastSig"], SdkValue::Int(-1000000007)), "{:?}", back["lastSig"]);
    assert!(matches!(back["count"], SdkValue::Int(3)), "{:?}", back["count"]);
}

#[test]
#[should_panic(expected = "does not fit")]
fn rabin_state_field_out_of_range_refused() {
    let mut v: HashMap<String, SdkValue> = HashMap::new();
    v.insert("k".into(), SdkValue::BigInt(num_bigint::BigInt::from(1u64 << 63)));
    serialize_state(&[field("k", "RabinPubKey", 0)], &v);
}
