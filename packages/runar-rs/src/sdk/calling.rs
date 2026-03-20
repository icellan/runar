//! Transaction construction for contract method invocation.

use super::types::Utxo;
use super::deployment::{
    to_little_endian_32, to_little_endian_64, encode_varint, reverse_hex,
    build_p2pkh_script_from_address,
};

/// A contract output specification (script + satoshis).
pub struct ContractOutput {
    pub script: String,
    pub satoshis: i64,
}

/// An additional contract input with its own unlocking script (for merge).
pub struct AdditionalContractInput {
    pub utxo: Utxo,
    pub unlocking_script: String,
}

/// Extended options for `build_call_transaction`.
pub struct CallTxOptions {
    /// Multiple contract outputs (replaces single newLockingScript).
    pub contract_outputs: Option<Vec<ContractOutput>>,
    /// Additional contract inputs with their own unlocking scripts (for merge).
    pub additional_contract_inputs: Option<Vec<AdditionalContractInput>>,
}

/// Build a raw transaction that spends a contract UTXO (method call).
///
/// The transaction:
/// - Input 0: the current contract UTXO with the given unlocking script.
/// - Additional contract inputs (if provided via options): with their own unlock scripts.
/// - Additional P2PKH funding inputs if provided.
/// - Contract outputs (multi-output or single continuation).
/// - Last output (optional): change.
///
/// Returns the transaction hex (with unlocking script for input 0 already
/// placed), the total input count, and the change amount.
pub fn build_call_transaction(
    current_utxo: &Utxo,
    unlocking_script: &str,
    new_locking_script: Option<&str>,
    new_satoshis: Option<i64>,
    change_address: Option<&str>,
    change_script: Option<&str>,
    additional_utxos: Option<&[Utxo]>,
    fee_rate: Option<i64>,
) -> (String, usize, i64) {
    build_call_transaction_ext(
        current_utxo,
        unlocking_script,
        new_locking_script,
        new_satoshis,
        change_address,
        change_script,
        additional_utxos,
        fee_rate,
        None,
    )
}

/// Extended version of `build_call_transaction` with support for multi-output
/// and additional contract inputs.
pub fn build_call_transaction_ext(
    current_utxo: &Utxo,
    unlocking_script: &str,
    new_locking_script: Option<&str>,
    new_satoshis: Option<i64>,
    change_address: Option<&str>,
    change_script: Option<&str>,
    additional_utxos: Option<&[Utxo]>,
    fee_rate: Option<i64>,
    options: Option<&CallTxOptions>,
) -> (String, usize, i64) {
    let extra_contract_inputs = options
        .and_then(|o| o.additional_contract_inputs.as_ref())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    let p2pkh_utxos = additional_utxos.unwrap_or(&[]);

    // Collect all input UTXOs for total calculation
    let mut all_utxos = vec![current_utxo.clone()];
    for ci in extra_contract_inputs {
        all_utxos.push(ci.utxo.clone());
    }
    all_utxos.extend_from_slice(p2pkh_utxos);

    let total_input: i64 = all_utxos.iter().map(|u| u.satoshis).sum();

    // Determine contract outputs: multi-output takes priority over single
    let contract_outputs: Vec<ContractOutput> = if let Some(cos) = options.and_then(|o| o.contract_outputs.as_ref()) {
        // Already provided externally — borrow as references for output
        cos.iter().map(|co| ContractOutput { script: co.script.clone(), satoshis: co.satoshis }).collect()
    } else if let Some(nls) = new_locking_script {
        vec![ContractOutput {
            script: nls.to_string(),
            satoshis: new_satoshis.unwrap_or(current_utxo.satoshis),
        }]
    } else {
        vec![]
    };

    let contract_output_sats: i64 = contract_outputs.iter().map(|o| o.satoshis).sum();

    // Estimate fee using actual script sizes
    let unlock_byte_len = unlocking_script.len() / 2;
    let input0_size = 32 + 4 + varint_byte_size(unlock_byte_len) + unlock_byte_len as i64 + 4;
    let mut extra_contract_inputs_size: i64 = 0;
    for ci in extra_contract_inputs {
        let ci_byte_len = ci.unlocking_script.len() / 2;
        extra_contract_inputs_size += 32 + 4 + varint_byte_size(ci_byte_len) + ci_byte_len as i64 + 4;
    }
    let p2pkh_inputs_size = p2pkh_utxos.len() as i64 * 148;
    let inputs_size = input0_size + extra_contract_inputs_size + p2pkh_inputs_size;

    let mut outputs_size: i64 = 0;
    for co in &contract_outputs {
        let co_byte_len = co.script.len() / 2;
        outputs_size += 8 + varint_byte_size(co_byte_len) + co_byte_len as i64;
    }
    let has_change_target = change_address.is_some() || change_script.is_some();
    if has_change_target {
        outputs_size += 34; // P2PKH change
    }
    let estimated_size = 10 + inputs_size + outputs_size;
    let rate = fee_rate.filter(|&r| r > 0).unwrap_or(100);
    let fee = (estimated_size * rate + 999) / 1000;

    let change = total_input - contract_output_sats - fee;

    // Build raw transaction
    let mut tx = String::new();

    // Version (4 bytes LE)
    tx.push_str(&to_little_endian_32(1));

    // Input count
    tx.push_str(&encode_varint(all_utxos.len() as u64));

    // Input 0: primary contract UTXO with unlocking script
    tx.push_str(&reverse_hex(&current_utxo.txid));
    tx.push_str(&to_little_endian_32(current_utxo.output_index));
    tx.push_str(&encode_varint(unlock_byte_len as u64));
    tx.push_str(unlocking_script);
    tx.push_str("ffffffff");

    // Additional contract inputs (with their own unlocking scripts)
    for ci in extra_contract_inputs {
        tx.push_str(&reverse_hex(&ci.utxo.txid));
        tx.push_str(&to_little_endian_32(ci.utxo.output_index));
        let ci_byte_len = ci.unlocking_script.len() / 2;
        tx.push_str(&encode_varint(ci_byte_len as u64));
        tx.push_str(&ci.unlocking_script);
        tx.push_str("ffffffff");
    }

    // P2PKH funding inputs (unsigned)
    for utxo in p2pkh_utxos {
        tx.push_str(&reverse_hex(&utxo.txid));
        tx.push_str(&to_little_endian_32(utxo.output_index));
        tx.push_str("00"); // empty scriptSig
        tx.push_str("ffffffff");
    }

    // Output count
    let mut num_outputs = contract_outputs.len() as u64;
    if change > 0 && has_change_target {
        num_outputs += 1;
    }
    tx.push_str(&encode_varint(num_outputs));

    // Contract outputs
    for co in &contract_outputs {
        tx.push_str(&to_little_endian_64(co.satoshis));
        tx.push_str(&encode_varint((co.script.len() / 2) as u64));
        tx.push_str(&co.script);
    }

    // Change output
    if change > 0 && has_change_target {
        let actual_change_script = if let Some(cs) = change_script {
            cs.to_string()
        } else if let Some(addr) = change_address {
            build_p2pkh_script_from_address(addr)
        } else {
            String::new()
        };
        tx.push_str(&to_little_endian_64(change));
        tx.push_str(&encode_varint((actual_change_script.len() / 2) as u64));
        tx.push_str(&actual_change_script);
    }

    // Locktime
    tx.push_str(&to_little_endian_32(0));

    let change_amount = if change > 0 { change } else { 0 };
    (tx, all_utxos.len(), change_amount)
}

fn varint_byte_size(n: usize) -> i64 {
    if n < 0xfd { 1 }
    else if n <= 0xffff { 3 }
    else if n <= 0xffff_ffff { 5 }
    else { 9 }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utxo(satoshis: i64, index: u32) -> Utxo {
        Utxo {
            txid: "aabbccdd".repeat(8),
            output_index: index,
            satoshis,
            script: format!("76a914{}88ac", "00".repeat(20)),
        }
    }

    fn parse_tx_hex(hex: &str) -> ParsedTx {
        let mut offset = 0;

        fn read_bytes<'a>(hex: &'a str, offset: &mut usize, n: usize) -> &'a str {
            let start = *offset;
            *offset += n * 2;
            &hex[start..*offset]
        }

        fn read_u32_le(hex: &str, offset: &mut usize) -> u32 {
            let h = read_bytes(hex, offset, 4);
            let mut bytes = [0u8; 4];
            for i in 0..4 {
                bytes[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
            }
            u32::from_le_bytes(bytes)
        }

        fn read_u64_le(hex: &str, offset: &mut usize) -> u64 {
            let lo = read_u32_le(hex, offset) as u64;
            let hi = read_u32_le(hex, offset) as u64;
            lo | (hi << 32)
        }

        fn read_varint(hex: &str, offset: &mut usize) -> u64 {
            let first = u8::from_str_radix(read_bytes(hex, offset, 1), 16).unwrap();
            if first < 0xfd {
                first as u64
            } else if first == 0xfd {
                let h = read_bytes(hex, offset, 2);
                let lo = u8::from_str_radix(&h[0..2], 16).unwrap() as u64;
                let hi = u8::from_str_radix(&h[2..4], 16).unwrap() as u64;
                lo | (hi << 8)
            } else {
                panic!("unsupported varint");
            }
        }

        let version = read_u32_le(hex, &mut offset);
        let input_count = read_varint(hex, &mut offset) as usize;

        let mut inputs = Vec::new();
        for _ in 0..input_count {
            let prev_txid = read_bytes(hex, &mut offset, 32).to_string();
            let prev_index = read_u32_le(hex, &mut offset);
            let script_len = read_varint(hex, &mut offset) as usize;
            let script = read_bytes(hex, &mut offset, script_len).to_string();
            let sequence = read_u32_le(hex, &mut offset);
            inputs.push(ParsedInput {
                prev_txid,
                prev_index,
                script,
                sequence,
            });
        }

        let output_count = read_varint(hex, &mut offset) as usize;
        let mut outputs = Vec::new();
        for _ in 0..output_count {
            let satoshis = read_u64_le(hex, &mut offset) as i64;
            let script_len = read_varint(hex, &mut offset) as usize;
            let script = read_bytes(hex, &mut offset, script_len).to_string();
            outputs.push(ParsedOutput { satoshis, script });
        }

        let locktime = read_u32_le(hex, &mut offset);

        ParsedTx {
            version,
            input_count,
            inputs,
            output_count,
            outputs,
            locktime,
        }
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    struct ParsedTx {
        version: u32,
        input_count: usize,
        inputs: Vec<ParsedInput>,
        output_count: usize,
        outputs: Vec<ParsedOutput>,
        locktime: u32,
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    struct ParsedInput {
        prev_txid: String,
        prev_index: u32,
        script: String,
        sequence: u32,
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    struct ParsedOutput {
        satoshis: i64,
        script: String,
    }

    fn reverse_hex_helper(hex: &str) -> String {
        let pairs: Vec<&str> = (0..hex.len()).step_by(2).map(|i| &hex[i..i + 2]).collect();
        pairs.iter().rev().copied().collect()
    }

    #[test]
    fn version_1_locktime_0() {
        let utxo = make_utxo(100_000, 0);
        let (tx_hex, _, _) = build_call_transaction(&utxo, "51", None, None, None, None, None, None);
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.locktime, 0);
    }

    #[test]
    fn valid_hex_output() {
        let utxo = make_utxo(100_000, 0);
        let (tx_hex, _, _) = build_call_transaction(&utxo, "51", None, None, None, None, None, None);
        assert!(!tx_hex.is_empty());
        assert!(tx_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn embeds_unlocking_script_in_input_0() {
        let utxo = make_utxo(100_000, 0);
        let (tx_hex, _, _) = build_call_transaction(&utxo, "aabb", None, None, None, None, None, None);
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.inputs[0].script, "aabb");
    }

    #[test]
    fn all_sequences_ffffffff() {
        let utxo = make_utxo(100_000, 0);
        let additional = vec![make_utxo(50_000, 1), make_utxo(30_000, 2)];
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, _, _) = build_call_transaction(
            &utxo, "51", None, None, Some("changeaddr"), Some(&change_script), Some(&additional), None,
        );
        let parsed = parse_tx_hex(&tx_hex);
        for input in &parsed.inputs {
            assert_eq!(input.sequence, 0xffff_ffff);
        }
    }

    #[test]
    fn reversed_txid_in_wire_format() {
        let utxo = make_utxo(100_000, 0);
        let (tx_hex, _, _) = build_call_transaction(&utxo, "51", None, None, None, None, None, None);
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.inputs[0].prev_txid, reverse_hex_helper(&utxo.txid));
    }

    #[test]
    fn single_input_no_additional() {
        let utxo = make_utxo(100_000, 0);
        let (tx_hex, input_count, _) = build_call_transaction(&utxo, "51", None, None, None, None, None, None);
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(input_count, 1);
        assert_eq!(parsed.input_count, 1);
    }

    #[test]
    fn additional_utxos_have_empty_scriptsig() {
        let utxo = make_utxo(100_000, 0);
        let additional = vec![make_utxo(50_000, 1), make_utxo(30_000, 2)];
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, input_count, _) = build_call_transaction(
            &utxo, "51", None, None, Some("changeaddr"), Some(&change_script), Some(&additional), None,
        );
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(input_count, 3);
        assert_eq!(parsed.inputs[0].script, "51");
        assert_eq!(parsed.inputs[1].script, "");
        assert_eq!(parsed.inputs[2].script, "");
    }

    #[test]
    fn correct_output_index_reference() {
        let utxo = make_utxo(100_000, 3);
        let (tx_hex, _, _) = build_call_transaction(&utxo, "51", None, None, None, None, None, None);
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.inputs[0].prev_index, 3);
    }

    #[test]
    fn stateful_output_with_new_locking_script() {
        let utxo = make_utxo(100_000, 0);
        let new_ls = format!("76a914{}88ac", "dd".repeat(20));
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, _, _) = build_call_transaction(
            &utxo, "51", Some(&new_ls), Some(50_000), Some("changeaddr"), Some(&change_script), None, None,
        );
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.outputs[0].script, new_ls);
        assert_eq!(parsed.outputs[0].satoshis, 50_000);
    }

    #[test]
    fn defaults_to_current_utxo_satoshis() {
        let utxo = make_utxo(75_000, 0);
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, _, _) = build_call_transaction(
            &utxo, "00", Some("51"), None, Some("changeaddr"), Some(&change_script), None, None,
        );
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.outputs[0].satoshis, 75_000);
    }

    #[test]
    fn change_calculation() {
        let utxo = make_utxo(100_000, 0);
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, _, _) = build_call_transaction(
            &utxo, "00", Some("51"), Some(50_000), Some("changeaddr"), Some(&change_script), None, None,
        );
        let parsed = parse_tx_hex(&tx_hex);
        // txSize: input0(32+4+1+1+4=42) + contractOut(8+1+1=10) + changeOut(34) + overhead(10) = 96
        // Fee: ceil(96 * 100 / 1000) = 10
        // Change = 100000 - 50000 - 10 = 49990
        assert_eq!(parsed.output_count, 2);
        assert_eq!(parsed.outputs[0].satoshis, 50_000);
        assert_eq!(parsed.outputs[1].satoshis, 49_990);
        assert_eq!(parsed.outputs[1].script, change_script);
    }

    #[test]
    fn omits_change_when_zero() {
        // txSize: input0(42) + contractOut(10) + changeOut(34) + overhead(10) = 96
        // Fee: ceil(96 * 100 / 1000) = 10
        let utxo = make_utxo(50_010, 0);
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, _, _) = build_call_transaction(
            &utxo, "00", Some("51"), Some(50_000), Some("changeaddr"), Some(&change_script), None, None,
        );
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.output_count, 1);
        assert_eq!(parsed.outputs[0].satoshis, 50_000);
    }

    #[test]
    fn stateless_change_only() {
        let utxo = make_utxo(100_000, 0);
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, _, _) = build_call_transaction(
            &utxo, "51", None, None, Some("changeaddr"), Some(&change_script), None, None,
        );
        let parsed = parse_tx_hex(&tx_hex);
        // txSize: input0(42) + changeOut(34) + overhead(10) = 86
        // Fee: ceil(86 * 100 / 1000) = 9
        // Change: 100000 - 0 - 9 = 99991
        assert_eq!(parsed.output_count, 1);
        assert_eq!(parsed.outputs[0].script, change_script);
        assert_eq!(parsed.outputs[0].satoshis, 99_991);
    }

    #[test]
    fn stateless_no_outputs_when_change_zero() {
        // txSize: input0(42) + changeOut(34) + overhead(10) = 86
        // Fee: ceil(86 * 100 / 1000) = 9
        let utxo = make_utxo(9, 0);
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, _, _) = build_call_transaction(
            &utxo, "51", None, None, Some("changeaddr"), Some(&change_script), None, None,
        );
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.output_count, 0);
    }

    #[test]
    fn accumulates_additional_utxos() {
        let utxo = make_utxo(50_000, 0);
        let additional = vec![make_utxo(30_000, 1)];
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, _, _) = build_call_transaction(
            &utxo, "00", Some("51"), Some(40_000), Some("changeaddr"), Some(&change_script), Some(&additional), None,
        );
        let parsed = parse_tx_hex(&tx_hex);
        // txSize: input0(42) + additional(148) + contractOut(10) + changeOut(34) + overhead(10) = 244
        // Fee: ceil(244 * 100 / 1000) = 25
        // Total input: 80000, Change: 80000 - 40000 - 25 = 39975
        assert_eq!(parsed.output_count, 2);
        assert_eq!(parsed.outputs[0].satoshis, 40_000);
        assert_eq!(parsed.outputs[1].satoshis, 39_975);
    }
}
