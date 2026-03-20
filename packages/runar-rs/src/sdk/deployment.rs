//! Transaction construction for contract deployment.

use super::types::Utxo;

/// Estimated size of a P2PKH input (prevTxid + index + sig + pubkey + seq).
const P2PKH_INPUT_SIZE: i64 = 148;
/// Estimated size of a P2PKH output (satoshis + varint + 25-byte script).
const P2PKH_OUTPUT_SIZE: i64 = 34;
/// Transaction overhead: version(4) + input varint(1) + output varint(1) + locktime(4).
const TX_OVERHEAD: i64 = 10;

/// Build a raw transaction that creates an output with the given locking
/// script. The transaction consumes the provided UTXOs, places the contract
/// output first, and sends any remaining value (minus fees) to a change
/// address.
///
/// Returns the unsigned transaction hex and the number of inputs.
pub fn build_deploy_transaction(
    locking_script: &str,
    utxos: &[Utxo],
    satoshis: i64,
    _change_address: &str,
    change_script: &str,
    fee_rate: Option<i64>,
) -> (String, usize) {
    if utxos.is_empty() {
        panic!("buildDeployTransaction: no UTXOs provided");
    }

    let total_input: i64 = utxos.iter().map(|u| u.satoshis).sum();
    let fee = estimate_deploy_fee(utxos.len(), locking_script.len() / 2, fee_rate);
    let change = total_input - satoshis - fee;

    if change < 0 {
        panic!(
            "buildDeployTransaction: insufficient funds. Need {} sats, have {}",
            satoshis + fee,
            total_input
        );
    }

    let mut tx = String::new();

    // Version (4 bytes LE)
    tx.push_str(&to_little_endian_32(1));

    // Input count (varint)
    tx.push_str(&encode_varint(utxos.len() as u64));

    // Inputs (unsigned -- scriptSig is empty)
    for utxo in utxos {
        // Previous txid (32 bytes, reversed)
        tx.push_str(&reverse_hex(&utxo.txid));
        // Previous output index (4 bytes LE)
        tx.push_str(&to_little_endian_32(utxo.output_index));
        // ScriptSig length + script (empty for unsigned)
        tx.push_str("00");
        // Sequence (4 bytes LE) -- 0xffffffff
        tx.push_str("ffffffff");
    }

    // Output count
    let has_change = change > 0;
    let output_count = if has_change { 2u64 } else { 1u64 };
    tx.push_str(&encode_varint(output_count));

    // Output 0: contract locking script
    tx.push_str(&to_little_endian_64(satoshis));
    tx.push_str(&encode_varint((locking_script.len() / 2) as u64));
    tx.push_str(locking_script);

    // Output 1: change (if any)
    if has_change {
        tx.push_str(&to_little_endian_64(change));
        tx.push_str(&encode_varint((change_script.len() / 2) as u64));
        tx.push_str(change_script);
    }

    // Locktime (4 bytes LE)
    tx.push_str(&to_little_endian_32(0));

    (tx, utxos.len())
}

/// Estimate the fee for a deploy transaction given the number of P2PKH
/// inputs and the contract locking script byte length. Fee rate is in
/// satoshis per KB (default 100, i.e. 0.1 sat/byte). Includes a P2PKH
/// change output.
pub fn estimate_deploy_fee(num_inputs: usize, locking_script_byte_len: usize, fee_rate: Option<i64>) -> i64 {
    let rate = fee_rate.filter(|&r| r > 0).unwrap_or(100);
    let inputs_size = num_inputs as i64 * P2PKH_INPUT_SIZE;
    let contract_output_size =
        8 + varint_byte_size(locking_script_byte_len) + locking_script_byte_len as i64;
    let change_output_size = P2PKH_OUTPUT_SIZE;
    let tx_size = TX_OVERHEAD + inputs_size + contract_output_size + change_output_size;
    (tx_size * rate + 999) / 1000
}

/// Select the minimum set of UTXOs needed to fund a deployment, using a
/// largest-first strategy. Returns the selected subset.
pub fn select_utxos(
    utxos: &[Utxo],
    target_satoshis: i64,
    locking_script_byte_len: usize,
    fee_rate: Option<i64>,
) -> Vec<Utxo> {
    let mut sorted: Vec<Utxo> = utxos.to_vec();
    sorted.sort_by(|a, b| b.satoshis.cmp(&a.satoshis));

    let mut selected = Vec::new();
    let mut total: i64 = 0;

    for utxo in sorted {
        selected.push(utxo);
        total += selected.last().unwrap().satoshis;

        let fee = estimate_deploy_fee(selected.len(), locking_script_byte_len, fee_rate);
        if total >= target_satoshis + fee {
            return selected;
        }
    }

    // Return all UTXOs; build_deploy_transaction will panic if still insufficient
    selected
}

// ---------------------------------------------------------------------------
// Bitcoin wire format helpers
// ---------------------------------------------------------------------------

pub(crate) fn to_little_endian_32(n: u32) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        n & 0xff,
        (n >> 8) & 0xff,
        (n >> 16) & 0xff,
        (n >> 24) & 0xff,
    )
}

pub(crate) fn to_little_endian_64(n: i64) -> String {
    let lo = (n as u64) & 0xffff_ffff;
    let hi = ((n as u64) >> 32) & 0xffff_ffff;
    format!("{}{}", to_little_endian_32(lo as u32), to_little_endian_32(hi as u32))
}

fn to_little_endian_16(n: u16) -> String {
    format!("{:02x}{:02x}", n & 0xff, (n >> 8) & 0xff)
}

pub(crate) fn encode_varint(n: u64) -> String {
    if n < 0xfd {
        format!("{:02x}", n)
    } else if n <= 0xffff {
        format!("fd{}", to_little_endian_16(n as u16))
    } else if n <= 0xffff_ffff {
        format!("fe{}", to_little_endian_32(n as u32))
    } else {
        format!("ff{}", to_little_endian_64(n as i64))
    }
}

pub(crate) fn reverse_hex(hex: &str) -> String {
    let pairs: Vec<&str> = (0..hex.len())
        .step_by(2)
        .map(|i| &hex[i..i + 2])
        .collect();
    pairs.iter().rev().copied().collect()
}

fn varint_byte_size(n: usize) -> i64 {
    if n < 0xfd { 1 }
    else if n <= 0xffff { 3 }
    else if n <= 0xffff_ffff { 5 }
    else { 9 }
}

/// Build a P2PKH locking script from an address.
///
///   OP_DUP OP_HASH160 OP_PUSH20 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
///   76      a9         14        <20 bytes>    88              ac
///
/// If the address is 40-char hex, treat as raw pubkey hash.
/// Otherwise, decode the Base58Check address to extract the 20-byte pubkey hash.
pub(crate) fn build_p2pkh_script_from_address(address: &str) -> String {
    let pub_key_hash = if is_hex_40(address) {
        address.to_string()
    } else {
        // Decode Base58Check address: version(1) + pubKeyHash(20) + checksum(4)
        let decoded = bs58::decode(address)
            .with_check(None)
            .into_vec()
            .unwrap_or_else(|e| panic!("build_p2pkh_script_from_address: invalid address {:?}: {}", address, e));
        if decoded.len() != 21 {
            panic!(
                "build_p2pkh_script_from_address: unexpected decoded length {} for address {:?}",
                decoded.len(), address
            );
        }
        // Skip version byte (0x00 for mainnet, 0x6f for testnet), take 20-byte hash
        decoded[1..].iter().map(|b| format!("{:02x}", b)).collect()
    };
    format!("76a914{}88ac", pub_key_hash)
}

fn is_hex_40(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
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

    /// Parse a raw transaction hex into its structural components.
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

    #[test]
    fn produces_nonempty_hex() {
        let locking_script = format!("76a914{}88ac", "00".repeat(20));
        let utxos = vec![make_utxo(100_000, 0)];
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, input_count) =
            build_deploy_transaction(&locking_script, &utxos, 50_000, "addr", &change_script, None);

        assert!(!tx_hex.is_empty());
        assert_eq!(input_count, 1);
        assert!(tx_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn correct_structure() {
        let locking_script = "51";
        let utxos = vec![make_utxo(100_000, 0)];
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, _) =
            build_deploy_transaction(locking_script, &utxos, 50_000, "addr", &change_script, None);

        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.input_count, 1);
        assert_eq!(parsed.inputs[0].script, "");
        assert_eq!(parsed.inputs[0].sequence, 0xffff_ffff);
        assert_eq!(parsed.output_count, 2);
        assert_eq!(parsed.outputs[0].script, locking_script);
        assert_eq!(parsed.outputs[1].script, change_script);
        assert_eq!(parsed.locktime, 0);
    }

    #[test]
    fn handles_multiple_utxos() {
        let utxos = vec![make_utxo(30_000, 0), make_utxo(40_000, 1), make_utxo(50_000, 2)];
        let change_script = format!("76a914{}88ac", "ff".repeat(20));
        let (tx_hex, input_count) =
            build_deploy_transaction("51", &utxos, 50_000, "addr", &change_script, None);

        assert_eq!(input_count, 3);
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.input_count, 3);
    }

    #[test]
    #[should_panic(expected = "no UTXOs provided")]
    fn throws_no_utxos() {
        build_deploy_transaction("51", &[], 50_000, "addr", "51", None);
    }

    #[test]
    #[should_panic(expected = "insufficient funds")]
    fn throws_insufficient_funds() {
        let utxos = vec![make_utxo(100, 0)];
        build_deploy_transaction("51", &utxos, 50_000, "addr", "51", None);
    }

    #[test]
    fn single_output_when_change_zero() {
        // txSize: TX_OVERHEAD(10) + 1 * P2PKH(148) + contract output(8 + 1 + 1) + change(34) = 202
        // Fee: ceil(202 * 100 / 1000) = 21
        let utxos = vec![make_utxo(50_021, 0)];
        let (tx_hex, _) = build_deploy_transaction("51", &utxos, 50_000, "addr", "51", None);
        let parsed = parse_tx_hex(&tx_hex);
        assert_eq!(parsed.output_count, 1);
    }

    #[test]
    fn select_utxos_picks_largest_first() {
        let utxos = vec![
            make_utxo(1_000, 0),
            make_utxo(50_000, 1),
            make_utxo(200_000, 2),
        ];
        let selected = select_utxos(&utxos, 50_000, 1, None);
        // Should pick the 200_000 UTXO first (largest), which is enough alone
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].satoshis, 200_000);
    }

    #[test]
    fn select_utxos_picks_multiple_if_needed() {
        let utxos = vec![
            make_utxo(30_000, 0),
            make_utxo(20_000, 1),
            make_utxo(10_000, 2),
        ];
        let selected = select_utxos(&utxos, 50_000, 1, None);
        // 30_000 alone not enough; 30_000 + 20_000 = 50_000, need fee too; may need all 3
        assert!(selected.len() >= 2);
    }
}
