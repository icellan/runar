//! OP_PUSH_TX helper for checkPreimage contracts.
//!
//! Computes the BIP-143 sighash preimage and OP_PUSH_TX signature for contracts
//! that use checkPreimage() (both stateful and stateless).
//!
//! The OP_PUSH_TX technique uses private key k=1 (public key = generator point G).
//! The on-chain script derives the signature from the preimage, so both must be
//! provided in the unlocking script.

use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Sha256, Digest};

/// SIGHASH_ALL | SIGHASH_FORKID — the default BSV sighash type.
const SIGHASH_ALL_FORKID: u32 = 0x41;

/// Compute the OP_PUSH_TX DER signature and BIP-143 preimage for a contract input.
///
/// Returns `(sig_hex, preimage_hex)` where `sig_hex` includes the sighash byte.
pub fn compute_op_push_tx(
    tx_hex: &str,
    input_index: usize,
    subscript: &str,
    satoshis: i64,
) -> Result<(String, String), String> {
    compute_op_push_tx_with_code_sep(tx_hex, input_index, subscript, satoshis, -1)
}

/// Like `compute_op_push_tx` but supports OP_CODESEPARATOR.
/// When `code_separator_index` >= 0, the scriptCode in the BIP-143 preimage uses only
/// the portion of subscript after the OP_CODESEPARATOR byte offset.
///
/// Uses the default `ALL|FORKID` (0x41) sighash mode. Callers honouring a
/// `@sighash` directive use [`compute_op_push_tx_with_code_sep_sighash`].
pub fn compute_op_push_tx_with_code_sep(
    tx_hex: &str,
    input_index: usize,
    subscript: &str,
    satoshis: i64,
    code_separator_index: i64,
) -> Result<(String, String), String> {
    compute_op_push_tx_with_code_sep_sighash(
        tx_hex,
        input_index,
        subscript,
        satoshis,
        code_separator_index,
        SIGHASH_ALL_FORKID,
    )
}

/// Like [`compute_op_push_tx_with_code_sep`] but builds the BIP-143 preimage
/// under the given `sig_hash_type` (issue #123). The mode drives which preimage
/// fields are zeroed (hashPrevouts under ANYONECANPAY, hashSequence unless pure
/// ALL, hashOutputs under NONE / restricted to the same-index output under
/// SINGLE) AND the sighash flag byte appended to the DER signature. Must match
/// the method's declared `@sighash` mode or the on-chain OP_PUSH_TX binding
/// fails to verify.
pub fn compute_op_push_tx_with_code_sep_sighash(
    tx_hex: &str,
    input_index: usize,
    subscript: &str,
    satoshis: i64,
    code_separator_index: i64,
    sig_hash_type: u32,
) -> Result<(String, String), String> {
    // R-178: an out-of-range code_separator_index used to leave the subscript
    // UNTRIMMED and sign it anyway — a wrong scriptCode, with no error, from a
    // fund-moving primitive. Reject it instead: there is no correct signature
    // for a separator offset that is not in the script.
    let mut effective_subscript = subscript.to_string();
    if code_separator_index >= 0 {
        let trim_pos = ((code_separator_index as usize) + 1) * 2;
        if trim_pos > subscript.len() {
            return Err(format!(
                "compute_op_push_tx: code_separator_index {} is past the end of the \
                 subscript ({} bytes)",
                code_separator_index,
                subscript.len() / 2
            ));
        }
        effective_subscript = subscript[trim_pos..].to_string();
    }

    let tx_bytes = hex_to_bytes(tx_hex)?;
    let tx = parse_raw_tx(&tx_bytes)?;

    if input_index >= tx.inputs.len() {
        return Err(format!(
            "compute_op_push_tx: input index {} out of range ({} inputs)",
            input_index,
            tx.inputs.len()
        ));
    }

    let subscript_bytes = hex_to_bytes(&effective_subscript)?;

    // Compute BIP-143 preimage (raw bytes, not hashed)
    let preimage = bip143_preimage(&tx, input_index, &subscript_bytes, satoshis as u64, sig_hash_type);

    // Double-SHA256 for the sighash
    let sighash = sha256d(&preimage);

    // Sign with k=1 private key
    let mut key_bytes = [0u8; 32];
    key_bytes[31] = 1;
    let signing_key = SigningKey::from_slice(&key_bytes)
        .map_err(|e| format!("compute_op_push_tx: create k=1 key: {}", e))?;

    let (sig, _) = signing_key
        .sign_prehash(&sighash)
        .map_err(|e| format!("compute_op_push_tx: sign: {}", e))?;

    // Normalize to low-S
    let normalized = sig.normalize_s().unwrap_or(sig);

    // DER encode + append sighash byte
    let der = normalized.to_der();
    let mut result = der.as_bytes().to_vec();
    result.push((sig_hash_type & 0xff) as u8);

    let sig_hex = bytes_to_hex(&result);
    let preimage_hex = bytes_to_hex(&preimage);

    Ok((sig_hex, preimage_hex))
}

// ---------------------------------------------------------------------------
// BIP-143 preimage computation (returns raw bytes, not hashed)
// ---------------------------------------------------------------------------

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn bip143_preimage(
    tx: &ParsedTx,
    input_index: usize,
    subscript: &[u8],
    satoshis: u64,
    sig_hash_type: u32,
) -> Vec<u8> {
    // Issue #123: BIP-143 zeroes specific digest fields under relaxed modes.
    const ZERO32: [u8; 32] = [0u8; 32];
    let base = sig_hash_type & 0x1f;
    let acp = (sig_hash_type & 0x80) != 0;

    // hashPrevouts = SHA256d(all outpoints). ANYONECANPAY zeroes it (only this
    // input is signed).
    let hash_prevouts = if acp {
        ZERO32
    } else {
        let mut prevouts_data = Vec::new();
        for inp in &tx.inputs {
            prevouts_data.extend_from_slice(&inp.prev_txid_bytes);
            prevouts_data.extend_from_slice(&inp.prev_output_index.to_le_bytes());
        }
        sha256d(&prevouts_data)
    };

    // hashSequence = SHA256d(all sequences). Zeroed under anything but pure ALL
    // (NONE / SINGLE / ANYONECANPAY all clear it).
    let hash_sequence = if base == 0x01 && !acp {
        let mut sequence_data = Vec::new();
        for inp in &tx.inputs {
            sequence_data.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        sha256d(&sequence_data)
    } else {
        ZERO32
    };

    // hashOutputs by sighash base:
    //   ALL    -> hash256(all outputs)
    //   SINGLE -> hash256(the single output at THIS input's index), or ZERO32
    //             when input_index >= outputs.len (matches BIP-143)
    //   NONE   -> 32 zero bytes (no outputs committed)
    let hash_outputs = if base == 0x02 {
        ZERO32
    } else if base == 0x03 {
        if input_index < tx.outputs.len() {
            let out = &tx.outputs[input_index];
            let mut od = Vec::new();
            od.extend_from_slice(&out.satoshis.to_le_bytes());
            write_var_int(&mut od, out.script.len() as u64);
            od.extend_from_slice(&out.script);
            sha256d(&od)
        } else {
            ZERO32
        }
    } else {
        let mut outputs_data = Vec::new();
        for out in &tx.outputs {
            outputs_data.extend_from_slice(&out.satoshis.to_le_bytes());
            write_var_int(&mut outputs_data, out.script.len() as u64);
            outputs_data.extend_from_slice(&out.script);
        }
        sha256d(&outputs_data)
    };

    // BIP-143 preimage
    let input = &tx.inputs[input_index];
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&input.prev_txid_bytes);
    preimage.extend_from_slice(&input.prev_output_index.to_le_bytes());
    write_var_int(&mut preimage, subscript.len() as u64);
    preimage.extend_from_slice(subscript);
    preimage.extend_from_slice(&satoshis.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());
    preimage.extend_from_slice(&sig_hash_type.to_le_bytes());

    preimage
}

// ---------------------------------------------------------------------------
// Minimal raw transaction parser (duplicated from signer.rs for module independence)
// ---------------------------------------------------------------------------

struct ParsedInput {
    prev_txid_bytes: [u8; 32],
    prev_output_index: u32,
    sequence: u32,
}

struct ParsedOutput {
    satoshis: u64,
    script: Vec<u8>,
}

struct ParsedTx {
    version: u32,
    inputs: Vec<ParsedInput>,
    outputs: Vec<ParsedOutput>,
    locktime: u32,
}

fn parse_raw_tx(bytes: &[u8]) -> Result<ParsedTx, String> {
    let mut offset = 0;

    let read = |offset: &mut usize, n: usize| -> Result<&[u8], String> {
        if *offset + n > bytes.len() {
            return Err("compute_op_push_tx: transaction hex too short".to_string());
        }
        let slice = &bytes[*offset..*offset + n];
        *offset += n;
        Ok(slice)
    };

    let read_u32_le = |offset: &mut usize| -> Result<u32, String> {
        let b = read(offset, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    let read_u64_le = |offset: &mut usize| -> Result<u64, String> {
        let b = read(offset, 8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    };

    let read_var_int = |offset: &mut usize| -> Result<u64, String> {
        let first = read(offset, 1)?[0];
        match first {
            0..=0xfc => Ok(first as u64),
            0xfd => {
                let b = read(offset, 2)?;
                Ok(u16::from_le_bytes([b[0], b[1]]) as u64)
            }
            0xfe => {
                let b = read(offset, 4)?;
                Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64)
            }
            0xff => {
                let b = read(offset, 8)?;
                Ok(u64::from_le_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
        }
    };

    let version = read_u32_le(&mut offset)?;

    let input_count = read_var_int(&mut offset)?;
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        let txid_slice = read(&mut offset, 32)?;
        let mut prev_txid_bytes = [0u8; 32];
        prev_txid_bytes.copy_from_slice(txid_slice);
        let prev_output_index = read_u32_le(&mut offset)?;
        let script_len = read_var_int(&mut offset)?;
        let _ = read(&mut offset, script_len as usize)?;
        let sequence = read_u32_le(&mut offset)?;
        inputs.push(ParsedInput {
            prev_txid_bytes,
            prev_output_index,
            sequence,
        });
    }

    let output_count = read_var_int(&mut offset)?;
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let satoshis = read_u64_le(&mut offset)?;
        let script_len = read_var_int(&mut offset)?;
        let script = read(&mut offset, script_len as usize)?.to_vec();
        outputs.push(ParsedOutput { satoshis, script });
    }

    let locktime = read_u32_le(&mut offset)?;

    Ok(ParsedTx {
        version,
        inputs,
        outputs,
        locktime,
    })
}

fn write_var_int(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("invalid hex at position {}", i))
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid raw transaction hex with one input and one output.
    /// version(4) + input_count(1) + txid(32) + vout(4) + script_len(1) + sequence(4)
    ///           + output_count(1) + satoshis(8) + script_len(1) + script(1) + locktime(4)
    fn minimal_tx_hex() -> String {
        let mut tx: Vec<u8> = Vec::new();
        // version = 1
        tx.extend_from_slice(&1u32.to_le_bytes());
        // input count = 1
        tx.push(1);
        // prev txid (32 zero bytes)
        tx.extend_from_slice(&[0u8; 32]);
        // prev output index = 0
        tx.extend_from_slice(&0u32.to_le_bytes());
        // scriptSig length = 0
        tx.push(0);
        // sequence = 0xffffffff
        tx.extend_from_slice(&0xffffffffu32.to_le_bytes());
        // output count = 1
        tx.push(1);
        // satoshis = 1000
        tx.extend_from_slice(&1000u64.to_le_bytes());
        // output script: OP_1 (one byte)
        tx.push(1);
        tx.push(0x51);
        // locktime = 0
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// A trivial locking script hex (OP_1 = 0x51).
    fn minimal_subscript() -> &'static str {
        "51"
    }

    /// R-178 (CL-BUG-071): an out-of-range code_separator_index used to leave
    /// the subscript UNTRIMMED and sign it — a wrong scriptCode, silently, from
    /// a fund-moving primitive.
    #[test]
    fn r178_out_of_range_code_separator_index_is_refused() {
        let tx_hex = minimal_tx_hex();
        let sub = minimal_subscript(); // "51" — one byte

        for idx in [1i64, 2, 99] {
            let out = compute_op_push_tx_with_code_sep(&tx_hex, 0, sub, 1000, idx);
            let err = match out {
                Ok((sig, _preimage)) => panic!(
                    "code_separator_index {} past the end of a {}-byte subscript was \
                     accepted and signed ({}...)",
                    idx,
                    sub.len() / 2,
                    &sig[..8.min(sig.len())]
                ),
                Err(e) => e,
            };
            assert!(
                err.contains("code_separator_index"),
                "the refusal must name the offending input; got: {}",
                err
            );
        }
    }

    /// Control: an IN-range separator still trims and signs, and the signature
    /// differs from the untrimmed one — which is what makes the silent
    /// fallthrough a wrong answer rather than a harmless one.
    #[test]
    fn r178_in_range_code_separator_index_still_trims() {
        let tx_hex = minimal_tx_hex();
        // Two bytes: OP_CODESEPARATOR (0xab) then OP_1 (0x51).
        let sub = "ab51";

        let trimmed = compute_op_push_tx_with_code_sep(&tx_hex, 0, sub, 1000, 0)
            .expect("an in-range separator must still work");
        let untrimmed = compute_op_push_tx_with_code_sep(&tx_hex, 0, sub, 1000, -1)
            .expect("no separator must still work");
        assert_ne!(
            trimmed.1, untrimmed.1,
            "trimming the subscript must change the preimage"
        );
    }

    #[test]
    fn test_returns_der_signature() {
        let tx_hex = minimal_tx_hex();
        let result = compute_op_push_tx(&tx_hex, 0, minimal_subscript(), 1000);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        let (sig_hex, _preimage_hex) = result.unwrap();
        let sig_bytes = (0..sig_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(sig_bytes[0], 0x30, "DER signature must start with sequence tag 0x30");
    }

    #[test]
    fn test_deterministic() {
        let tx_hex = minimal_tx_hex();
        let sig1 = compute_op_push_tx(&tx_hex, 0, minimal_subscript(), 1000).unwrap().0;
        let sig2 = compute_op_push_tx(&tx_hex, 0, minimal_subscript(), 1000).unwrap().0;
        assert_eq!(sig1, sig2, "same inputs must produce the same signature");
    }

    #[test]
    fn test_preimage_is_nonempty() {
        let tx_hex = minimal_tx_hex();
        let (_sig, preimage) = compute_op_push_tx(&tx_hex, 0, minimal_subscript(), 1000).unwrap();
        assert!(!preimage.is_empty(), "preimage must not be empty");
        // BIP-143 preimage contains several fixed-length fields; for a minimal tx it is at least 156 bytes = 312 hex chars
        assert!(preimage.len() >= 312, "preimage too short: {} hex chars", preimage.len());
    }

    #[test]
    fn test_sighash_byte_appended() {
        // SIGHASH_ALL | SIGHASH_FORKID = 0x41
        let tx_hex = minimal_tx_hex();
        let (sig_hex, _) = compute_op_push_tx(&tx_hex, 0, minimal_subscript(), 1000).unwrap();
        let sig_bytes: Vec<u8> = (0..sig_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(*sig_bytes.last().unwrap(), 0x41, "last byte must be SIGHASH_ALL|FORKID (0x41)");
    }

    fn sig_last_byte(sig_hex: &str) -> u8 {
        let n = sig_hex.len();
        u8::from_str_radix(&sig_hex[n - 2..n], 16).unwrap()
    }

    // Issue #123: the appended sighash byte + the preimage's sighashType field
    // (last 4 bytes, LE) follow the declared @sighash mode.
    #[test]
    fn test_sighash_mode_single_forkid_0x43() {
        let tx_hex = minimal_tx_hex();
        let (sig_hex, preimage_hex) =
            compute_op_push_tx_with_code_sep_sighash(&tx_hex, 0, minimal_subscript(), 1000, -1, 0x43)
                .unwrap();
        assert_eq!(sig_last_byte(&sig_hex), 0x43, "sig must end in SINGLE|FORKID 0x43");
        // sighashType is the final 4 preimage bytes, little-endian → "43000000".
        assert!(
            preimage_hex.ends_with("43000000"),
            "preimage sighashType field must be 0x43 LE, got tail: {}",
            &preimage_hex[preimage_hex.len() - 8..]
        );
    }

    #[test]
    fn test_sighash_mode_anyonecanpay_0xc1() {
        let tx_hex = minimal_tx_hex();
        let (sig_hex, preimage_hex) =
            compute_op_push_tx_with_code_sep_sighash(&tx_hex, 0, minimal_subscript(), 1000, -1, 0xC1)
                .unwrap();
        assert_eq!(sig_last_byte(&sig_hex), 0xC1, "sig must end in ALL|ANYONECANPAY|FORKID 0xC1");
        assert!(preimage_hex.ends_with("c1000000"), "preimage sighashType must be 0xC1 LE");
        // ANYONECANPAY zeroes hashPrevouts (preimage bytes 4..36).
        let bytes: Vec<u8> = (0..preimage_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&preimage_hex[i..i + 2], 16).unwrap())
            .collect();
        assert!(bytes[4..36].iter().all(|&b| b == 0), "hashPrevouts must be zeroed under ANYONECANPAY");
    }

    #[test]
    fn test_sighash_mode_default_still_0x41() {
        let tx_hex = minimal_tx_hex();
        let with_default =
            compute_op_push_tx_with_code_sep_sighash(&tx_hex, 0, minimal_subscript(), 1000, -1, 0x41)
                .unwrap();
        let plain = compute_op_push_tx(&tx_hex, 0, minimal_subscript(), 1000).unwrap();
        assert_eq!(with_default, plain, "explicit 0x41 must equal the default path byte-for-byte");
    }

    #[test]
    fn test_low_s_enforcement() {
        let half_n: [u8; 32] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
            0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
        ];
        for i in 0..20u8 {
            // Vary the subscript by appending different OP_NOP bytes to change the sighash
            let subscript = format!("51{:02x}", i);
            let tx_hex = minimal_tx_hex();
            let (sig_hex, _) = compute_op_push_tx(&tx_hex, 0, &subscript, 1000).unwrap();
            let sig_bytes: Vec<u8> = (0..sig_hex.len())
                .step_by(2)
                .map(|j| u8::from_str_radix(&sig_hex[j..j + 2], 16).unwrap())
                .collect();
            // Parse DER: 0x30 [total_len] 0x02 [r_len] <r> 0x02 [s_len] <s> [sighash]
            let r_len = sig_bytes[3] as usize;
            let s_offset = 4 + r_len + 1; // skip tag + len + r + 0x02 tag
            let s_len = sig_bytes[s_offset] as usize;
            let s_bytes = &sig_bytes[s_offset + 1..s_offset + 1 + s_len];
            // Strip leading zero padding byte that DER may prepend for sign bit
            let s_trimmed = if s_bytes.len() == 33 && s_bytes[0] == 0 { &s_bytes[1..] } else { s_bytes };
            let mut padded = [0u8; 32];
            let start = 32usize.saturating_sub(s_trimmed.len());
            padded[start..].copy_from_slice(s_trimmed);
            assert!(padded <= half_n, "S exceeds N/2 on iteration {i}");
        }
    }

    #[test]
    fn test_input_index_out_of_range() {
        let tx_hex = minimal_tx_hex();
        let result = compute_op_push_tx(&tx_hex, 99, minimal_subscript(), 1000);
        assert!(result.is_err(), "expected Err for out-of-range input index");
        let msg = result.unwrap_err();
        assert!(msg.contains("out of range"), "error message should mention 'out of range': {msg}");
    }

    #[test]
    fn test_code_separator_trims_subscript() {
        let tx_hex = minimal_tx_hex();
        // subscript "ab51": code_sep_index=0 trims first byte, leaving "51"
        let (sig_with_sep, _) = compute_op_push_tx_with_code_sep(&tx_hex, 0, "ab51", 1000, 0).unwrap();
        let (sig_plain, _) = compute_op_push_tx(&tx_hex, 0, "51", 1000).unwrap();
        assert_eq!(sig_with_sep, sig_plain, "trimmed subscript must produce same signature as plain subscript");
    }
}
