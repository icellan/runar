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
    let tx_bytes = hex_to_bytes(tx_hex)?;
    let tx = parse_raw_tx(&tx_bytes)?;

    if input_index >= tx.inputs.len() {
        return Err(format!(
            "compute_op_push_tx: input index {} out of range ({} inputs)",
            input_index,
            tx.inputs.len()
        ));
    }

    let subscript_bytes = hex_to_bytes(subscript)?;

    // Compute BIP-143 preimage (raw bytes, not hashed)
    let preimage = bip143_preimage(&tx, input_index, &subscript_bytes, satoshis as u64, SIGHASH_ALL_FORKID);

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
    result.push(SIGHASH_ALL_FORKID as u8);

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
    // hashPrevouts = SHA256d(all outpoints)
    let mut prevouts_data = Vec::new();
    for inp in &tx.inputs {
        prevouts_data.extend_from_slice(&inp.prev_txid_bytes);
        prevouts_data.extend_from_slice(&inp.prev_output_index.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_data);

    // hashSequence = SHA256d(all sequences)
    let mut sequence_data = Vec::new();
    for inp in &tx.inputs {
        sequence_data.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    let hash_sequence = sha256d(&sequence_data);

    // hashOutputs = SHA256d(all outputs)
    let mut outputs_data = Vec::new();
    for out in &tx.outputs {
        outputs_data.extend_from_slice(&out.satoshis.to_le_bytes());
        write_var_int(&mut outputs_data, out.script.len() as u64);
        outputs_data.extend_from_slice(&out.script);
    }
    let hash_outputs = sha256d(&outputs_data);

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
