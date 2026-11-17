//! GK-BUG-013 (off-chain half, Rust tier): `sha256_finalize` must refuse a
//! msgBitLen outside [0, 2^64), the domain the compiled script enforces with
//! its `<00> OP_EQUALVERIFY` sign-byte check. It used to write
//! `msg_bit_len as u64`, so -24 wrapped to 2^64 - 24 and produced a digest no
//! script computes. `i64` cannot hold 2^64 or more, so the negative half is
//! the whole Rust case.
//!
//! Proves: -24, -1 and i64::MIN panic with the shared "msgBitLen must be in
//! [0, 2^64)" diagnostic naming the value; 24 still yields the FIPS 180-4
//! SHA-256("abc") digest; the largest multiple of 8 in i64 is accepted.
//! Does not prove: the other six tiers (each has its own gk-bug-013 test).

use std::panic;

use runar_lang::prelude::sha256_finalize;

const IV: &str = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
/// FIPS 180-4 Appendix B.1: SHA-256("abc").
const SHA_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn panic_text(bit_len: i64) -> Option<String> {
    let iv = unhex(IV);
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let r = panic::catch_unwind(|| sha256_finalize(&iv, b"abc", bit_len));
    panic::set_hook(prev);
    match r {
        Ok(_) => None,
        Err(e) => Some(
            e.downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default(),
        ),
    }
}

#[test]
fn gk_bug_013_honest_length_still_hashes() {
    let out = sha256_finalize(&unhex(IV), b"abc", 24);
    assert_eq!(hex(&out), SHA_ABC);
}

#[test]
fn gk_bug_013_refuses_negative_bit_len() {
    for bit_len in [-24i64, -1, i64::MIN] {
        let msg = panic_text(bit_len)
            .unwrap_or_else(|| panic!("sha256_finalize(IV, abc, {bit_len}) returned a digest; want a refusal"));
        assert!(
            msg.contains("msgBitLen must be in [0, 2^64)"),
            "sha256_finalize(IV, abc, {bit_len}) panicked with {msg:?}; want the msgBitLen domain diagnostic"
        );
        assert!(msg.contains(&format!("got {bit_len}")), "diagnostic {msg:?} does not name {bit_len}");
    }
}

#[test]
fn gk_bug_013_accepts_top_of_i64() {
    assert_eq!(panic_text(i64::MAX & !7), None);
}
