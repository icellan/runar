//! Generates Poseidon2 KoalaBear permutation and compression test vectors
//! using Plonky3 as the reference implementation.
//!
//! These vectors validate Rúnar's compiled Bitcoin Script Poseidon2 codegen
//! AND the Go runtime mock against the same library SP1 v6 is built on.
//!
//! Parameters (SP1 v6.0.2):
//!   - Field: KoalaBear (p = 2130706433)
//!   - State width: 16
//!   - S-box: x^3 (degree 3)
//!   - External rounds: 8 (4 initial + 4 final)
//!   - Internal rounds: 20
//!   - Total rounds: 28
//!   - Digest: first 8 elements of the output state
//!
//! Output: ../vectors/poseidon2_koalabear.json
//!
//! Usage: cargo run --release --bin generate_poseidon2_kb_vectors

mod koalabear_common;

use koalabear_common::{kb, to_u64, KoalaBear, P};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{default_koalabear_poseidon2_16, Poseidon2KoalaBear};
use p3_symmetric::Permutation;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Serialize)]
struct Poseidon2VectorFile {
    field: String,
    prime: u64,
    width: usize,
    sbox_degree: u64,
    external_rounds: usize,
    internal_rounds: usize,
    vectors: Vec<Poseidon2Vector>,
}

#[derive(Serialize)]
struct Poseidon2Vector {
    op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    left: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    right: Option<Vec<u64>>,
    expected: Vec<u64>,
    description: String,
}

fn state_to_u64(state: &[KoalaBear; 16]) -> Vec<u64> {
    state.iter().map(|f| to_u64(*f)).collect()
}

fn make_state(vals: [u64; 16]) -> [KoalaBear; 16] {
    let mut s = [KoalaBear::ZERO; 16];
    for (i, v) in vals.iter().enumerate() {
        s[i] = kb(*v);
    }
    s
}

fn generate_permute_vectors(perm: &Poseidon2KoalaBear<16>) -> Vec<Poseidon2Vector> {
    let mut vectors = Vec::new();
    let mut rng = StdRng::seed_from_u64(100);

    // All-zero input
    let mut state = make_state([0; 16]);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "all-zero input".into(),
    });

    // All-one input
    let mut state = make_state([1; 16]);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "all-one input".into(),
    });

    // Ascending [0, 1, 2, ..., 15]
    let mut state = make_state([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "ascending [0..15]".into(),
    });

    // All p-1
    let mut state = make_state([P - 1; 16]);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "all (p-1)".into(),
    });

    // Single element at position 0
    let mut vals = [0u64; 16];
    vals[0] = 42;
    let mut state = make_state(vals);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "single element at pos 0 (42)".into(),
    });

    // Single element at position 7
    let mut vals = [0u64; 16];
    vals[7] = 42;
    let mut state = make_state(vals);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "single element at pos 7 (42)".into(),
    });

    // Single element at position 15
    let mut vals = [0u64; 16];
    vals[15] = 42;
    let mut state = make_state(vals);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "single element at pos 15 (42)".into(),
    });

    // Rate slots p-1, capacity slots 0 (tests rate/capacity interaction)
    let mut vals = [0u64; 16];
    for i in 0..8 {
        vals[i] = P - 1;
    }
    let mut state = make_state(vals);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "rate slots (p-1), capacity zero".into(),
    });

    // Capacity slots p-1, rate slots 0 (inverse of above)
    let mut vals = [0u64; 16];
    for i in 8..16 {
        vals[i] = P - 1;
    }
    let mut state = make_state(vals);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "rate zero, capacity slots (p-1)".into(),
    });

    // Alternating 0 and p-1
    let mut vals = [0u64; 16];
    for i in 0..16 {
        vals[i] = if i % 2 == 0 { 0 } else { P - 1 };
    }
    let mut state = make_state(vals);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "alternating 0 and (p-1)".into(),
    });

    // Powers of 2
    let mut vals = [0u64; 16];
    for i in 0..16 {
        vals[i] = 1u64 << i;
    }
    let mut state = make_state(vals);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "powers of 2 [1, 2, 4, ..., 32768]".into(),
    });

    // All same large value (tests S-box with large input)
    let mut state = make_state([P / 2; 16]);
    let input = state_to_u64(&state);
    perm.permute_mut(&mut state);
    vectors.push(Poseidon2Vector {
        op: "permute".into(),
        input: Some(input),
        left: None,
        right: None,
        expected: state_to_u64(&state),
        description: "all (p/2)".into(),
    });

    // 5 random states
    for i in 0..5 {
        let mut vals = [0u64; 16];
        for v in vals.iter_mut() {
            *v = rng.gen_range(0..P);
        }
        let mut state = make_state(vals);
        let input = state_to_u64(&state);
        perm.permute_mut(&mut state);
        vectors.push(Poseidon2Vector {
            op: "permute".into(),
            input: Some(input),
            left: None,
            right: None,
            expected: state_to_u64(&state),
            description: format!("random state #{}", i),
        });
    }

    vectors
}

fn generate_compress_vectors(perm: &Poseidon2KoalaBear<16>) -> Vec<Poseidon2Vector> {
    let mut vectors = Vec::new();
    let mut rng = StdRng::seed_from_u64(101);

    let compress = |left: [u64; 8], right: [u64; 8], perm: &Poseidon2KoalaBear<16>| -> Vec<u64> {
        let mut state = [KoalaBear::ZERO; 16];
        for i in 0..8 {
            state[i] = kb(left[i]);
        }
        for i in 0..8 {
            state[8 + i] = kb(right[i]);
        }
        perm.permute_mut(&mut state);
        state[0..8].iter().map(|f| to_u64(*f)).collect()
    };

    // Both zero
    let left = [0u64; 8];
    let right = [0u64; 8];
    vectors.push(Poseidon2Vector {
        op: "compress".into(),
        input: None,
        left: Some(left.to_vec()),
        right: Some(right.to_vec()),
        expected: compress(left, right, perm),
        description: "both zero".into(),
    });

    // Left ascending, right zero
    let left = [1, 2, 3, 4, 5, 6, 7, 8];
    let right = [0u64; 8];
    vectors.push(Poseidon2Vector {
        op: "compress".into(),
        input: None,
        left: Some(left.to_vec()),
        right: Some(right.to_vec()),
        expected: compress(left, right, perm),
        description: "left ascending [1..8], right zero".into(),
    });

    // Left zero, right ascending
    let left = [0u64; 8];
    let right = [1, 2, 3, 4, 5, 6, 7, 8];
    vectors.push(Poseidon2Vector {
        op: "compress".into(),
        input: None,
        left: Some(left.to_vec()),
        right: Some(right.to_vec()),
        expected: compress(left, right, perm),
        description: "left zero, right ascending [1..8]".into(),
    });

    // Both ascending
    let left = [1, 2, 3, 4, 5, 6, 7, 8];
    let right = [9, 10, 11, 12, 13, 14, 15, 16];
    vectors.push(Poseidon2Vector {
        op: "compress".into(),
        input: None,
        left: Some(left.to_vec()),
        right: Some(right.to_vec()),
        expected: compress(left, right, perm),
        description: "both ascending [1..8] [9..16]".into(),
    });

    // Both all-one
    let left = [1u64; 8];
    let right = [1u64; 8];
    vectors.push(Poseidon2Vector {
        op: "compress".into(),
        input: None,
        left: Some(left.to_vec()),
        right: Some(right.to_vec()),
        expected: compress(left, right, perm),
        description: "both all-one".into(),
    });

    // Both all (p-1)
    let left = [P - 1; 8];
    let right = [P - 1; 8];
    vectors.push(Poseidon2Vector {
        op: "compress".into(),
        input: None,
        left: Some(left.to_vec()),
        right: Some(right.to_vec()),
        expected: compress(left, right, perm),
        description: "both all (p-1)".into(),
    });

    // Left all (p-1), right zero
    let left = [P - 1; 8];
    let right = [0u64; 8];
    vectors.push(Poseidon2Vector {
        op: "compress".into(),
        input: None,
        left: Some(left.to_vec()),
        right: Some(right.to_vec()),
        expected: compress(left, right, perm),
        description: "left all (p-1), right zero".into(),
    });

    // Left = right (identical halves)
    let both = [100, 200, 300, 400, 500, 600, 700, 800];
    vectors.push(Poseidon2Vector {
        op: "compress".into(),
        input: None,
        left: Some(both.to_vec()),
        right: Some(both.to_vec()),
        expected: compress(both, both, perm),
        description: "identical halves [100..800]".into(),
    });

    // 5 random pairs
    for i in 0..5 {
        let mut left = [0u64; 8];
        let mut right = [0u64; 8];
        for v in left.iter_mut() {
            *v = rng.gen_range(0..P);
        }
        for v in right.iter_mut() {
            *v = rng.gen_range(0..P);
        }
        vectors.push(Poseidon2Vector {
            op: "compress".into(),
            input: None,
            left: Some(left.to_vec()),
            right: Some(right.to_vec()),
            expected: compress(left, right, perm),
            description: format!("random pair #{}", i),
        });
    }

    vectors
}

fn main() {
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    fs::create_dir_all(&vectors_dir).expect("create vectors dir");

    // Use the default Plonky3 KoalaBear Poseidon2 width-16 instance
    let perm = default_koalabear_poseidon2_16();

    let mut all_vectors = Vec::new();
    all_vectors.extend(generate_permute_vectors(&perm));
    all_vectors.extend(generate_compress_vectors(&perm));

    let file = Poseidon2VectorFile {
        field: "koalabear".into(),
        prime: P,
        width: 16,
        sbox_degree: 3,
        external_rounds: 8,
        internal_rounds: 20,
        vectors: all_vectors,
    };

    let json = serde_json::to_string_pretty(&file).unwrap();
    let path = vectors_dir.join("poseidon2_koalabear.json");
    fs::write(&path, &json).unwrap();
    println!(
        "Generated {} Poseidon2 KoalaBear vectors in {:?}",
        file.vectors.len(),
        path
    );
}
