//! Generates Koala Bear field arithmetic test vectors using Plonky3's p3-koala-bear
//! as the reference implementation. These vectors validate Rúnar's compiled
//! Bitcoin Script field arithmetic against the same library SP1 is built on.
//!
//! Output: JSON files in ../vectors/ for add, sub, mul, inv operations.

mod koalabear_common;

use p3_field::{Field, PrimeCharacteristicRing};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use std::fs;
use std::path::Path;

use koalabear_common::*;

#[derive(Serialize)]
struct TestVectorFile {
    field: String,
    prime: u64,
    vectors: Vec<TestVector>,
}

#[derive(Serialize)]
struct TestVector {
    op: String,
    a: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    b: Option<u64>,
    expected: u64,
    description: String,
}

#[derive(Serialize)]
struct Ext4TestVectorFile {
    field: String,
    prime: u64,
    extension_degree: u32,
    vectors: Vec<Ext4TestVector>,
}

#[derive(Serialize)]
struct Ext4TestVector {
    op: String,
    a: [u64; 4],
    #[serde(skip_serializing_if = "Option::is_none")]
    b: Option<[u64; 4]>,
    expected: [u64; 4],
    description: String,
}

/// Generate deterministic "random" values using a seeded RNG
fn random_field_values(rng: &mut StdRng, count: usize) -> Vec<u64> {
    (0..count).map(|_| rng.gen_range(0..P) as u64).collect()
}

fn generate_add_vectors() -> Vec<TestVector> {
    let mut vectors = Vec::new();
    let mut rng = StdRng::seed_from_u64(42);

    // Edge cases: zero
    vectors.push(TestVector {
        op: "add".into(),
        a: 0,
        b: Some(0),
        expected: to_u64(kb(0) + kb(0)),
        description: "0 + 0 = 0".into(),
    });
    vectors.push(TestVector {
        op: "add".into(),
        a: 1,
        b: Some(0),
        expected: to_u64(kb(1) + kb(0)),
        description: "1 + 0 = 1 (additive identity)".into(),
    });
    vectors.push(TestVector {
        op: "add".into(),
        a: 0,
        b: Some(1),
        expected: to_u64(kb(0) + kb(1)),
        description: "0 + 1 = 1 (additive identity)".into(),
    });

    // Edge cases: near prime
    vectors.push(TestVector {
        op: "add".into(),
        a: P - 1,
        b: Some(1),
        expected: to_u64(kb((P - 1) as u64) + kb(1)),
        description: "(p-1) + 1 = 0 (wrap around)".into(),
    });
    vectors.push(TestVector {
        op: "add".into(),
        a: P - 1,
        b: Some(P - 1),
        expected: to_u64(kb((P - 1) as u64) + kb((P - 1) as u64)),
        description: "(p-1) + (p-1) = p-2 (double wrap)".into(),
    });
    vectors.push(TestVector {
        op: "add".into(),
        a: P - 2,
        b: Some(2),
        expected: to_u64(kb((P - 2) as u64) + kb(2)),
        description: "(p-2) + 2 = 0".into(),
    });

    // Small values
    for i in 1u64..=10 {
        for j in 1u64..=10 {
            vectors.push(TestVector {
                op: "add".into(),
                a: i,
                b: Some(j),
                expected: to_u64(kb(i) + kb(j)),
                description: format!("{} + {}", i, j),
            });
        }
    }

    // Powers of 2
    for i in 0..31 {
        let a = 1u64 << i;
        if a < P {
            vectors.push(TestVector {
                op: "add".into(),
                a,
                b: Some(1),
                expected: to_u64(kb(a) + kb(1)),
                description: format!("2^{} + 1", i),
            });
        }
    }

    // Random values
    let randoms = random_field_values(&mut rng, 100);
    for i in (0..randoms.len()).step_by(2) {
        let a = randoms[i];
        let b = randoms[i + 1];
        vectors.push(TestVector {
            op: "add".into(),
            a,
            b: Some(b),
            expected: to_u64(kb(a) + kb(b)),
            description: format!("random: {} + {}", a, b),
        });
    }

    vectors
}

fn generate_sub_vectors() -> Vec<TestVector> {
    let mut vectors = Vec::new();
    let mut rng = StdRng::seed_from_u64(43);

    // Edge cases
    vectors.push(TestVector {
        op: "sub".into(),
        a: 0,
        b: Some(0),
        expected: to_u64(kb(0) - kb(0)),
        description: "0 - 0 = 0".into(),
    });
    vectors.push(TestVector {
        op: "sub".into(),
        a: 1,
        b: Some(0),
        expected: to_u64(kb(1) - kb(0)),
        description: "1 - 0 = 1".into(),
    });
    vectors.push(TestVector {
        op: "sub".into(),
        a: 0,
        b: Some(1),
        expected: to_u64(kb(0) - kb(1)),
        description: "0 - 1 = p-1 (underflow wrap)".into(),
    });
    vectors.push(TestVector {
        op: "sub".into(),
        a: 1,
        b: Some(P - 1),
        expected: to_u64(kb(1) - kb((P - 1) as u64)),
        description: "1 - (p-1) = 2 (underflow wrap)".into(),
    });
    vectors.push(TestVector {
        op: "sub".into(),
        a: P - 1,
        b: Some(P - 1),
        expected: to_u64(kb((P - 1) as u64) - kb((P - 1) as u64)),
        description: "(p-1) - (p-1) = 0".into(),
    });

    // Small values
    for i in 0u64..=10 {
        for j in 0u64..=10 {
            vectors.push(TestVector {
                op: "sub".into(),
                a: i,
                b: Some(j),
                expected: to_u64(kb(i) - kb(j)),
                description: format!("{} - {}", i, j),
            });
        }
    }

    // Random values
    let randoms = random_field_values(&mut rng, 200);
    for i in (0..randoms.len()).step_by(2) {
        let a = randoms[i];
        let b = randoms[i + 1];
        vectors.push(TestVector {
            op: "sub".into(),
            a,
            b: Some(b),
            expected: to_u64(kb(a) - kb(b)),
            description: format!("random: {} - {}", a, b),
        });
    }

    vectors
}

fn generate_mul_vectors() -> Vec<TestVector> {
    let mut vectors = Vec::new();
    let mut rng = StdRng::seed_from_u64(44);

    // Edge cases
    vectors.push(TestVector {
        op: "mul".into(),
        a: 0,
        b: Some(0),
        expected: to_u64(kb(0) * kb(0)),
        description: "0 * 0 = 0".into(),
    });
    vectors.push(TestVector {
        op: "mul".into(),
        a: 1,
        b: Some(0),
        expected: to_u64(kb(1) * kb(0)),
        description: "1 * 0 = 0".into(),
    });
    vectors.push(TestVector {
        op: "mul".into(),
        a: 0,
        b: Some(1),
        expected: to_u64(kb(0) * kb(1)),
        description: "0 * 1 = 0".into(),
    });
    vectors.push(TestVector {
        op: "mul".into(),
        a: 1,
        b: Some(1),
        expected: to_u64(kb(1) * kb(1)),
        description: "1 * 1 = 1 (multiplicative identity)".into(),
    });
    vectors.push(TestVector {
        op: "mul".into(),
        a: P - 1,
        b: Some(P - 1),
        expected: to_u64(kb((P - 1) as u64) * kb((P - 1) as u64)),
        description: "(p-1) * (p-1) = 1 ((-1)*(-1)=1)".into(),
    });
    vectors.push(TestVector {
        op: "mul".into(),
        a: P - 1,
        b: Some(2),
        expected: to_u64(kb((P - 1) as u64) * kb(2)),
        description: "(p-1) * 2 = p-2 ((-1)*2=-2)".into(),
    });

    // Small values
    for i in 1u64..=12 {
        for j in 1u64..=12 {
            vectors.push(TestVector {
                op: "mul".into(),
                a: i,
                b: Some(j),
                expected: to_u64(kb(i) * kb(j)),
                description: format!("{} * {}", i, j),
            });
        }
    }

    // Powers of 2
    for i in 0..31 {
        let a = 1u64 << i;
        if a < P {
            vectors.push(TestVector {
                op: "mul".into(),
                a,
                b: Some(2),
                expected: to_u64(kb(a) * kb(2)),
                description: format!("2^{} * 2", i),
            });
        }
    }

    // Large products that require reduction
    vectors.push(TestVector {
        op: "mul".into(),
        a: 123456,
        b: Some(789012),
        expected: to_u64(kb(123456) * kb(789012)),
        description: "123456 * 789012 (large product)".into(),
    });
    vectors.push(TestVector {
        op: "mul".into(),
        a: 1000000000,
        b: Some(1000000000),
        expected: to_u64(kb(1000000000) * kb(1000000000)),
        description: "10^9 * 10^9 (overflow reduction)".into(),
    });

    // Generator powers (Koala Bear generator = 3)
    let gen = 3u64;
    let mut g = kb(gen);
    for i in 1..=20 {
        vectors.push(TestVector {
            op: "mul".into(),
            a: to_u64(g),
            b: Some(gen),
            expected: to_u64(g * kb(gen)),
            description: format!("g^{} * g (generator chain)", i),
        });
        g = g * kb(gen);
    }

    // Random values
    let randoms = random_field_values(&mut rng, 100);
    for i in (0..randoms.len()).step_by(2) {
        let a = randoms[i];
        let b = randoms[i + 1];
        vectors.push(TestVector {
            op: "mul".into(),
            a,
            b: Some(b),
            expected: to_u64(kb(a) * kb(b)),
            description: format!("random: {} * {}", a, b),
        });
    }

    vectors
}

fn generate_inv_vectors() -> Vec<TestVector> {
    let mut vectors = Vec::new();
    let mut rng = StdRng::seed_from_u64(45);

    // Edge cases
    vectors.push(TestVector {
        op: "inv".into(),
        a: 1,
        b: None,
        expected: to_u64(kb(1).inverse()),
        description: "inv(1) = 1".into(),
    });
    vectors.push(TestVector {
        op: "inv".into(),
        a: P - 1,
        b: None,
        expected: to_u64(kb((P - 1) as u64).inverse()),
        description: "inv(p-1) = p-1 (inv(-1) = -1)".into(),
    });
    vectors.push(TestVector {
        op: "inv".into(),
        a: 2,
        b: None,
        expected: to_u64(kb(2).inverse()),
        description: "inv(2)".into(),
    });

    // Small values
    for i in 1u64..=50 {
        vectors.push(TestVector {
            op: "inv".into(),
            a: i,
            b: None,
            expected: to_u64(kb(i).inverse()),
            description: format!("inv({})", i),
        });
    }

    // Powers of 2
    for i in 1..31 {
        let a = 1u64 << i;
        if a < P {
            vectors.push(TestVector {
                op: "inv".into(),
                a,
                b: None,
                expected: to_u64(kb(a).inverse()),
                description: format!("inv(2^{})", i),
            });
        }
    }

    // Near-prime values
    for offset in 1u64..=10 {
        vectors.push(TestVector {
            op: "inv".into(),
            a: P - offset,
            b: None,
            expected: to_u64(kb((P - offset) as u64).inverse()),
            description: format!("inv(p-{})", offset),
        });
    }

    // Generator powers
    let gen = 3u64;
    let mut g = kb(gen);
    for i in 1..=20 {
        vectors.push(TestVector {
            op: "inv".into(),
            a: to_u64(g),
            b: None,
            expected: to_u64(g.inverse()),
            description: format!("inv(g^{}) where g=3", i),
        });
        g = g * kb(gen);
    }

    // Random values
    let randoms: Vec<u64> = random_field_values(&mut rng, 50)
        .into_iter()
        .filter(|&v| v != 0) // inv(0) is undefined
        .collect();
    for a in &randoms {
        vectors.push(TestVector {
            op: "inv".into(),
            a: *a,
            b: None,
            expected: to_u64(kb(*a).inverse()),
            description: format!("random: inv({})", a),
        });
    }

    vectors
}

fn generate_ext4_mul_vectors() -> Vec<Ext4TestVector> {
    let mut vectors = Vec::new();
    let mut rng = StdRng::seed_from_u64(46);

    // Identity: a * 1 = a
    let a = ef4(42, 17, 99, 3);
    let one = EF4::ONE;
    vectors.push(Ext4TestVector {
        op: "ext4_mul".into(),
        a: ef4_to_array(a),
        b: Some(ef4_to_array(one)),
        expected: ef4_to_array(a * one),
        description: "a * 1 = a (multiplicative identity)".into(),
    });

    // Zero: a * 0 = 0
    let zero = EF4::ZERO;
    vectors.push(Ext4TestVector {
        op: "ext4_mul".into(),
        a: ef4_to_array(a),
        b: Some(ef4_to_array(zero)),
        expected: ef4_to_array(a * zero),
        description: "a * 0 = 0".into(),
    });

    // Base field embedding: (x, 0, 0, 0) * (y, 0, 0, 0) = (x*y mod p, 0, 0, 0)
    for i in 1u64..=10 {
        for j in 1u64..=10 {
            let a = ef4(i, 0, 0, 0);
            let b = ef4(j, 0, 0, 0);
            vectors.push(Ext4TestVector {
                op: "ext4_mul".into(),
                a: ef4_to_array(a),
                b: Some(ef4_to_array(b)),
                expected: ef4_to_array(a * b),
                description: format!("base: {} * {}", i, j),
            });
        }
    }

    // Pure extension elements: (0, a1, 0, 0) * (0, b1, 0, 0)
    // Tests the irreducible polynomial reduction
    for i in [1u64, 2, 5, 100, P - 1] {
        for j in [1u64, 3, 7, 200, P - 2] {
            let a = ef4(0, i, 0, 0);
            let b = ef4(0, j, 0, 0);
            vectors.push(Ext4TestVector {
                op: "ext4_mul".into(),
                a: ef4_to_array(a),
                b: Some(ef4_to_array(b)),
                expected: ef4_to_array(a * b),
                description: format!("pure ext: (0,{},0,0) * (0,{},0,0)", i, j),
            });
        }
    }

    // Mixed elements
    let test_elems: Vec<EF4> = vec![
        ef4(1, 1, 0, 0),
        ef4(1, 0, 1, 0),
        ef4(1, 0, 0, 1),
        ef4(1, 1, 1, 1),
        ef4(P - 1, P - 1, P - 1, P - 1),
        ef4(2, 3, 5, 7),
        ef4(11, 13, 17, 19),
    ];
    for a in &test_elems {
        for b in &test_elems {
            vectors.push(Ext4TestVector {
                op: "ext4_mul".into(),
                a: ef4_to_array(*a),
                b: Some(ef4_to_array(*b)),
                expected: ef4_to_array(*a * *b),
                description: format!(
                    "mixed: {:?} * {:?}",
                    ef4_to_array(*a),
                    ef4_to_array(*b)
                ),
            });
        }
    }

    // Random values
    for _ in 0..50 {
        let a = random_ef4(&mut rng);
        let b = random_ef4(&mut rng);
        vectors.push(Ext4TestVector {
            op: "ext4_mul".into(),
            a: ef4_to_array(a),
            b: Some(ef4_to_array(b)),
            expected: ef4_to_array(a * b),
            description: format!("random: {:?} * {:?}", ef4_to_array(a), ef4_to_array(b)),
        });
    }

    vectors
}

fn generate_ext4_inv_vectors() -> Vec<Ext4TestVector> {
    let mut vectors = Vec::new();
    let mut rng = StdRng::seed_from_u64(47);

    // inv(1) = 1
    let one = EF4::ONE;
    vectors.push(Ext4TestVector {
        op: "ext4_inv".into(),
        a: ef4_to_array(one),
        b: None,
        expected: ef4_to_array(one.inverse()),
        description: "inv(1) = 1".into(),
    });

    // inv(-1) = -1
    let neg_one = ef4(P - 1, 0, 0, 0);
    vectors.push(Ext4TestVector {
        op: "ext4_inv".into(),
        a: ef4_to_array(neg_one),
        b: None,
        expected: ef4_to_array(neg_one.inverse()),
        description: "inv(-1) = -1".into(),
    });

    // Base field embeddings
    for i in [2u64, 3, 5, 7, 11, 42, 100, P - 1, P - 2] {
        let a = ef4(i, 0, 0, 0);
        vectors.push(Ext4TestVector {
            op: "ext4_inv".into(),
            a: ef4_to_array(a),
            b: None,
            expected: ef4_to_array(a.inverse()),
            description: format!("inv(({},0,0,0))", i),
        });
    }

    // Pure extension elements
    let test_elems: Vec<EF4> = vec![
        ef4(0, 1, 0, 0),
        ef4(0, 0, 1, 0),
        ef4(0, 0, 0, 1),
        ef4(1, 1, 0, 0),
        ef4(1, 1, 1, 1),
        ef4(2, 3, 5, 7),
        ef4(11, 13, 17, 19),
        ef4(P - 1, P - 1, P - 1, P - 1),
    ];
    for a in &test_elems {
        vectors.push(Ext4TestVector {
            op: "ext4_inv".into(),
            a: ef4_to_array(*a),
            b: None,
            expected: ef4_to_array(a.inverse()),
            description: format!("inv({:?})", ef4_to_array(*a)),
        });
    }

    // Random values (non-zero)
    for _ in 0..50 {
        let a = loop {
            let candidate = random_ef4(&mut rng);
            if candidate != EF4::ZERO {
                break candidate;
            }
        };
        vectors.push(Ext4TestVector {
            op: "ext4_inv".into(),
            a: ef4_to_array(a),
            b: None,
            expected: ef4_to_array(a.inverse()),
            description: format!("random: inv({:?})", ef4_to_array(a)),
        });
    }

    vectors
}

fn main() {
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    fs::create_dir_all(&vectors_dir).expect("create vectors dir");

    // Generate addition vectors
    let add_vectors = generate_add_vectors();
    let add_file = TestVectorFile {
        field: "koalabear".into(),
        prime: P,
        vectors: add_vectors,
    };
    let add_json = serde_json::to_string_pretty(&add_file).unwrap();
    fs::write(vectors_dir.join("koalabear_add.json"), &add_json).unwrap();
    println!(
        "Generated {} addition vectors",
        add_file.vectors.len()
    );

    // Generate subtraction vectors
    let sub_vectors = generate_sub_vectors();
    let sub_file = TestVectorFile {
        field: "koalabear".into(),
        prime: P,
        vectors: sub_vectors,
    };
    let sub_json = serde_json::to_string_pretty(&sub_file).unwrap();
    fs::write(vectors_dir.join("koalabear_sub.json"), &sub_json).unwrap();
    println!(
        "Generated {} subtraction vectors",
        sub_file.vectors.len()
    );

    // Generate multiplication vectors
    let mul_vectors = generate_mul_vectors();
    let mul_file = TestVectorFile {
        field: "koalabear".into(),
        prime: P,
        vectors: mul_vectors,
    };
    let mul_json = serde_json::to_string_pretty(&mul_file).unwrap();
    fs::write(vectors_dir.join("koalabear_mul.json"), &mul_json).unwrap();
    println!(
        "Generated {} multiplication vectors",
        mul_file.vectors.len()
    );

    // Generate inverse vectors
    let inv_vectors = generate_inv_vectors();
    let inv_file = TestVectorFile {
        field: "koalabear".into(),
        prime: P,
        vectors: inv_vectors,
    };
    let inv_json = serde_json::to_string_pretty(&inv_file).unwrap();
    fs::write(vectors_dir.join("koalabear_inv.json"), &inv_json).unwrap();
    println!(
        "Generated {} inverse vectors",
        inv_file.vectors.len()
    );

    // Generate extension field multiplication vectors
    let ext4_mul_vectors = generate_ext4_mul_vectors();
    let ext4_mul_file = Ext4TestVectorFile {
        field: "koalabear_ext4".into(),
        prime: P,
        extension_degree: 4,
        vectors: ext4_mul_vectors,
    };
    let ext4_mul_json = serde_json::to_string_pretty(&ext4_mul_file).unwrap();
    fs::write(vectors_dir.join("koalabear_ext4_mul.json"), &ext4_mul_json).unwrap();
    println!(
        "Generated {} extension field multiplication vectors",
        ext4_mul_file.vectors.len()
    );

    // Generate extension field inverse vectors
    let ext4_inv_vectors = generate_ext4_inv_vectors();
    let ext4_inv_file = Ext4TestVectorFile {
        field: "koalabear_ext4".into(),
        prime: P,
        extension_degree: 4,
        vectors: ext4_inv_vectors,
    };
    let ext4_inv_json = serde_json::to_string_pretty(&ext4_inv_file).unwrap();
    fs::write(vectors_dir.join("koalabear_ext4_inv.json"), &ext4_inv_json).unwrap();
    println!(
        "Generated {} extension field inverse vectors",
        ext4_inv_file.vectors.len()
    );

    println!("\nAll Koala Bear test vectors written to {:?}", vectors_dir);
}
