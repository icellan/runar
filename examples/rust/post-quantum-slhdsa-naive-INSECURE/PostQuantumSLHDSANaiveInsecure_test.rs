// PostQuantumSLHDSANaiveInsecure.runar.rs is a pedagogical artifact that
// shows the broken pattern of verifying a free post-quantum signature
// against a free message — anyone observing one valid spend can reuse the
// (msg, sig) pair (or substitute any other (msg, sig) they have) and the
// script still verifies. The correct hybrid pattern lives in
// examples/rust/sphincs-wallet.
//
// We could in principle import the contract via `#[path]` and demonstrate
// the broken behaviour with a native call (the verify_slh_dsa_sha2_128s
// SDK shim returns true under mocked crypto), but the SDK mock would
// trivially pass for arbitrary (msg, sig) inputs and obscure the real
// attack vector — which only manifests on-chain against a real verifier.
// We exercise the Rúnar frontend directly via compile_check, which is the
// cross-compiler conformance boundary we care about.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("PostQuantumSLHDSANaiveInsecure.runar.rs"),
        "PostQuantumSLHDSANaiveInsecure.runar.rs",
    )
    .unwrap();
}
