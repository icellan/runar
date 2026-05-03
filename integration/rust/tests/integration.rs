mod helpers;
mod counter;
mod math_demo;
mod p2pkh;
mod escrow;
mod fungible_token;
mod nft;
mod auction;
mod covenant_vault;
mod oracle_price_feed;
mod function_patterns;
mod post_quantum_wallet;
mod sphincs_wallet;
mod schnorr_zkp;
mod convergence_proof;
mod ec_isolation;
mod tic_tac_toe;
mod babybear;
mod merkle_proof;
mod private_helper_outputs;
mod state_covenant;

// Phase 2 (2026-05-03): port advanced TS/Go regtest cases that the Rust
// integration suite was missing per the 2026-05-01 audit.
mod blake3;
mod sha256_compress;
mod sha256_finalize;
mod slhdsa;
mod wots;
mod p256_wallet;
mod p384_wallet;
mod data_outputs;
mod nullfail_multimethod;
mod message_board;
mod ordinals;
