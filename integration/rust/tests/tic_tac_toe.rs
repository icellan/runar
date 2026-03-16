//! TicTacToe integration test — stateful contract with terminal payout methods.
//!
//! Tests compile, deploy, join, move, full game flow, and rejection cases
//! using the Runar SDK against a regtest node.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

fn deploy_game(
    provider: &mut runar_lang::sdk::RPCProvider,
    signer: &dyn runar_lang::sdk::Signer,
    player_x_hex: &str,
    bet_amount: i64,
) -> RunarContract {
    let artifact = compile_contract("examples/ts/tic-tac-toe/TicTacToe.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(player_x_hex.to_string()),
        SdkValue::Int(bet_amount),
    ]);
    contract
        .deploy(provider, signer, &DeployOptions {
            satoshis: 10000,
            change_address: None,
        })
        .expect("deploy failed");
    contract
}

// ---------------------------------------------------------------------------
// Compile
// ---------------------------------------------------------------------------

#[test]

fn test_tic_tac_toe_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/tic-tac-toe/TicTacToe.runar.ts");
    assert_eq!(artifact.contract_name, "TicTacToe");
}

// ---------------------------------------------------------------------------
// Deploy
// ---------------------------------------------------------------------------

#[test]

fn test_tic_tac_toe_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/tic-tac-toe/TicTacToe.runar.ts");

    let mut provider = create_provider();
    let player_x = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(player_x.pub_key_hex),
        SdkValue::Int(5000),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 10000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}

// ---------------------------------------------------------------------------
// Join — player O enters the game
// ---------------------------------------------------------------------------

#[test]

fn test_tic_tac_toe_join() {
    skip_if_no_node();

    let mut provider = create_provider();
    let (signer_x, player_x_wallet) = create_funded_wallet(&mut provider);
    let (signer_o, player_o_wallet) = create_funded_wallet(&mut provider);

    let mut contract = deploy_game(
        &mut provider,
        &*signer_x,
        &player_x_wallet.pub_key_hex,
        5000,
    );

    // join(opponentPK, sig) — sig is Auto (auto-computed)
    // State auto-computed from ANF IR
    let (txid, _) = contract
        .call(
            "join",
            &[SdkValue::Bytes(player_o_wallet.pub_key_hex.clone()), SdkValue::Auto],
            &mut provider,
            &*signer_o,
            None,
        )
        .expect("join failed");
    assert!(!txid.is_empty());
    assert_eq!(txid.len(), 64);
}

// ---------------------------------------------------------------------------
// Move — single move after join
// ---------------------------------------------------------------------------

#[test]

fn test_tic_tac_toe_move() {
    skip_if_no_node();

    let mut provider = create_provider();
    let (signer_x, player_x_wallet) = create_funded_wallet(&mut provider);
    let (signer_o, player_o_wallet) = create_funded_wallet(&mut provider);

    let mut contract = deploy_game(
        &mut provider,
        &*signer_x,
        &player_x_wallet.pub_key_hex,
        5000,
    );

    // Join
    contract
        .call(
            "join",
            &[SdkValue::Bytes(player_o_wallet.pub_key_hex.clone()), SdkValue::Auto],
            &mut provider,
            &*signer_o,
            None,
        )
        .expect("join failed");

    // Move: player X plays position 4 (center)
    // State auto-computed from ANF IR
    let (txid, _) = contract
        .call(
            "move",
            &[SdkValue::Int(4), SdkValue::Bytes(player_x_wallet.pub_key_hex.clone()), SdkValue::Auto],
            &mut provider,
            &*signer_x,
            None,
        )
        .expect("move failed");
    assert!(!txid.is_empty());
    assert_eq!(txid.len(), 64);
}

// ---------------------------------------------------------------------------
// Full game — X wins top row with moveAndWin
// ---------------------------------------------------------------------------

#[test]

fn test_tic_tac_toe_full_game() {
    skip_if_no_node();

    let mut provider = create_provider();
    let (signer_x, player_x_wallet) = create_funded_wallet(&mut provider);
    let (signer_o, player_o_wallet) = create_funded_wallet(&mut provider);

    let bet_amount = 1000i64;
    let mut contract = deploy_game(
        &mut provider,
        &*signer_x,
        &player_x_wallet.pub_key_hex,
        bet_amount,
    );

    let px = &player_x_wallet.pub_key_hex;
    let po = &player_o_wallet.pub_key_hex;

    // Join
    contract.call(
        "join",
        &[SdkValue::Bytes(po.clone()), SdkValue::Auto],
        &mut provider, &*signer_o, None,
    ).expect("join failed");

    // X@0, O@3, X@1, O@4 — set up X to win with position 2 (top row)
    contract.call(
        "move",
        &[SdkValue::Int(0), SdkValue::Bytes(px.clone()), SdkValue::Auto],
        &mut provider, &*signer_x, None,
    ).expect("move X@0 failed");

    contract.call(
        "move",
        &[SdkValue::Int(3), SdkValue::Bytes(po.clone()), SdkValue::Auto],
        &mut provider, &*signer_o, None,
    ).expect("move O@3 failed");

    contract.call(
        "move",
        &[SdkValue::Int(1), SdkValue::Bytes(px.clone()), SdkValue::Auto],
        &mut provider, &*signer_x, None,
    ).expect("move X@1 failed");

    contract.call(
        "move",
        &[SdkValue::Int(4), SdkValue::Bytes(po.clone()), SdkValue::Auto],
        &mut provider, &*signer_o, None,
    ).expect("move O@4 failed");

    // Board: X X _ | O O _ | _ _ _ — X plays position 2 to win top row
    // moveAndWin(position, player, sig, changePKH, changeAmount)
    let total_payout = bet_amount * 2;
    let winner_p2pkh = format!("76a914{}88ac", player_x_wallet.pub_key_hash);

    let (txid, _) = contract.call(
        "moveAndWin",
        &[
            SdkValue::Int(2),
            SdkValue::Bytes(px.clone()),
            SdkValue::Auto,
            SdkValue::Bytes("00".repeat(20)),
            SdkValue::Int(0),
        ],
        &mut provider, &*signer_x,
        Some(&runar_lang::sdk::CallOptions {
            terminal_outputs: Some(vec![runar_lang::sdk::TerminalOutput {
                script_hex: winner_p2pkh,
                satoshis: total_payout,
            }]),
            ..Default::default()
        }),
    ).expect("moveAndWin failed");
    assert!(!txid.is_empty());
    assert_eq!(txid.len(), 64);
}

// ---------------------------------------------------------------------------
// Wrong player rejected — player O tries to move on player X's turn
// ---------------------------------------------------------------------------

#[test]

fn test_tic_tac_toe_wrong_player_rejected() {
    skip_if_no_node();

    let mut provider = create_provider();
    let (signer_x, player_x_wallet) = create_funded_wallet(&mut provider);
    let (signer_o, player_o_wallet) = create_funded_wallet(&mut provider);

    let mut contract = deploy_game(
        &mut provider,
        &*signer_x,
        &player_x_wallet.pub_key_hex,
        5000,
    );

    let po = &player_o_wallet.pub_key_hex;

    // Join
    contract.call(
        "join",
        &[SdkValue::Bytes(po.clone()), SdkValue::Auto],
        &mut provider, &*signer_o, None,
    ).expect("join failed");

    // Player O tries to move on player X's turn — should fail
    let result = contract.call(
        "move",
        &[SdkValue::Int(4), SdkValue::Bytes(po.clone()), SdkValue::Auto],
        &mut provider, &*signer_o, None,
    );
    assert!(result.is_err(), "move by wrong player should be rejected");
}

// ---------------------------------------------------------------------------
// Join after playing rejected — cannot call join when game is in progress
// ---------------------------------------------------------------------------

#[test]

fn test_tic_tac_toe_join_after_playing_rejected() {
    skip_if_no_node();

    let mut provider = create_provider();
    let (signer_x, player_x_wallet) = create_funded_wallet(&mut provider);
    let (signer_o, player_o_wallet) = create_funded_wallet(&mut provider);

    let mut contract = deploy_game(
        &mut provider,
        &*signer_x,
        &player_x_wallet.pub_key_hex,
        5000,
    );

    let po = &player_o_wallet.pub_key_hex;

    // Join
    contract.call(
        "join",
        &[SdkValue::Bytes(po.clone()), SdkValue::Auto],
        &mut provider, &*signer_o, None,
    ).expect("join failed");

    // Try joining again — status is now 1 (playing), assert(status==0) should fail
    let intruder = create_wallet();
    let (intruder_signer, _) = create_funded_wallet(&mut provider);
    let result = contract.call(
        "join",
        &[SdkValue::Bytes(intruder.pub_key_hex.clone()), SdkValue::Auto],
        &mut provider, &*intruder_signer, None,
    );
    assert!(result.is_err(), "join after game started should be rejected");
}
