//! Rúnar deployment SDK — deploy and interact with compiled contracts on BSV.

pub mod types;
pub mod state;
pub mod deployment;
pub mod calling;
pub mod provider;
pub mod rpc_provider;
pub mod signer;
pub mod contract;
pub mod oppushtx;
pub mod anf_interpreter;
pub mod codegen;
pub mod script_utils;
pub mod token_wallet;
pub mod wallet;
pub mod woc_provider;
pub mod ordinals;
pub mod gorillapool;

pub use types::*;
pub use state::{serialize_state, deserialize_state, extract_state_from_script, find_last_op_return};
pub use deployment::{build_deploy_transaction, select_utxos, estimate_deploy_fee};
pub use calling::{build_call_transaction, build_call_transaction_ext, estimate_call_fee, CallTxOptions, ContractOutput, AdditionalContractInput};
pub use provider::{Provider, MockProvider};
pub use rpc_provider::RPCProvider;
pub use signer::{Signer, LocalSigner, ExternalSigner, MockSigner};
pub use contract::RunarContract;
pub use types::PreparedCall;
pub use oppushtx::compute_op_push_tx;
pub use codegen::generate_rust;
pub use script_utils::{extract_constructor_args, matches_artifact};
pub use woc_provider::WhatsOnChainProvider;
pub use token_wallet::TokenWallet;
pub use wallet::{
    WalletClient, WalletSigner, WalletProvider,
    WalletActionOutput, WalletActionResult, WalletOutput,
    DeployWithWalletOptions, deploy_with_wallet,
};
pub use ordinals::{
    Inscription, EnvelopeBounds,
    build_inscription_envelope, parse_inscription_envelope,
    find_inscription_envelope, strip_inscription_envelope,
    bsv20_deploy, bsv20_mint, bsv20_transfer,
    bsv21_deploy_mint, bsv21_transfer,
};
pub use gorillapool::GorillaPoolProvider;
