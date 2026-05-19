"""Runar SDK for Python — deployment and interaction with compiled contracts."""

from runar.sdk.types import (
    Utxo, TransactionData, Transaction, TxInput, TxOutput,
    RunarArtifact, Abi, AbiMethod, AbiParam,
    StateField, ConstructorSlot, CodeSepIndexSlot, DeployOptions, CallOptions, OutputSpec,
    PreparedCall, SdkValue, TerminalOutput,
)
from runar.sdk.input_limits import MAX_SCRIPT_BYTES
from runar.sdk.errors import ScriptSizeExceededError, assert_script_hex_under_limit
from runar.sdk.provider import Provider, MockProvider
from runar.sdk.rpc_provider import RPCProvider
from runar.sdk.woc_provider import WhatsOnChainProvider
from runar.sdk.signer import Signer, MockSigner, ExternalSigner
from runar.sdk.local_signer import LocalSigner
from runar.sdk.contract import RunarContract
from runar.sdk.deployment import build_deploy_transaction, select_utxos, estimate_deploy_fee, build_p2pkh_script
from runar.sdk.calling import build_call_transaction, insert_unlocking_script, estimate_call_fee
from runar.sdk.state import serialize_state, deserialize_state, find_last_op_return
from runar.sdk.oppushtx import compute_op_push_tx
from runar.sdk.anf_interpreter import (
    compute_new_state,
    compute_new_state_and_data_outputs,
    execute_strict,
    execute_on_chain_authoritative,
    AssertionFailureError,
    OnChainCryptoContext,
    IntentInterpreter,
    IntentCallResult,
    WitnessBytesMissingError,
)
from runar.sdk.codegen import generate_python
from runar.sdk.script_utils import extract_constructor_args, matches_artifact
from runar.sdk.token_wallet import TokenWallet
from runar.sdk.wallet import WalletClient, WalletProvider, WalletSigner
from runar.sdk.ordinals import (
    Inscription, EnvelopeBounds,
    build_inscription_envelope, parse_inscription_envelope,
    find_inscription_envelope, strip_inscription_envelope,
    bsv20_deploy, bsv20_mint, bsv20_transfer,
    bsv21_deploy_mint, bsv21_transfer,
)
from runar.sdk.gorillapool import GorillaPoolProvider
from runar.sdk.envelope import (
    canonical_json,
    sign_envelope, verify_envelope,
    SignedEnvelope, VerifyEnvelopeResult, VerifyEnvelopeReason, SignFn,
)

__all__ = [
    'Utxo', 'TransactionData', 'Transaction', 'TxInput', 'TxOutput',
    'RunarArtifact', 'Abi', 'AbiMethod', 'AbiParam',
    'StateField', 'ConstructorSlot', 'CodeSepIndexSlot', 'DeployOptions', 'CallOptions', 'OutputSpec',
    'PreparedCall', 'SdkValue', 'TerminalOutput',
    'Provider', 'MockProvider', 'RPCProvider', 'WhatsOnChainProvider',
    'Signer', 'MockSigner', 'ExternalSigner', 'LocalSigner',
    'RunarContract',
    'build_deploy_transaction', 'select_utxos', 'estimate_deploy_fee',
    'build_p2pkh_script',
    'build_call_transaction', 'insert_unlocking_script', 'estimate_call_fee',
    'serialize_state', 'deserialize_state', 'find_last_op_return',
    'compute_op_push_tx',
    'compute_new_state', 'compute_new_state_and_data_outputs',
    'execute_strict', 'execute_on_chain_authoritative',
    'AssertionFailureError', 'OnChainCryptoContext',
    'IntentInterpreter', 'IntentCallResult', 'WitnessBytesMissingError',
    'generate_python',
    'extract_constructor_args', 'matches_artifact',
    'TokenWallet',
    'WalletClient', 'WalletProvider', 'WalletSigner',
    'Inscription', 'EnvelopeBounds',
    'build_inscription_envelope', 'parse_inscription_envelope',
    'find_inscription_envelope', 'strip_inscription_envelope',
    'bsv20_deploy', 'bsv20_mint', 'bsv20_transfer',
    'bsv21_deploy_mint', 'bsv21_transfer',
    'GorillaPoolProvider',
    'canonical_json', 'sign_envelope', 'verify_envelope',
    'SignedEnvelope', 'VerifyEnvelopeResult', 'VerifyEnvelopeReason', 'SignFn',
    'MAX_SCRIPT_BYTES', 'ScriptSizeExceededError', 'assert_script_hex_under_limit',
]
