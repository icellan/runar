"""Runar SDK types for deploying and interacting with compiled contracts on BSV."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from runar.sdk.signer import Signer


@dataclass
class Utxo:
    """An unspent transaction output."""
    txid: str
    output_index: int
    satoshis: int
    script: str  # hex-encoded locking script


@dataclass
class TxInput:
    """A transaction input."""
    txid: str
    output_index: int
    script: str  # hex-encoded scriptSig
    sequence: int = 0xFFFFFFFF


@dataclass
class TxOutput:
    """A transaction output."""
    satoshis: int
    script: str  # hex-encoded locking script


@dataclass
class TransactionData:
    """A parsed Bitcoin transaction (data shape for get_transaction return)."""
    txid: str
    version: int = 1
    inputs: list[TxInput] = field(default_factory=list)
    outputs: list[TxOutput] = field(default_factory=list)
    locktime: int = 0
    raw: str = ''


# Backward compatibility alias
Transaction = TransactionData


@dataclass
class AbiParam:
    """A single ABI parameter."""
    name: str
    type: str
    # Present when this param represents an expanded FixedArray<T, N>.
    fixed_array: dict | None = None


@dataclass
class AbiMethod:
    """A contract method descriptor."""
    name: str
    params: list[AbiParam] = field(default_factory=list)
    is_public: bool = True
    is_terminal: bool | None = None
    # Unlocking script is prefixed with _codePart (issue #100).
    uses_code_part: bool | None = None
    # Issue #123: BIP-143 sighash type this method's preimage/covenant is built
    # under (from a @sighash directive), e.g. 0x43 for SINGLE|FORKID. ``None`` =
    # default ALL|FORKID (0x41); the SDK falls back to 0x41.
    sig_hash_type: int | None = None


@dataclass
class Abi:
    """Contract ABI: constructor params and method descriptors."""
    constructor_params: list[AbiParam] = field(default_factory=list)
    methods: list[AbiMethod] = field(default_factory=list)


@dataclass
class StateField:
    """A state field in a stateful contract."""
    name: str
    type: str
    index: int
    initial_value: object = None  # compile-time default (may be "0n" string from JSON)
    # Present for grouped FixedArray state fields. Shape:
    # ``{"elementType": str, "length": int, "syntheticNames": list[str]}``.
    fixed_array: dict | None = None


@dataclass
class ConstructorSlot:
    """Where a constructor placeholder resides in the compiled script."""
    param_index: int
    byte_offset: int


@dataclass
class CodeSepIndexSlot:
    """Where a codeSeparatorIndex placeholder (OP_0) resides in the template script.

    The SDK substitutes these at deployment time with the adjusted
    codeSeparatorIndex value that accounts for constructor arg expansion.
    """
    byte_offset: int
    code_sep_index: int


@dataclass
class RunarArtifact:
    """Compiled output of a Runar compiler."""
    version: str = ''
    compiler_version: str = ''
    contract_name: str = ''
    # Base class the source contract extends. Authoritative stateful signal
    # for the issue-#42/#44 terminal sighash subscript trim: a
    # StatefulSmartContract with zero mutable fields still needs the trim even
    # though state_fields is empty. Older artifacts leave it empty.
    parent_class: str = ''
    abi: Abi = field(default_factory=Abi)
    script: str = ''
    asm: str = ''
    state_fields: list[StateField] = field(default_factory=list)
    constructor_slots: list[ConstructorSlot] = field(default_factory=list)
    code_sep_index_slots: list[CodeSepIndexSlot] = field(default_factory=list)
    build_timestamp: str = ''
    code_separator_index: int | None = None
    code_separator_indices: list[int] | None = None
    anf: dict | None = None
    # Builtins this script reaches that the compiler does not claim are sound
    # (R-062). Empty for every ordinary contract; see unsound_primitives.py.
    unsound_primitives: list[str] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict) -> RunarArtifact:
        """Load an artifact from a JSON-parsed dict."""
        abi_raw = d.get('abi', {})
        ctor_params = [
            AbiParam(
                name=p['name'], type=p['type'],
                fixed_array=p.get('fixedArray'),
            )
            for p in abi_raw.get('constructor', {}).get('params', [])
        ]
        methods = [
            AbiMethod(
                name=m['name'],
                params=[
                    AbiParam(
                        name=p['name'], type=p['type'],
                        fixed_array=p.get('fixedArray'),
                    )
                    for p in m.get('params', [])
                ],
                is_public=m.get('isPublic', True),
                is_terminal=m.get('isTerminal'),
                uses_code_part=m.get('usesCodePart'),
                sig_hash_type=m.get('sigHashType'),
            )
            for m in abi_raw.get('methods', [])
        ]
        state_fields = [
            StateField(
                name=sf['name'], type=sf['type'], index=sf['index'],
                initial_value=sf.get('initialValue'),
                fixed_array=sf.get('fixedArray'),
            )
            for sf in d.get('stateFields', [])
        ]
        ctor_slots = [
            ConstructorSlot(param_index=cs['paramIndex'], byte_offset=cs['byteOffset'])
            for cs in d.get('constructorSlots', [])
        ]
        code_sep_idx_slots = [
            CodeSepIndexSlot(byte_offset=s['byteOffset'], code_sep_index=s['codeSepIndex'])
            for s in d.get('codeSepIndexSlots', [])
        ]
        return RunarArtifact(
            version=d.get('version', ''),
            compiler_version=d.get('compilerVersion', ''),
            contract_name=d.get('contractName', ''),
            parent_class=d.get('parentClass', ''),
            abi=Abi(constructor_params=ctor_params, methods=methods),
            script=d.get('script', ''),
            asm=d.get('asm', ''),
            state_fields=state_fields,
            constructor_slots=ctor_slots,
            code_sep_index_slots=code_sep_idx_slots,
            build_timestamp=d.get('buildTimestamp', ''),
            code_separator_index=d.get('codeSeparatorIndex'),
            code_separator_indices=d.get('codeSeparatorIndices'),
            anf=d.get('anf'),
            unsound_primitives=list(d.get('unsoundPrimitives') or []),
        )


@dataclass
class DeployOptions:
    """Options for deploying a contract."""
    satoshis: int = 10000
    change_address: str = ''
    # Signer for the P2PKH funding inputs (issue #134). When the funding UTXOs
    # are owned by a different key than the connected deploy signer, set this
    # so the funding inputs are signed by their real owner. Defaults to the
    # connected signer (zero behaviour change).
    funding_signer: 'Signer | None' = None
    # Builtins the caller accepts despite the compiler not claiming they are
    # sound (R-062). Required — naming each one — when the artifact declares
    # unsound_primitives; ignored otherwise.
    acknowledge_unsound: list[str] = field(default_factory=list)


@dataclass
class OutputSpec:
    """Specification for a single contract continuation output."""
    satoshis: int
    state: dict

    @staticmethod
    def from_dict(d: dict) -> OutputSpec:
        return OutputSpec(satoshis=d['satoshis'], state=d['state'])


@dataclass
class TerminalOutput:
    """Specification for an exact output in a terminal method call."""
    script_hex: str
    satoshis: int


@dataclass
class CallOptions:
    """Options for calling a contract method."""
    satoshis: int = 0
    change_address: str = ''
    change_pub_key: str = ''
    new_state: dict | None = None
    outputs: list[OutputSpec | dict] | None = None
    additional_contract_inputs: list[Utxo | dict] | None = None
    additional_contract_input_args: list[list] | None = None
    terminal_outputs: list[TerminalOutput | dict] | None = None
    funding_utxos: list[Utxo] | None = None
    # Optional explicit override for data outputs emitted via
    # this.addDataOutput(...) in the method body. When None or empty, the
    # SDK resolves data outputs automatically by running the ANF interpreter.
    # Entries are {"script": hex, "satoshis": int}.
    data_outputs: list[dict] | None = None
    # Override the call tx's nLockTime field. None → SDK uses 0 (legacy
    # behavior, preserves existing contracts). Set for contracts that assert
    # extractLocktime(preimage) >= deadline (e.g. auction close/claim).
    # Threaded through both the non-terminal and terminal call-tx build sites.
    locktime: int | None = None
    # Override the nSequence written onto EVERY input of the call tx (issue
    # #131). None → 0xfffffffe when locktime is set and non-zero (so consensus
    # actually enforces nLockTime); otherwise 0xffffffff (final, legacy). Set
    # explicitly only for RBF or custom relative-locktime scenarios. Threaded
    # through the non-terminal and terminal call-tx build sites.
    sequence: int | None = None
    # Cap the number of P2PKH funding inputs added to a non-terminal call tx
    # (issue #133). Funding is chosen by smallest-sufficient, largest-first
    # selection (the same select_utxos strategy deploy uses). If covering the
    # outputs + fee would need more than this many inputs, the call raises
    # rather than silently sweeping the wallet. None → no cap.
    max_funding_inputs: int | None = None
    # A single plain P2PKH UTXO added to a terminal call tx purely to pay the
    # miner fee (issue #118). A true terminal method pays out the full contract
    # balance, so fee would be 0 and ARC rejects; the covenant asserts its
    # exact output set, so no change output can absorb a fee. The fee input is
    # added BEFORE the OP_PUSH_TX preimage is computed (so hashPrevouts covers
    # it) and is consumed entirely as fee -- no change output is created.
    # Signed with funding_signer or signer.
    fee_utxo: Utxo | None = None
    # Signer for the P2PKH funding (and terminal fee) inputs (issue #134). When
    # the funding/fee UTXOs are owned by a different key than the connected
    # method signer, set this so those inputs are signed by their real owner.
    # The method's own Sig args are still signed by the connected signer.
    # Defaults to the connected signer (zero behaviour change).
    funding_signer: 'Signer | None' = None


@dataclass
class PreparedCall:
    """Result of prepare_call() -- contains everything needed for external signing and finalize_call()."""
    # Public -- callers use these to coordinate external signing
    # 64-char hex -- hash256(preimage) = sha256(sha256(preimage)), the BIP-143
    # digest external signers ECDSA-sign DIRECTLY (no further hashing).
    sighash: str = ''
    preimage: str = ''          # hex -- full BIP-143 preimage
    op_push_tx_sig: str = ''    # hex -- OP_PUSH_TX DER sig (empty if not needed)
    tx_hex: str = ''            # hex -- built TX (P2PKH funding signed, primary input uses placeholder sigs)
    sig_indices: list[int] = field(default_factory=list)  # which user-visible arg positions need external Sig values

    # Internal -- consumed by finalize_call()
    method_name: str = ''
    resolved_args: list = field(default_factory=list)
    method_selector_hex: str = ''
    is_stateful: bool = False
    # True when the contract extends StatefulSmartContract (from artifact
    # parent_class), independent of mutable state fields. Gates the
    # issue-#42/#44 terminal sighash subscript trim.
    parent_stateful: bool = False
    is_terminal: bool = False
    needs_op_push_tx: bool = False
    method_needs_change: bool = False
    # Unlocking script is prefixed with _codePart (issue #100).
    method_uses_code_part: bool = False
    change_pkh_hex: str = ''
    change_amount: int = 0
    method_needs_new_amount: bool = False
    new_amount: int = 0
    preimage_index: int = -1
    contract_utxo: Utxo | None = None
    new_locking_script: str = ''
    new_satoshis: int = 0
    has_multi_output: bool = False
    contract_outputs: list[dict] = field(default_factory=list)
    code_sep_idx: int = -1  # adjusted OP_CODESEPARATOR byte offset, -1 if none
    # Pre-resolved intent-intrinsic witness hex (PUSHDATA-encoded
    # `_prevOutScript_*` followed by `_serialisedOutputs`, ABI order).
    # Empty when the method has no auto-injected intent params.
    intent_witness_hex: str = ''


# SdkValue is the union of types that can be passed as contract arguments
SdkValue = Union[int, bool, bytes, str]
