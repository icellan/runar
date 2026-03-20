"""Runar SDK types for deploying and interacting with compiled contracts on BSV."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Union


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


@dataclass
class AbiMethod:
    """A contract method descriptor."""
    name: str
    params: list[AbiParam] = field(default_factory=list)
    is_public: bool = True
    is_terminal: bool | None = None


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


@dataclass
class ConstructorSlot:
    """Where a constructor placeholder resides in the compiled script."""
    param_index: int
    byte_offset: int


@dataclass
class RunarArtifact:
    """Compiled output of a Runar compiler."""
    version: str = ''
    compiler_version: str = ''
    contract_name: str = ''
    abi: Abi = field(default_factory=Abi)
    script: str = ''
    asm: str = ''
    state_fields: list[StateField] = field(default_factory=list)
    constructor_slots: list[ConstructorSlot] = field(default_factory=list)
    build_timestamp: str = ''
    code_separator_index: int | None = None
    code_separator_indices: list[int] | None = None
    anf: dict | None = None

    @staticmethod
    def from_dict(d: dict) -> RunarArtifact:
        """Load an artifact from a JSON-parsed dict."""
        abi_raw = d.get('abi', {})
        ctor_params = [
            AbiParam(name=p['name'], type=p['type'])
            for p in abi_raw.get('constructor', {}).get('params', [])
        ]
        methods = [
            AbiMethod(
                name=m['name'],
                params=[AbiParam(name=p['name'], type=p['type']) for p in m.get('params', [])],
                is_public=m.get('isPublic', True),
                is_terminal=m.get('isTerminal'),
            )
            for m in abi_raw.get('methods', [])
        ]
        state_fields = [
            StateField(
                name=sf['name'], type=sf['type'], index=sf['index'],
                initial_value=sf.get('initialValue'),
            )
            for sf in d.get('stateFields', [])
        ]
        ctor_slots = [
            ConstructorSlot(param_index=cs['paramIndex'], byte_offset=cs['byteOffset'])
            for cs in d.get('constructorSlots', [])
        ]
        return RunarArtifact(
            version=d.get('version', ''),
            compiler_version=d.get('compilerVersion', ''),
            contract_name=d.get('contractName', ''),
            abi=Abi(constructor_params=ctor_params, methods=methods),
            script=d.get('script', ''),
            asm=d.get('asm', ''),
            state_fields=state_fields,
            constructor_slots=ctor_slots,
            build_timestamp=d.get('buildTimestamp', ''),
            code_separator_index=d.get('codeSeparatorIndex'),
            code_separator_indices=d.get('codeSeparatorIndices'),
            anf=d.get('anf'),
        )


@dataclass
class DeployOptions:
    """Options for deploying a contract."""
    satoshis: int = 10000
    change_address: str = ''


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


@dataclass
class PreparedCall:
    """Result of prepare_call() -- contains everything needed for external signing and finalize_call()."""
    # Public -- callers use these to coordinate external signing
    sighash: str = ''           # 64-char hex -- BIP-143 hash external signers sign
    preimage: str = ''          # hex -- full BIP-143 preimage
    op_push_tx_sig: str = ''    # hex -- OP_PUSH_TX DER sig (empty if not needed)
    tx_hex: str = ''            # hex -- built TX (P2PKH funding signed, primary input uses placeholder sigs)
    sig_indices: list[int] = field(default_factory=list)  # which user-visible arg positions need external Sig values

    # Internal -- consumed by finalize_call()
    method_name: str = ''
    resolved_args: list = field(default_factory=list)
    method_selector_hex: str = ''
    is_stateful: bool = False
    is_terminal: bool = False
    needs_op_push_tx: bool = False
    method_needs_change: bool = False
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


# SdkValue is the union of types that can be passed as contract arguments
SdkValue = Union[int, bool, bytes, str]
