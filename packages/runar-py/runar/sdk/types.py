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
class Transaction:
    """A parsed Bitcoin transaction."""
    txid: str
    version: int = 1
    inputs: list[TxInput] = field(default_factory=list)
    outputs: list[TxOutput] = field(default_factory=list)
    locktime: int = 0
    raw: str = ''


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
            )
            for m in abi_raw.get('methods', [])
        ]
        state_fields = [
            StateField(name=sf['name'], type=sf['type'], index=sf['index'])
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
class CallOptions:
    """Options for calling a contract method."""
    satoshis: int = 0
    change_address: str = ''
    change_pub_key: str = ''
    new_state: dict | None = None
    outputs: list[OutputSpec | dict] | None = None
    additional_contract_inputs: list[Utxo | dict] | None = None
    additional_contract_input_args: list[list] | None = None


# SdkValue is the union of types that can be passed as contract arguments
SdkValue = Union[int, bool, bytes, str]
