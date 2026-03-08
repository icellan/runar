"""RunarContract — main contract runtime wrapper."""

from __future__ import annotations
import hashlib
from runar.sdk.types import (
    RunarArtifact, Utxo, Transaction, TxOutput,
    DeployOptions, CallOptions, OutputSpec,
)
from runar.sdk.provider import Provider
from runar.sdk.signer import Signer
from runar.sdk.deployment import build_deploy_transaction, select_utxos, build_p2pkh_script
from runar.sdk.calling import build_call_transaction, insert_unlocking_script
from runar.sdk.state import (
    serialize_state, extract_state_from_script, find_last_op_return,
    encode_push_data,
)
from runar.sdk.oppushtx import compute_op_push_tx


class RunarContract:
    """Runtime wrapper for a compiled Runar contract.

    Handles deployment, method invocation, state tracking, and script construction.
    """

    def __init__(self, artifact: RunarArtifact, constructor_args: list):
        expected = len(artifact.abi.constructor_params)
        if len(constructor_args) != expected:
            raise ValueError(
                f"RunarContract: expected {expected} constructor args for "
                f"{artifact.contract_name}, got {len(constructor_args)}"
            )

        self.artifact = artifact
        self._constructor_args = list(constructor_args)
        self._state: dict = {}
        self._code_script = ''
        self._current_utxo: Utxo | None = None
        self._provider: Provider | None = None
        self._signer: Signer | None = None

        # Initialize state from constructor args for stateful contracts
        if artifact.state_fields:
            for field in artifact.state_fields:
                if field.index < len(constructor_args):
                    self._state[field.name] = constructor_args[field.index]

    def get_utxo(self):
        """Returns the current UTXO tracked by this contract, if any."""
        return self._current_utxo

    def connect(self, provider: Provider, signer: Signer) -> None:
        """Store provider and signer for later use."""
        self._provider = provider
        self._signer = signer

    def deploy(
        self,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: DeployOptions | None = None,
    ) -> tuple[str, Transaction]:
        """Deploy the contract. Returns (txid, transaction)."""
        provider = provider or self._provider
        signer = signer or self._signer
        if provider is None or signer is None:
            raise RuntimeError(
                "RunarContract.deploy: no provider/signer. Call connect() or pass them."
            )

        opts = options or DeployOptions()
        address = signer.get_address()
        change_address = opts.change_address or address
        locking_script = self.get_locking_script()

        fee_rate = provider.get_fee_rate()
        all_utxos = provider.get_utxos(address)
        if not all_utxos:
            raise RuntimeError(f"RunarContract.deploy: no UTXOs found for {address}")

        utxos = select_utxos(all_utxos, opts.satoshis, len(locking_script) // 2, fee_rate)
        change_script = build_p2pkh_script(change_address)

        tx_hex, input_count = build_deploy_transaction(
            locking_script, utxos, opts.satoshis, change_address, change_script, fee_rate,
        )

        # Sign all inputs
        signed_tx = tx_hex
        pub_key = signer.get_public_key()
        for i in range(input_count):
            utxo = utxos[i]
            sig = signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
            unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
            signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

        txid = provider.broadcast(signed_tx)

        self._current_utxo = Utxo(
            txid=txid, output_index=0, satoshis=opts.satoshis, script=locking_script,
        )

        try:
            tx = provider.get_transaction(txid)
        except Exception:
            tx = Transaction(
                txid=txid, version=1,
                outputs=[TxOutput(satoshis=opts.satoshis, script=locking_script)],
                raw=signed_tx,
            )

        return txid, tx

    def call(
        self,
        method_name: str,
        args: list | None = None,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: CallOptions | None = None,
    ) -> tuple[str, Transaction]:
        """Invoke a public method (spend the UTXO). Returns (txid, transaction)."""
        provider = provider or self._provider
        signer = signer or self._signer
        if provider is None or signer is None:
            raise RuntimeError(
                "RunarContract.call: no provider/signer. Call connect() or pass them."
            )

        args = args or []
        method = self._find_method(method_name)
        if method is None:
            raise ValueError(
                f"RunarContract.call: method '{method_name}' not found in {self.artifact.contract_name}"
            )

        is_stateful = bool(self.artifact.state_fields)

        # For stateful contracts, the compiler injects implicit params into every
        # public method's ABI (SigHashPreimage, and for state-mutating methods:
        # _changePKH and _changeAmount). The SDK auto-computes these.
        # Filter them out so users only pass their own args.
        method_needs_change = any(p.name == '_changePKH' for p in method.params)
        if is_stateful:
            user_params = [
                p for p in method.params
                if p.type != 'SigHashPreimage'
                and p.name != '_changePKH'
                and p.name != '_changeAmount'
            ]
        else:
            user_params = method.params

        if len(user_params) != len(args):
            raise ValueError(
                f"RunarContract.call: method '{method_name}' expects {len(user_params)} args, got {len(args)}"
            )
        if self._current_utxo is None:
            raise RuntimeError(
                "RunarContract.call: contract is not deployed. Call deploy() or from_txid() first."
            )

        address = signer.get_address()
        opts = options or CallOptions()
        change_address = opts.change_address or address

        # Detect Sig/PubKey/SigHashPreimage/ByteString params that need auto-compute (user passed None)
        resolved_args = list(args)
        sig_indices = []
        prevouts_indices: list[int] = []
        preimage_index = -1
        # Estimate input count for ByteString placeholder sizing
        estimated_inputs = 1 + (len(opts.additional_contract_inputs) if opts.additional_contract_inputs else 0) + 1
        for i, param in enumerate(user_params):
            if param.type == 'Sig' and args[i] is None:
                sig_indices.append(i)
                # 72-byte placeholder
                resolved_args[i] = '00' * 72
            elif param.type == 'PubKey' and args[i] is None:
                resolved_args[i] = signer.get_public_key()
            elif param.type == 'SigHashPreimage' and args[i] is None:
                preimage_index = i
                # Placeholder preimage (will be replaced after tx construction)
                resolved_args[i] = '00' * 181
            elif param.type == 'ByteString' and args[i] is None:
                prevouts_indices.append(i)
                # Placeholder: 36 bytes per estimated input
                resolved_args[i] = '00' * (36 * estimated_inputs)

        # If any param uses SigHashPreimage, or this is stateful,
        # the compiler injects an implicit _opPushTxSig.
        needs_op_push_tx = preimage_index >= 0 or is_stateful

        if needs_op_push_tx:
            # Prepend placeholder _opPushTxSig before user args
            unlocking_script = encode_push_data('00' * 72) + \
                self.build_unlocking_script(method_name, resolved_args)
        else:
            unlocking_script = self.build_unlocking_script(method_name, resolved_args)

        new_locking_script = ''
        new_satoshis = 0

        # Normalize additional contract inputs to Utxo objects
        extra_contract_utxos: list[Utxo] = []
        if opts.additional_contract_inputs:
            for item in opts.additional_contract_inputs:
                if isinstance(item, Utxo):
                    extra_contract_utxos.append(item)
                elif isinstance(item, dict):
                    extra_contract_utxos.append(Utxo(
                        txid=item['txid'],
                        output_index=item['output_index'],
                        satoshis=item['satoshis'],
                        script=item['script'],
                    ))
                else:
                    extra_contract_utxos.append(item)

        # Normalize outputs
        has_multi_output = opts.outputs is not None and len(opts.outputs) > 0

        # Build contract outputs: multi-output takes priority, then single
        contract_outputs: list[dict] | None = None

        if is_stateful and has_multi_output:
            # Multi-output: build a locking script for each output
            code_script = self._code_script or self._build_code_script()
            contract_outputs = []
            for out_spec in opts.outputs:
                if isinstance(out_spec, dict):
                    state_dict = out_spec['state']
                    sats = out_spec['satoshis']
                elif isinstance(out_spec, OutputSpec):
                    state_dict = out_spec.state
                    sats = out_spec.satoshis
                else:
                    raise ValueError(f"Invalid output spec: {out_spec}")
                state_hex = serialize_state(self.artifact.state_fields, state_dict)
                contract_outputs.append({
                    'script': code_script + '6a' + state_hex,
                    'satoshis': sats,
                })
        elif is_stateful:
            # For single-output continuations, the on-chain script uses the input amount
            # (extracted from the preimage). The SDK output must match.
            new_satoshis = opts.satoshis if opts.satoshis > 0 else self._current_utxo.satoshis
            if opts.new_state:
                for k, v in opts.new_state.items():
                    self._state[k] = v
            new_locking_script = self.get_locking_script()

        # Fetch fee rate and funding UTXOs for all contract types.
        # For stateful contracts with change output support, the change output
        # is verified by the on-chain script (hashOutputs check).
        fee_rate = provider.get_fee_rate()
        change_script = build_p2pkh_script(change_address)
        all_funding_utxos = provider.get_utxos(address)
        # Filter out the contract UTXO to avoid duplicate inputs
        additional_utxos: list[Utxo] = [
            u for u in all_funding_utxos
            if not (u.txid == self._current_utxo.txid and u.output_index == self._current_utxo.output_index)
        ]

        # Compute change PKH for stateful methods that need it
        change_pkh_hex = ''
        if is_stateful and method_needs_change:
            change_pub_key_hex = opts.change_pub_key or signer.get_public_key()
            pub_key_bytes = bytes.fromhex(change_pub_key_hex)
            hash160_bytes = hashlib.new(
                'ripemd160', hashlib.sha256(pub_key_bytes).digest()
            ).digest()
            change_pkh_hex = hash160_bytes.hex()

        # Resolve per-input args for additional contract inputs (same Sig/PubKey/ByteString handling)
        resolved_per_input_args: list[list] | None = None
        if opts.additional_contract_input_args:
            resolved_per_input_args = []
            for input_args in opts.additional_contract_input_args:
                resolved = list(input_args)
                for i, param in enumerate(user_params):
                    if i >= len(resolved):
                        break
                    if param.type == 'Sig' and resolved[i] is None:
                        resolved[i] = '00' * 72
                    elif param.type == 'PubKey' and resolved[i] is None:
                        resolved[i] = signer.get_public_key()
                    elif param.type == 'ByteString' and resolved[i] is None:
                        resolved[i] = '00' * (36 * estimated_inputs)
                resolved_per_input_args.append(resolved)

        # Build placeholder unlocking scripts for merge inputs
        extra_unlock_placeholders = []
        for i in range(len(extra_contract_utxos)):
            args_for_placeholder = resolved_per_input_args[i] if resolved_per_input_args and i < len(resolved_per_input_args) else resolved_args
            extra_unlock_placeholders.append(
                encode_push_data('00' * 72) + self.build_unlocking_script(method_name, args_for_placeholder)
            )

        tx_hex, input_count, change_amount = build_call_transaction(
            self._current_utxo, unlocking_script, new_locking_script,
            new_satoshis, change_address, change_script,
            additional_utxos if additional_utxos else None, fee_rate,
            contract_outputs=contract_outputs,
            additional_contract_inputs=[
                {'utxo': u, 'unlocking_script': extra_unlock_placeholders[i]}
                for i, u in enumerate(extra_contract_utxos)
            ] if extra_contract_utxos else None,
        )

        # Sign P2PKH funding inputs (after contract inputs)
        signed_tx = tx_hex
        pub_key = signer.get_public_key()
        p2pkh_start_idx = 1 + len(extra_contract_utxos)
        for i in range(p2pkh_start_idx, input_count):
            utxo_idx = i - p2pkh_start_idx
            if utxo_idx < len(additional_utxos):
                utxo = additional_utxos[utxo_idx]
                sig = signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
                unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
                signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

        # For stateful contracts, build the OP_PUSH_TX unlocking script:
        #   <opPushTxSig> <user_args> <txPreimage> <methodSelector>
        if is_stateful:
            method_selector_hex = ''
            public_methods = self._get_public_methods()
            if len(public_methods) > 1:
                for mi, m in enumerate(public_methods):
                    if m.name == method_name:
                        method_selector_hex = _encode_script_number(mi)
                        break

            def _build_stateful_unlock(tx: str, input_idx: int, subscript: str, sats: int, args_override: list | None = None, tx_change_amount: int = 0, pi: list[int] | None = None) -> str:
                op_sig, preimage = compute_op_push_tx(tx, input_idx, subscript, sats)
                base_args = args_override if args_override is not None else resolved_args
                input_args = list(base_args)
                for idx in sig_indices:
                    input_args[idx] = signer.sign(tx, input_idx, subscript, sats)
                # Resolve ByteString prevouts
                if pi:
                    all_prevouts_hex = _extract_all_prevouts(tx)
                    for idx in pi:
                        input_args[idx] = all_prevouts_hex
                args_hex = ''
                for arg in input_args:
                    args_hex += _encode_arg(arg)
                # Append change params (PKH + amount) for methods that need them
                change_hex = ''
                if method_needs_change and change_pkh_hex:
                    change_hex = encode_push_data(change_pkh_hex) + _encode_script_number(tx_change_amount)
                return (
                    encode_push_data(op_sig) +
                    args_hex +
                    change_hex +
                    encode_push_data(preimage) +
                    method_selector_hex
                )

            # First pass: build unlocking scripts with current tx layout
            input0_unlock = _build_stateful_unlock(
                signed_tx, 0, self._current_utxo.script, self._current_utxo.satoshis,
                tx_change_amount=change_amount,
                pi=prevouts_indices,
            )
            extra_unlocks: list[str] = []
            for i, mu in enumerate(extra_contract_utxos):
                extra_args = resolved_per_input_args[i] if resolved_per_input_args and i < len(resolved_per_input_args) else None
                extra_unlocks.append(_build_stateful_unlock(
                    signed_tx, i + 1, mu.script, mu.satoshis, extra_args,
                    tx_change_amount=change_amount,
                    pi=prevouts_indices,
                ))

            # Rebuild TX with real unlocking scripts (sizes may differ from placeholders)
            tx_hex, input_count, change_amount = build_call_transaction(
                self._current_utxo, input0_unlock, new_locking_script,
                new_satoshis, change_address, change_script,
                additional_utxos if additional_utxos else None, fee_rate,
                contract_outputs=contract_outputs,
                additional_contract_inputs=[
                    {'utxo': u, 'unlocking_script': extra_unlocks[i]}
                    for i, u in enumerate(extra_contract_utxos)
                ] if extra_contract_utxos else None,
            )
            signed_tx = tx_hex

            # Re-sign P2PKH funding inputs after rebuild
            p2pkh_start_idx = 1 + len(extra_contract_utxos)
            for i in range(p2pkh_start_idx, input_count):
                utxo_idx = i - p2pkh_start_idx
                if utxo_idx < len(additional_utxos):
                    utxo = additional_utxos[utxo_idx]
                    sig = signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
                    unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
                    signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

            # Second pass: recompute with final tx (preimage changes with unlock size)
            final_input0_unlock = _build_stateful_unlock(
                signed_tx, 0, self._current_utxo.script, self._current_utxo.satoshis,
                tx_change_amount=change_amount,
                pi=prevouts_indices,
            )
            signed_tx = insert_unlocking_script(signed_tx, 0, final_input0_unlock)

            for i, mu in enumerate(extra_contract_utxos):
                extra_args = resolved_per_input_args[i] if resolved_per_input_args and i < len(resolved_per_input_args) else None
                final_merge_unlock = _build_stateful_unlock(
                    signed_tx, i + 1, mu.script, mu.satoshis, extra_args,
                    tx_change_amount=change_amount,
                    pi=prevouts_indices,
                )
                signed_tx = insert_unlocking_script(signed_tx, i + 1, final_merge_unlock)

            # Re-sign P2PKH funding inputs after second pass
            for i in range(p2pkh_start_idx, input_count):
                utxo_idx = i - p2pkh_start_idx
                if utxo_idx < len(additional_utxos):
                    utxo = additional_utxos[utxo_idx]
                    sig = signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
                    unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
                    signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

        elif needs_op_push_tx or sig_indices:
            # Stateless with SigHashPreimage or Sig params: auto-compute
            op_push_tx_sig_hex = None
            if needs_op_push_tx:
                sig_hex, preimage_hex = compute_op_push_tx(
                    signed_tx, 0, self._current_utxo.script, self._current_utxo.satoshis,
                )
                op_push_tx_sig_hex = sig_hex
                resolved_args[preimage_index] = preimage_hex

            for idx in sig_indices:
                resolved_args[idx] = signer.sign(
                    signed_tx, 0, self._current_utxo.script, self._current_utxo.satoshis,
                )

            real_unlocking_script = self.build_unlocking_script(method_name, resolved_args)
            if op_push_tx_sig_hex is not None:
                real_unlocking_script = encode_push_data(op_push_tx_sig_hex) + real_unlocking_script

                tmp_tx = insert_unlocking_script(signed_tx, 0, real_unlocking_script)
                final_sig, final_preimage = compute_op_push_tx(
                    tmp_tx, 0, self._current_utxo.script, self._current_utxo.satoshis,
                )
                resolved_args[preimage_index] = final_preimage
                if sig_indices:
                    for idx in sig_indices:
                        resolved_args[idx] = signer.sign(
                            tmp_tx, 0, self._current_utxo.script, self._current_utxo.satoshis,
                        )
                real_unlocking_script = encode_push_data(final_sig) + \
                    self.build_unlocking_script(method_name, resolved_args)
            signed_tx = insert_unlocking_script(signed_tx, 0, real_unlocking_script)

        txid = provider.broadcast(signed_tx)

        # Update tracked UTXO
        if is_stateful and has_multi_output and contract_outputs:
            # Multi-output: track the first continuation output
            self._current_utxo = Utxo(
                txid=txid, output_index=0,
                satoshis=contract_outputs[0]['satoshis'],
                script=contract_outputs[0]['script'],
            )
        elif is_stateful and new_locking_script:
            self._current_utxo = Utxo(
                txid=txid, output_index=0, satoshis=new_satoshis, script=new_locking_script,
            )
        else:
            self._current_utxo = None

        try:
            tx = provider.get_transaction(txid)
        except Exception:
            tx = Transaction(txid=txid, version=1, raw=signed_tx)

        return txid, tx

    @staticmethod
    def from_txid(
        artifact: RunarArtifact,
        txid: str,
        output_index: int,
        provider: Provider,
    ) -> RunarContract:
        """Reconnect to an existing deployed contract."""
        tx = provider.get_transaction(txid)
        if output_index >= len(tx.outputs):
            raise ValueError(
                f"RunarContract.from_txid: output index {output_index} out of range "
                f"(tx has {len(tx.outputs)} outputs)"
            )

        output = tx.outputs[output_index]
        dummy_args = [0] * len(artifact.abi.constructor_params)
        contract = RunarContract(artifact, dummy_args)

        if artifact.state_fields:
            last_op_return = find_last_op_return(output.script)
            if last_op_return != -1:
                contract._code_script = output.script[:last_op_return]
            else:
                contract._code_script = output.script
        else:
            contract._code_script = output.script

        contract._current_utxo = Utxo(
            txid=txid, output_index=output_index,
            satoshis=output.satoshis, script=output.script,
        )

        if artifact.state_fields:
            state = extract_state_from_script(artifact, output.script)
            if state is not None:
                contract._state = state

        return contract

    def get_locking_script(self) -> str:
        """Return the full locking script hex."""
        script = self._code_script or self._build_code_script()

        if self.artifact.state_fields:
            state_hex = serialize_state(self.artifact.state_fields, self._state)
            if state_hex:
                script += '6a'  # OP_RETURN
                script += state_hex

        return script

    def build_unlocking_script(self, method_name: str, args: list) -> str:
        """Build the unlocking script for a method call."""
        script = ''
        for arg in args:
            script += _encode_arg(arg)

        public_methods = self._get_public_methods()
        if len(public_methods) > 1:
            method_index = -1
            for i, m in enumerate(public_methods):
                if m.name == method_name:
                    method_index = i
                    break
            if method_index < 0:
                raise ValueError(
                    f"build_unlocking_script: public method '{method_name}' not found"
                )
            script += _encode_script_number(method_index)

        return script

    def get_state(self) -> dict:
        """Return a copy of the current state."""
        return dict(self._state)

    def set_state(self, new_state: dict) -> None:
        """Update state values directly."""
        self._state.update(new_state)

    # -- Private helpers --

    def _build_code_script(self) -> str:
        script = self.artifact.script

        if self.artifact.constructor_slots:
            slots = sorted(self.artifact.constructor_slots, key=lambda s: s.byte_offset, reverse=True)
            for slot in slots:
                encoded = _encode_arg(self._constructor_args[slot.param_index])
                hex_offset = slot.byte_offset * 2
                script = script[:hex_offset] + encoded + script[hex_offset + 2:]
        elif not self.artifact.state_fields:
            # Backward compatibility: old stateless artifacts without constructorSlots.
            # For stateful contracts, constructor args initialize the state section
            # (after OP_RETURN), not the code portion.
            for arg in self._constructor_args:
                script += _encode_arg(arg)

        return script

    def _find_method(self, name: str):
        for m in self.artifact.abi.methods:
            if m.name == name and m.is_public:
                return m
        return None

    def _get_public_methods(self):
        return [m for m in self.artifact.abi.methods if m.is_public]


# ---------------------------------------------------------------------------
# Argument encoding
# ---------------------------------------------------------------------------

def _encode_arg(value) -> str:
    if isinstance(value, bool):
        return '51' if value else '00'
    if isinstance(value, int):
        return _encode_script_number(value)
    if isinstance(value, str):
        return encode_push_data(value)
    if isinstance(value, bytes):
        return encode_push_data(value.hex())
    return encode_push_data(str(value))


def _extract_all_prevouts(tx_hex: str) -> str:
    """Extract all input outpoints (txid+vout, 36 bytes each) from a raw tx hex."""
    raw = bytes.fromhex(tx_hex)
    offset = 4  # skip version
    input_count, varint_size = _read_varint(raw, offset)
    offset += varint_size
    prevouts = ''
    for _ in range(input_count):
        prevouts += raw[offset:offset + 36].hex()
        offset += 36  # txid + vout
        script_len, vs = _read_varint(raw, offset)
        offset += vs + script_len + 4  # scriptSig + sequence
    return prevouts


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a Bitcoin varint. Returns (value, bytes_consumed)."""
    first = data[offset]
    if first < 0xFD:
        return first, 1
    elif first == 0xFD:
        return int.from_bytes(data[offset + 1:offset + 3], 'little'), 3
    elif first == 0xFE:
        return int.from_bytes(data[offset + 1:offset + 5], 'little'), 5
    else:
        return int.from_bytes(data[offset + 1:offset + 9], 'little'), 9


def _encode_script_number(n: int) -> str:
    """Encode an integer as a Bitcoin Script opcode or push data."""
    if n == 0:
        return '00'  # OP_0
    if 1 <= n <= 16:
        return f'{0x50 + n:02x}'
    if n == -1:
        return '4f'  # OP_1NEGATE

    negative = n < 0
    abs_val = abs(n)

    result_bytes = []
    while abs_val > 0:
        result_bytes.append(abs_val & 0xFF)
        abs_val >>= 8

    if result_bytes[-1] & 0x80:
        result_bytes.append(0x80 if negative else 0x00)
    elif negative:
        result_bytes[-1] |= 0x80

    data_hex = bytes(result_bytes).hex()
    return encode_push_data(data_hex)
