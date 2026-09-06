"""RunarContract — main contract runtime wrapper."""

from __future__ import annotations
import hashlib
import warnings
from runar.sdk.types import (
    RunarArtifact, Utxo, TransactionData, TxOutput,
    DeployOptions, CallOptions, OutputSpec, TerminalOutput, PreparedCall,
)
from runar.sdk.provider import Provider
from runar.sdk.signer import Signer
from runar.sdk.errors import assert_script_hex_under_limit, WitnessValueMissingError
from runar.sdk.input_limits import MAX_SCRIPT_BYTES
from runar.sdk.deployment import (
    build_deploy_transaction, select_utxos, build_p2pkh_script,
    _to_le32, _to_le64, _encode_varint, _reverse_hex,
)
from runar.sdk.calling import (
    build_call_transaction, insert_unlocking_script, resolve_input_sequence,
)
from runar.sdk.script_utils import restore_constructor_args
from runar.sdk.state import (
    serialize_state, extract_state_from_script, find_last_op_return,
    encode_push_data,
    _parse_fixed_array_dims, _flatten_nested, _regroup_nested,
)
from runar.sdk.oppushtx import compute_op_push_tx
from runar.sdk.anf_interpreter import compute_new_state, compute_new_state_and_data_outputs
from runar.sdk.ordinals import (
    Inscription, build_inscription_envelope, parse_inscription_envelope,
)


class _EmptySig:
    """Producer-side marker type (issue #106) for the deliberately-empty branch
    of an OR-CHECKSIG method — ``checkSig(sigA, pkA) || checkSig(sigB, pkB)``,
    where ``||`` lowers to the non-lazy ``OP_BOOLOR`` so BOTH ``OP_CHECKSIG``s
    run. Only the matching branch supplies a real signature; the failing branch
    MUST push an empty signature (OP_0) or BIP146 NULLFAIL rejects the spend.

    Pass :data:`EMPTY_SIG` as the call arg for the non-matching ``Sig`` slot: the
    SDK pushes OP_0 for it and never signs it, distinct from ``None`` (auto-sign)
    and an explicit hex-bytes value. ``call('execute', [None, EMPTY_SIG])`` signs
    only slot 0.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "EMPTY_SIG"


#: Singleton marker for the empty OR-CHECKSIG branch (issue #106).
EMPTY_SIG = _EmptySig()


def is_empty_sig(value: object) -> bool:
    """Type guard: is this call arg the :data:`EMPTY_SIG` marker (issue #106)?

    Uses ``isinstance`` so identity holds even if the module is imported twice.
    """
    return isinstance(value, _EmptySig)


def _is_likely_or_checksig(artifact) -> bool:
    """True for OR-CHECKSIG (OP_BOOLOR+OP_CHECKSIG), false for OP_CHECKMULTISIG."""
    asm = (getattr(artifact, 'asm', None) or '').upper()
    if 'OP_CHECKMULTISIG' in asm:
        return False
    if 'OP_BOOLOR' in asm and 'OP_CHECKSIG' in asm:
        return True
    # NEW-014: `||` no longer lowers to OP_BOOLOR — it lowers to real
    # OP_IF / OP_ELSE / OP_ENDIF control flow. The NULLFAIL hazard SURVIVES
    # that change: when the FIRST branch fails, its OP_CHECKSIG has already
    # run with a non-empty signature, which is exactly what BIP146 rejects.
    # Short-circuiting only removes the hazard when the first branch succeeds,
    # so this warning must still fire for the branch-shaped form.
    if 'OP_IF' in asm and 'OP_CHECKSIG' in asm:
        return True
    script = (getattr(artifact, 'script', None) or getattr(artifact, 'script_hex', None) or '').lower()
    if not asm and ('ae' in script or 'af' in script):
        return False
    return False


#: The well-known ByteString parameter the SDK fills in with the transaction's
#: concatenated outpoints (36 bytes per input) once the input list has
#: converged. It is the ONLY ByteString slot for which a ``None`` call arg is a
#: request rather than a mistake.
AUTO_PREVOUTS_PARAM_NAME = 'allPrevouts'


def _is_auto_prevouts_param(param) -> bool:
    """Is a ``None`` arg for ``param`` the SDK's auto-compute sentinel?

    Mirrors the Zig SDK's name gate (``sdk_contract.zig``): ``None`` for any
    other ByteString param is a caller error, not a stub request.
    """
    return param.name == AUTO_PREVOUTS_PARAM_NAME


def _nil_non_sig_arg_error(where: str, param, index: int) -> ValueError:
    """Build the build-time error for a ``None`` arg with no auto-resolution rule.

    Silently substituting the allPrevouts stub here produces a transaction that
    broadcasts and then fails at script execution with an opaque error; failing
    at build time names the offending parameter instead.
    """
    return ValueError(
        f'{where}: None arg for {param.type} param {param.name!r} (index {index}): '
        'None is only auto-resolved for Sig (auto-signed), PubKey (taken from the '
        'signer), SigHashPreimage, and the '
        f'{AUTO_PREVOUTS_PARAM_NAME!r} outpoint slot. Pass an explicit value '
        "(hex string, or '' for an empty ByteString)"
    )


def _compute_bip143_sighash(preimage_hex: str) -> str:
    """Compute the BIP-143 sighash digest -- ``hash256(preimage)``, i.e.
    ``sha256(sha256(preimage))`` -- that is ACTUALLY ECDSA-signed by
    ``OP_CHECKSIG`` on-chain. Returns ``''`` for an empty preimage.

    Deep-review finding C19: ``PreparedCall.sighash`` previously stored only
    ``sha256(preimage)`` (a SINGLE hash). The default ``call()`` path never
    reads that field -- it re-derives the digest inside ``LocalSigner.sign``
    (``_bip143_sighash`` -> ``_sha256d`` -> ``ecdsa_sign``) -- so the bug stayed
    invisible there. But the documented multi-signer path hands
    ``PreparedCall.sighash`` to an EXTERNAL signer (a BRC-100-style
    ``WalletSigner.sign_hash(digest)`` wallet / hardware device) that
    ECDSA-signs those 32 bytes DIRECTLY with no further hashing. Handed the
    single-hashed value, such a signer signs the wrong message and the node's
    real ``OP_CHECKSIG`` rejects the spend. Mirrors ``computeBip143Sighash`` in
    ``packages/runar-sdk/src/contract.ts``.
    """
    if not preimage_hex:
        return ''
    preimage_bytes = bytes.fromhex(preimage_hex)
    return hashlib.sha256(hashlib.sha256(preimage_bytes).digest()).hexdigest()


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
        self._inscription: Inscription | None = None
        self._current_utxo: Utxo | None = None
        self._provider: Provider | None = None
        self._signer: Signer | None = None
        # Witness values for intent-covenant intrinsic auto-injected params.
        # `_prevOutScript_<i>` values are stored per-input-index in
        # `_prev_out_scripts`; `_serialisedOutputs` is stored in
        # `_serialised_outputs`. Both are lowercase hex strings (normalized
        # in the setters). Read by the call-builder when assembling the
        # unlocking script for methods that use extractPrevOutputScript /
        # requireOutputP2PKH.
        self._prev_out_scripts: dict[int, str] = {}
        self._serialised_outputs: str | None = None

        # Initialize state from constructor args for stateful contracts.
        # Properties with initial_value use their default; others are matched
        # to constructor args by name lookup in the ABI constructor params.
        if artifact.state_fields:
            for field in artifact.state_fields:
                if field.initial_value is not None:
                    # Property has a compile-time default value.
                    # Revive BigInt strings ("0n") that occur when artifacts
                    # are loaded via plain JSON import (without a reviver).
                    fa = getattr(field, 'fixed_array', None)
                    if fa:
                        leaf_type = _unwrap_fixed_array_leaf_type(field.type)
                        self._state[field.name] = _deep_revive(
                            field.initial_value, leaf_type,
                        )
                    else:
                        self._state[field.name] = _revive_json_value(
                            field.initial_value, field.type,
                        )
                else:
                    # Match by name to constructor params
                    param_idx = next(
                        (i for i, p in enumerate(artifact.abi.constructor_params)
                         if p.name == field.name),
                        -1,
                    )
                    if 0 <= param_idx < len(constructor_args):
                        self._state[field.name] = constructor_args[param_idx]
                    elif field.index < len(constructor_args):
                        # Fallback: use declaration index for backward compat
                        self._state[field.name] = constructor_args[field.index]

    def get_utxo(self):
        """Returns the current UTXO tracked by this contract, if any."""
        return self._current_utxo

    def connect(self, provider: Provider, signer: Signer) -> None:
        """Store provider and signer for later use."""
        self._provider = provider
        self._signer = signer

    # ------------------------------------------------------------------
    # Intent-intrinsic witness values
    # ------------------------------------------------------------------

    def set_prev_out_script(self, input_index: int, value) -> None:
        """Supply the prev-output locking-script witness for input ``input_index``.

        Required for methods that call ``extractPrevOutputScript(input_index)``,
        which the compiler lowers into an auto-injected
        ``_prevOutScript_<input_index>`` ABI param.

        Args:
            input_index: literal input index passed to extractPrevOutputScript.
            value:       hex string (with or without 0x prefix) or raw bytes.
        """
        self._prev_out_scripts[input_index] = _normalize_witness_bytes(value)

    def set_serialised_outputs(self, value) -> None:
        """Supply the serialised-outputs witness for the current call.

        Required for methods that call ``requireOutputP2PKH(...)``, which the
        compiler lowers into an auto-injected ``_serialisedOutputs`` ABI param.

        Args:
            value: hex string (with or without 0x prefix) or raw bytes.
        """
        self._serialised_outputs = _normalize_witness_bytes(value)

    def _build_intent_witness_hex(self, method) -> str:
        """Build the trailing witness-hex for the auto-injected intent-intrinsic
        params of ``method``, in ABI order (``_prevOutScript_*`` first, then
        ``_serialisedOutputs``). Each value is pushed via PUSHDATA so the
        on-chain method body's ``load_param`` lifts the exact bytes the caller
        set.

        Raises:
            WitnessValueMissingError: any auto-injected param the caller hasn't
                supplied via :meth:`set_prev_out_script` /
                :meth:`set_serialised_outputs`.
        """
        out = ''
        for p in method.params:
            if p.name.startswith('_prevOutScript_'):
                idx_str = p.name[len('_prevOutScript_'):]
                try:
                    idx = int(idx_str)
                except ValueError as exc:
                    raise ValueError(
                        f"malformed auto-injected param name '{p.name}'"
                    ) from exc
                val = self._prev_out_scripts.get(idx)
                if val is None:
                    raise WitnessValueMissingError(
                        param_name=p.name,
                        method_name=method.name,
                        contract_name=self.artifact.contract_name,
                    )
                out += encode_push_data(val)
            elif p.name == '_serialisedOutputs':
                if self._serialised_outputs is None:
                    raise WitnessValueMissingError(
                        param_name=p.name,
                        method_name=method.name,
                        contract_name=self.artifact.contract_name,
                    )
                out += encode_push_data(self._serialised_outputs)
        return out

    def deploy(
        self,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: DeployOptions | None = None,
    ) -> tuple[str, TransactionData]:
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

        # DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
        assert_script_hex_under_limit(
            locking_script, MAX_SCRIPT_BYTES,
            f"{self.artifact.contract_name}.deploy",
        )

        fee_rate = provider.get_fee_rate()
        all_utxos = provider.get_utxos(address)
        if not all_utxos:
            raise RuntimeError(f"RunarContract.deploy: no UTXOs found for {address}")

        utxos = select_utxos(all_utxos, opts.satoshis, len(locking_script) // 2, fee_rate)
        change_script = build_p2pkh_script(change_address)

        tx_hex, input_count = build_deploy_transaction(
            locking_script, utxos, opts.satoshis, change_address, change_script, fee_rate,
        )

        # Sign all inputs. Funding inputs are signed by funding_signer when set
        # (issue #134): the deploy signer may not own the funding coins.
        # Defaults to the connected signer (zero behaviour change).
        funding_signer = opts.funding_signer or signer
        signed_tx = tx_hex
        pub_key = funding_signer.get_public_key()
        for i in range(input_count):
            utxo = utxos[i]
            sig = funding_signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
            unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
            signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

        txid = provider.broadcast(signed_tx)

        self._current_utxo = Utxo(
            txid=txid, output_index=0, satoshis=opts.satoshis, script=locking_script,
        )

        try:
            tx = provider.get_transaction(txid)
        except Exception:
            tx = TransactionData(
                txid=txid, version=1,
                outputs=[TxOutput(satoshis=opts.satoshis, script=locking_script)],
                raw=signed_tx,
            )

        return txid, tx

    def deploy_with_wallet(
        self,
        satoshis: int = 1,
        description: str = '',
    ) -> tuple[str, int]:
        """Deploy the contract using a BRC-100 wallet.

        The wallet owns the coins and creates the transaction itself via
        ``create_action()``.  Requires the contract to be connected to a
        :class:`WalletProvider` (via ``connect()``).

        Args:
            satoshis: Satoshis to lock in the contract output (default: 1).
            description: Human-readable description for the wallet action.

        Returns:
            (txid, output_index) tuple.
        """
        from runar.sdk.wallet import WalletProvider

        if not isinstance(self._provider, WalletProvider):
            raise RuntimeError(
                'deploy_with_wallet requires a connected WalletProvider. '
                'Call connect(wallet_provider, signer) first.'
            )

        wallet_provider: WalletProvider = self._provider
        wallet = wallet_provider.wallet
        basket = wallet_provider.basket

        locking_script = self.get_locking_script()
        desc = description or 'Runar contract deployment'

        # DoS-bound: reject pathological scripts BEFORE involving the wallet.
        assert_script_hex_under_limit(
            locking_script, MAX_SCRIPT_BYTES,
            f"{self.artifact.contract_name}.deploy_with_wallet",
        )

        result = wallet.create_action(
            description=desc,
            outputs=[{
                'locking_script': locking_script,
                'satoshis': satoshis,
                'description': f'Deploy {self.artifact.contract_name}',
                'basket': basket,
            }],
        )

        txid = result.get('txid', '')
        output_index = 0

        # If the wallet returned a raw tx, try to find the exact output index
        raw_tx = result.get('raw_tx', '')
        actual_satoshis = satoshis
        if raw_tx:
            try:
                from runar.sdk.wallet import _parse_raw_tx_to_data
                tx_data = _parse_raw_tx_to_data(txid, raw_tx)
                for i, out in enumerate(tx_data.outputs):
                    if out.script == locking_script:
                        output_index = i
                        actual_satoshis = out.satoshis
                        break
                # Cache for future EF lookups
                if txid:
                    wallet_provider.cache_tx(txid, raw_tx)
            except Exception:
                pass

        # Track the deployed UTXO
        self._current_utxo = Utxo(
            txid=txid,
            output_index=output_index,
            satoshis=actual_satoshis,
            script=locking_script,
        )

        return txid, output_index

    def call(
        self,
        method_name: str,
        args: list | None = None,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: CallOptions | None = None,
    ) -> tuple[str, TransactionData]:
        """Invoke a public method (spend the UTXO). Returns (txid, transaction)."""
        provider = provider or self._provider
        signer = signer or self._signer
        if provider is None or signer is None:
            raise RuntimeError(
                "RunarContract.call: no provider/signer. Call connect() or pass them."
            )

        prepared = self.prepare_call(method_name, args, provider, signer, options)
        signatures: dict[int, str] = {}
        for idx in prepared.sig_indices:
            # Stateful contracts: checkPreimage is auto-injected at method entry,
            # so the user checkSig executes AFTER the OP_CODESEPARATOR — the
            # sighash must be computed over the subscript trimmed at that
            # separator. Issue #42: the trim must land at the *real* on-chain
            # codesep byte position, which _get_code_sep_index now recovers via
            # _find_codesep_offsets.
            # Stateless contracts: the user controls statement order and may
            # place checkSig BEFORE the codesep (e.g. CovenantVault) — those must
            # use the FULL script, so the trim stays gated on the parent class.
            # A stateful contract with ZERO mutable fields (empty state_fields)
            # still injects checkPreimage at entry, so the trim is gated on
            # parent_stateful (artifact parent_class), NOT is_stateful (issue #44).
            subscript = prepared.contract_utxo.script
            if prepared.parent_stateful and prepared.code_sep_idx >= 0:
                trim_pos = (prepared.code_sep_idx + 1) * 2
                if trim_pos <= len(subscript):
                    subscript = subscript[trim_pos:]
            signatures[idx] = signer.sign(
                prepared.tx_hex, 0,
                subscript,
                prepared.contract_utxo.satoshis,
            )
        return self.finalize_call(prepared, signatures, provider)

    # -------------------------------------------------------------------
    # prepare_call / finalize_call -- multi-signer support
    # -------------------------------------------------------------------

    def prepare_call(
        self,
        method_name: str,
        args: list | None = None,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: CallOptions | None = None,
    ) -> PreparedCall:
        """Build the transaction for a method call without signing the primary
        contract input's Sig params.  Returns a PreparedCall containing the
        BIP-143 sighash that external signers need, plus opaque internals for
        finalize_call().

        P2PKH funding inputs and additional contract inputs ARE signed with
        the connected signer.  Only the primary contract input's Sig params
        are left as 72-byte placeholders.
        """
        provider = provider or self._provider
        signer = signer or self._signer
        if provider is None or signer is None:
            raise RuntimeError(
                "RunarContract.prepare_call: no provider/signer. Call connect() or pass them."
            )

        # Funding (and terminal fee) inputs are signed by funding_signer when
        # set (issue #134). The method's own Sig args stay with the connected
        # signer. Defaults to the connected signer (zero behaviour change).
        funding_signer = (options.funding_signer if options and options.funding_signer else signer)

        args = args or []
        method = self._find_method(method_name)
        if method is None:
            raise ValueError(
                f"RunarContract.prepare_call: method '{method_name}' not found in {self.artifact.contract_name}"
            )

        is_stateful = bool(self.artifact.state_fields)
        # parent_stateful gates ONLY the issue-#42/#44 terminal sighash subscript
        # trim. A StatefulSmartContract with zero mutable fields has empty
        # state_fields yet still injects checkPreimage at entry, so its user
        # checkSig runs after the OP_CODESEPARATOR. parent_class is the
        # authoritative signal; fall back to is_stateful for older artifacts.
        parent_stateful = (
            self.artifact.parent_class == 'StatefulSmartContract'
            if self.artifact.parent_class
            else is_stateful
        )

        # For stateful contracts, the compiler injects implicit params into every
        # public method's ABI (SigHashPreimage, and for state-mutating methods:
        # _changePKH and _changeAmount). The SDK auto-computes these.
        # Filter them out so users only pass their own args.
        method_needs_change = any(p.name == '_changePKH' for p in method.params)
        method_needs_new_amount = any(p.name == '_newAmount' for p in method.params)
        # Whether the unlocking script is prefixed with _codePart. New artifacts
        # carry the authoritative uses_code_part flag (true for continuation
        # builders AND terminal var-length-state readers — issue #100). Older
        # artifacts lack it; fall back to the legacy rule.
        method_uses_code_part = (
            method.uses_code_part if method.uses_code_part is not None
            else method_needs_change
        )
        # Drop auto-injected continuation params AND intent-intrinsic witness
        # params (`_prevOutScript_<i>`, `_serialisedOutputs`) from the
        # user-facing arg count check. Witness values come from
        # set_prev_out_script / set_serialised_outputs, not from the args list.
        def _is_intent_witness_param(name: str) -> bool:
            return name.startswith('_prevOutScript_') or name == '_serialisedOutputs'

        if is_stateful:
            user_params = [
                p for p in method.params
                if p.type != 'SigHashPreimage'
                and p.name != '_changePKH'
                and p.name != '_changeAmount'
                and p.name != '_newAmount'
                and not _is_intent_witness_param(p.name)
            ]
        else:
            user_params = [p for p in method.params if not _is_intent_witness_param(p.name)]

        if len(user_params) != len(args):
            raise ValueError(
                f"RunarContract.prepare_call: method '{method_name}' expects {len(user_params)} args, got {len(args)}"
            )
        if self._current_utxo is None:
            raise RuntimeError(
                "RunarContract.prepare_call: contract is not deployed. Call deploy() or from_txid() first."
            )

        # DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
        assert_script_hex_under_limit(
            self._current_utxo.script, MAX_SCRIPT_BYTES,
            f"{self.artifact.contract_name}.call({method_name})",
        )

        contract_utxo = Utxo(
            txid=self._current_utxo.txid,
            output_index=self._current_utxo.output_index,
            satoshis=self._current_utxo.satoshis,
            script=self._current_utxo.script,
        )
        address = signer.get_address()
        opts = options or CallOptions()
        change_address = opts.change_address or address

        # Detect Sig/PubKey/SigHashPreimage/ByteString params that need auto-compute (user passed None)
        resolved_args = list(args)
        sig_indices: list[int] = []
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
                if not _is_auto_prevouts_param(param):
                    raise _nil_non_sig_arg_error('RunarContract.prepare_call', param, i)
                prevouts_indices.append(i)
                # Placeholder: 36 bytes per estimated input
                resolved_args[i] = '00' * (36 * estimated_inputs)
            # EMPTY_SIG (issue #106) is intentionally NOT handled here: it is not
            # None, so it is never added to `sig_indices` and never signed. It
            # stays in `resolved_args` and `_encode_arg` emits OP_0 for it.

        # Soft heuristic (issue #106): warn only for likely OR-CHECKSIG
        # (OP_BOOLOR + OP_CHECKSIG), not genuine multi-sig (OP_CHECKMULTISIG).
        if len(sig_indices) >= 2 and _is_likely_or_checksig(self.artifact):
            warnings.warn(
                f"runar-sdk: {self.artifact.contract_name}.call('{method_name}') "
                f"has {len(sig_indices)} auto-signed Sig slots. If this is an "
                f"OR-CHECKSIG method, pass EMPTY_SIG for the non-matching "
                f"branch(es) to satisfy BIP146 NULLFAIL (issue #106).",
                stacklevel=2,
            )

        # If any param uses SigHashPreimage, or this is stateful,
        # the compiler injects an implicit _opPushTxSig.
        needs_op_push_tx = preimage_index >= 0 or is_stateful

        # Compute method selector (needed for both terminal and non-terminal)
        method_selector_hex = ''
        if is_stateful:
            public_methods = self._get_public_methods()
            if len(public_methods) > 1:
                for mi, m in enumerate(public_methods):
                    if m.name == method_name:
                        method_selector_hex = _encode_script_number(mi)
                        break

        # Compute code separator index for this method
        code_sep_idx = self._get_code_sep_index(self._find_method_index(method_name))

        # Issue #123: build every preimage for this call under the method's
        # declared @sighash mode (default 0x41). A method with no directive
        # carries no sigHashType → falls back to 0x41 (unchanged behaviour).
        method_sig_hash_type = self._method_sig_hash_type(method_name)

        # Compute change PKH for stateful methods that need it
        change_pkh_hex = ''
        if is_stateful and method_needs_change:
            change_pub_key_hex = opts.change_pub_key or signer.get_public_key()
            pub_key_bytes = bytes.fromhex(change_pub_key_hex)
            hash160_bytes = hashlib.new(
                'ripemd160', hashlib.sha256(pub_key_bytes).digest()
            ).digest()
            change_pkh_hex = hash160_bytes.hex()

        # Pre-resolve intent-intrinsic witness hex (raises
        # WitnessValueMissingError if a `_prevOutScript_<i>` or
        # `_serialisedOutputs` param wasn't set on the contract). Resolving
        # up-front means the error is raised BEFORE any signing / broadcast
        # work, mirroring the script-size guard above.
        witness_hex = self._build_intent_witness_hex(method)

        # -------------------------------------------------------------------
        # Terminal method path: exact outputs, no funding, no change
        # -------------------------------------------------------------------
        if opts.terminal_outputs:
            return self._prepare_terminal(
                method_name, resolved_args, signer, opts,
                is_stateful, parent_stateful, needs_op_push_tx, method_needs_change,
                method_uses_code_part,
                sig_indices, prevouts_indices, preimage_index,
                method_selector_hex, change_pkh_hex, contract_utxo, witness_hex,
            )

        # -------------------------------------------------------------------
        # Non-terminal path
        # -------------------------------------------------------------------
        # Initial unlocking script (with placeholders). Intent-witness hex is
        # suffixed so size estimation accounts for the witness pushes; the
        # real ABI-correct unlock is rebuilt by _build_stateful_unlock below
        # for stateful methods.
        if needs_op_push_tx:
            # Prepend placeholder prefix (optionally _codePart + _opPushTxSig)
            unlocking_script = self._build_stateful_prefix('00' * 72, method_uses_code_part) + \
                self.build_unlocking_script(method_name, resolved_args) + witness_hex
        else:
            unlocking_script = self.build_unlocking_script(method_name, resolved_args) + witness_hex

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

        # Data outputs resolved from this.addDataOutput(...). Explicit
        # opts.data_outputs (if provided) wins; otherwise populated by the
        # ANF interpreter pass below.
        resolved_data_outputs: list[dict] = []
        explicit_data_outputs = getattr(opts, 'data_outputs', None)
        if explicit_data_outputs:
            resolved_data_outputs = [
                {'script': d['script'], 'satoshis': d['satoshis']}
                if isinstance(d, dict)
                else {'script': d.script, 'satoshis': d.satoshis}
                for d in explicit_data_outputs
            ]

        # Run the ANF interpreter for any stateful method whose artifact has
        # ANF IR. The interpreter resolves both the new state and any data
        # outputs declared via this.addDataOutput(...). Data outputs are part
        # of method-body behaviour (not state) and the on-chain continuation
        # hash check fails at spend time if they're missing — so this must
        # run even when the caller pre-supplied opts.new_state. Reference:
        # packages/runar-go/sdk_contract.go (ComputeNewStateAndDataOutputs).
        anf_computed_state: dict | None = None
        # State-class outputs (state continuation + raw) in SOURCE order, from
        # the ANF interpreter. Empty for methods that emit no add_raw_output(...)
        # (finding G1) — the raw-output rebuild below is then a no-op.
        anf_ordered_outputs: list[dict] = []
        if is_stateful and self.artifact.anf:
            named_args = _build_named_args(user_params, resolved_args)
            flat_state = _flatten_fixed_array_state(
                self._state, self.artifact.state_fields,
            )
            flat_ctor_args = _flatten_fixed_array_args(
                self._constructor_args,
                self.artifact.abi.constructor_params,
            )
            try:
                ordered: list[dict] = []
                computed, data_outs, _raw_outs = compute_new_state_and_data_outputs(
                    self.artifact.anf, method_name, flat_state, named_args,
                    flat_ctor_args, ordered_outputs=ordered,
                )
                anf_ordered_outputs = ordered
            except Exception as err:
                # FAIL CLOSED (NEW-006). The legacy behaviour was to swallow
                # this and build the continuation from the CURRENT (pre-call)
                # state, which the covenant's hashOutputs binding then rejects
                # -- a silent "your call cannot be broadcast", plus silent loss
                # of the method's data / raw outputs. The interpreter is the
                # only thing that knows this method's post-state and its
                # addDataOutput/addRawOutput payloads, so there is nothing to
                # fall back TO: an explicit `new_state` covers only the state
                # field and still leaves the outputs missing.
                raise RuntimeError(
                    f"RunarContract.call('{method_name}'): the ANF interpreter "
                    f"could not evaluate the method body, so the state "
                    f"continuation and data outputs this call would commit "
                    f"cannot be derived. Refusing to broadcast a transaction "
                    f"built from the pre-call state. Cause: {err}"
                ) from err
            if computed is not None:
                merged = {**flat_state, **computed}
                anf_computed_state = _regroup_fixed_array_state(
                    merged, self.artifact.state_fields,
                )
            if data_outs and not resolved_data_outputs:
                resolved_data_outputs = data_outs

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
            #
            # Honor an explicit `self.add_output(<sats>, ...)` state continuation:
            # the ANF interpreter records that amount in `anf_ordered_outputs`
            # (one `kind == 'state'` entry per add_output). A method with a single
            # explicit add_output and no raw output must build its continuation at
            # that amount, not default to the spent input's value -- otherwise the
            # covenant's hashOutputs binding rejects the spend and funds are
            # stranded. Finding G1 reads the same satoshis but only on the
            # raw-output-present branch below; this generalizes it to the no-raw
            # single-continuation path. With no explicit add_output (the
            # auto-injected continuation) `anf_ordered_outputs` is empty and the
            # input-value default is kept. An explicit `options.satoshis` still wins.
            anf_state_entries = [o for o in anf_ordered_outputs if o['kind'] == 'state']
            single_explicit_state_sats = (
                int(anf_state_entries[0]['satoshis'])
                if len(anf_ordered_outputs) == 1 and len(anf_state_entries) == 1
                else None
            )
            if opts.satoshis > 0:
                new_satoshis = opts.satoshis
            elif single_explicit_state_sats is not None:
                new_satoshis = single_explicit_state_sats
            else:
                new_satoshis = self._current_utxo.satoshis
            if opts.new_state:
                for k, v in opts.new_state.items():
                    self._state[k] = v
            elif method_needs_change and anf_computed_state is not None:
                self._state = {**self._state, **anf_computed_state}
            new_locking_script = self.get_locking_script()
            # DoS-bound: also reject pathological continuation scripts BEFORE broadcast.
            assert_script_hex_under_limit(
                new_locking_script, MAX_SCRIPT_BYTES,
                f"{self.artifact.contract_name}.call({method_name}).continuation",
            )

        # Finding G1: a method that calls self.add_raw_output(...) folds the raw
        # output(s) into the covenant's continuation hashOutputs IN SOURCE ORDER,
        # interleaved with the state continuation self.add_output(...). The
        # single-stateful branch above builds only the state continuation, so the
        # built tx would emit it alone and mismatch hashOutputs — input 0's
        # auto-injected OP_VERIFY would reject. Rebuild an ORDERED contract_outputs
        # from the interpreter's source-ordered output list. Purely additive:
        # absent raw outputs this is a no-op and existing behaviour is untouched.
        if is_stateful and any(o['kind'] == 'raw' for o in anf_ordered_outputs):
            state_entries = [o for o in anf_ordered_outputs if o['kind'] == 'state']
            # Fail closed. The covenant machinery below threads exactly one
            # continuation script/amount, so multi-output calls, >=2 state
            # continuations, or a missing continuation script are not
            # representable — raise rather than silently drop outputs and strand
            # the funds.
            if (
                has_multi_output
                or len(state_entries) >= 2
                or (len(state_entries) == 1 and not new_locking_script)
            ):
                raise ValueError(
                    f"RunarContract.call({method_name}): cannot build a transaction that "
                    f"interleaves raw outputs with {len(state_entries)} state continuation(s); "
                    f"the SDK currently supports raw outputs alongside a single state "
                    f"continuation only (finding G1)."
                )
            contract_outputs = [
                {'script': o['script'], 'satoshis': int(o['satoshis'])}
                if o['kind'] == 'raw'
                else {'script': new_locking_script, 'satoshis': int(o['satoshis'])}
                for o in anf_ordered_outputs
            ]
            # Keep the preimage's new-amount (built in _build_stateful_unlock) in
            # step with the continuation output's sats — self.addOutput(0, ...)
            # makes it 0, not the input value the single-stateful branch defaulted
            # to.
            if len(state_entries) == 1:
                new_satoshis = int(state_entries[0]['satoshis'])

        # Fetch fee rate and funding UTXOs for all contract types.
        # For stateful contracts with change output support, the change output
        # is verified by the on-chain script (hashOutputs check).
        fee_rate = provider.get_fee_rate()
        change_script = build_p2pkh_script(change_address)
        all_funding_utxos = provider.get_utxos(address)
        # Filter out the contract UTXO to avoid duplicate inputs
        candidate_funding_utxos: list[Utxo] = [
            u for u in all_funding_utxos
            if not (u.txid == self._current_utxo.txid and u.output_index == self._current_utxo.output_index)
        ]

        # Resolve per-input args for additional contract inputs (same
        # Sig/PubKey/ByteString handling). Computed BEFORE funding selection so
        # the merge unlock sizes -- and therefore the contract-input byte size
        # the funding fee must cover (finding C2) -- are known before we size
        # the funding. Consumed again later when the real merge unlocks are built.
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
                        if not _is_auto_prevouts_param(param):
                            raise _nil_non_sig_arg_error(
                                'RunarContract.prepare_call (additional contract input)', param, i)
                        resolved[i] = '00' * (36 * estimated_inputs)
                resolved_per_input_args.append(resolved)

        # Build placeholder unlocking scripts for merge inputs (witness_hex
        # suffixed for sizing — _build_stateful_unlock builds the real scripts).
        extra_unlock_placeholders = []
        for i in range(len(extra_contract_utxos)):
            args_for_placeholder = resolved_per_input_args[i] if resolved_per_input_args and i < len(resolved_per_input_args) else resolved_args
            extra_unlock_placeholders.append(
                self._build_stateful_prefix('00' * 72, method_uses_code_part) + self.build_unlocking_script(method_name, args_for_placeholder) + witness_hex
            )

        # Coin selection for funding inputs (issue #133): don't sweep the whole
        # wallet. Compute how much the funding must cover -- the contract's own
        # input value already offsets the contract/data outputs -- and pick the
        # smallest largest-first set via select_utxos (the strategy deploy uses).
        contract_output_sats = (
            (sum(co['satoshis'] for co in contract_outputs)
             if contract_outputs else (new_satoshis or 0))
            + sum(do['satoshis'] for do in resolved_data_outputs)
        )
        contract_input_sats = (
            self._current_utxo.satoshis
            + sum(u.satoshis for u in extra_contract_utxos)
        )
        funding_target = max(0, contract_output_sats - contract_input_sats)
        # Fee sizing hint for select_utxos: the continuation script length
        # (falls back to the first multi-output script, else 0 for stateless).
        if new_locking_script:
            funding_lock_len = len(new_locking_script) // 2
        elif contract_outputs:
            funding_lock_len = len(contract_outputs[0]['script']) // 2
        else:
            funding_lock_len = 0

        # C2: contract-input unlock bytes. select_utxos / estimate_deploy_fee
        # otherwise model ONLY the funding inputs (148-byte P2PKH each) +
        # continuation + change -- they are blind to the contract input(s) being
        # spent. For a MERGE each covenant input embeds both parent txs as method
        # args (tens of KB), so ignoring them under-provisions the funding;
        # build_call_transaction then sees change <= 0 and DROPS the change
        # output, and the merge covenant -- which reconstructs [continuation]
        # [P2PKH change] UNCONDITIONALLY -- fails its hashOutputs OP_VERIFY. Size
        # the funding fee against the SAME serialized per-input bytes
        # build_call_transaction uses (32 outpoint + 4 index + varint + script +
        # 4 sequence) for the primary contract input plus every extra one.
        # Over-estimating is safe (a little more funding / higher change);
        # under-estimating is the bug.
        def _per_input_bytes(unlock_hex: str) -> int:
            length = len(unlock_hex) // 2
            vi = 1 if length < 0xFD else 3 if length <= 0xFFFF else 5 if length <= 0xFFFFFFFF else 9
            return 32 + 4 + vi + length + 4

        # The sizing placeholders above are `prefix(sig72) + unlocking_script +
        # witness_hex`. The REAL unlock _build_stateful_unlock emits is larger --
        # it appends the BIP-143 preimage (whose scriptCode ~= the locking
        # script), the change + new-amount pushes, and the method selector, and
        # the opSig codePart prefix (~= the locking script). That gap is exactly
        # what would make select_utxos stop one UTXO short. Add a per-contract-
        # input overestimate covering those omitted components: codePart (~=
        # locking script) + preimage scriptCode (~= locking script) + a fixed
        # buffer for sig/amount/selector/varint framing. Over-estimating only
        # pulls slightly more funding (bigger change) -- always safe.
        num_contract_inputs = 1 + len(extra_contract_utxos)
        per_contract_input_overhead = 2 * funding_lock_len + 512
        contract_input_bytes = (
            _per_input_bytes(unlocking_script)
            + sum(_per_input_bytes(u) for u in extra_unlock_placeholders)
            + num_contract_inputs * per_contract_input_overhead
        )

        # C15: size the funding fee against ALL outputs, not just the single
        # continuation that `funding_lock_len` already covers. estimate_deploy_fee
        # counts one output of `funding_lock_len` bytes; add the framing (8 +
        # varint + scriptLen) of every OTHER contract output (extra multi-outputs
        # + raw outputs, finding G1) and every data output so selection does not
        # stop one UTXO short on multi-output / large-dataOutput calls. Single-
        # output calls net 0 (estimate unchanged). Over-estimating only pulls
        # slightly more funding (bigger change) -- always safe.
        def _output_framing(byte_len: int) -> int:
            vi = 1 if byte_len < 0xFD else 3 if byte_len <= 0xFFFF else 5 if byte_len <= 0xFFFFFFFF else 9
            return 8 + vi + byte_len

        all_output_byte_lens = [
            *(
                [len(co['script']) // 2 for co in contract_outputs]
                if contract_outputs
                else ([len(new_locking_script) // 2] if new_locking_script else [])
            ),
            *[len(do['script']) // 2 for do in resolved_data_outputs],
        ]
        total_output_framing = sum(_output_framing(n) for n in all_output_byte_lens)
        extra_output_bytes = max(
            0, total_output_framing - _output_framing(funding_lock_len),
        )

        additional_utxos: list[Utxo] = (
            select_utxos(
                candidate_funding_utxos, funding_target, funding_lock_len, fee_rate,
                contract_input_bytes, extra_output_bytes,
            )
            if candidate_funding_utxos else []
        )

        # Cap funding inputs when the caller sets max_funding_inputs. select_utxos
        # returns the minimal largest-first set; if that still exceeds the cap the
        # funding can't cover outputs + fee within the budget, so fail loudly
        # instead of broadcasting an underfunded tx.
        if (
            options is not None
            and options.max_funding_inputs is not None
            and len(additional_utxos) > options.max_funding_inputs
        ):
            raise ValueError(
                f"RunarContract.call({method_name}): funding requires "
                f"{len(additional_utxos)} input(s) but "
                f"max_funding_inputs={options.max_funding_inputs}. Increase "
                f"max_funding_inputs, use larger UTXOs, or consolidate."
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
            data_outputs=resolved_data_outputs or None,
            # Thread CallOptions.locktime so contracts asserting
            # extractLocktime(preimage) can succeed. None → 0 (legacy).
            locktime=opts.locktime,
            # Thread CallOptions.sequence (issue #131): a non-zero locktime
            # needs non-final input sequences or consensus ignores nLockTime.
            sequence=opts.sequence,
        )

        # Sign P2PKH funding inputs (after contract inputs). Funding inputs are
        # signed by funding_signer when set (issue #134): the method signer may
        # not own the funding coins. The method's own Sig args keep the
        # connected signer. Defaults to the connected signer.
        signed_tx = tx_hex
        pub_key = funding_signer.get_public_key()
        p2pkh_start_idx = 1 + len(extra_contract_utxos)
        for i in range(p2pkh_start_idx, input_count):
            utxo_idx = i - p2pkh_start_idx
            if utxo_idx < len(additional_utxos):
                utxo = additional_utxos[utxo_idx]
                sig = funding_signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
                unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
                signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

        final_op_push_tx_sig = ''
        final_preimage = ''

        if is_stateful:
            # Helper: build a stateful unlock.  For input_idx==0 (primary),
            # keeps placeholder Sig params.  For input_idx>0 (extra), signs
            # with signer.
            def _build_stateful_unlock(tx: str, input_idx: int, subscript: str, sats: int, args_override: list | None = None, tx_change_amount: int = 0, pi: list[int] | None = None) -> tuple[str, str, str]:
                op_sig, preimage = compute_op_push_tx(tx, input_idx, subscript, sats, code_sep_idx, method_sig_hash_type)
                base_args = args_override if args_override is not None else resolved_args
                input_args = list(base_args)
                # Only sign Sig params for extra inputs, not the primary
                if input_idx > 0:
                    sig_subscript = subscript
                    if code_sep_idx >= 0:
                        trim_pos = (code_sep_idx + 1) * 2
                        if trim_pos <= len(subscript):
                            sig_subscript = subscript[trim_pos:]
                    for idx in sig_indices:
                        input_args[idx] = signer.sign(tx, input_idx, sig_subscript, sats)
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
                new_amount_hex = ''
                if method_needs_new_amount:
                    new_amount_hex = _encode_script_number(new_satoshis)
                unlock = (
                    self._build_stateful_prefix(op_sig, method_uses_code_part) +
                    args_hex +
                    change_hex +
                    new_amount_hex +
                    encode_push_data(preimage) +
                    witness_hex +
                    method_selector_hex
                )
                return unlock, op_sig, preimage

            # First pass: build unlocking scripts with current tx layout
            input0_unlock, _, _ = _build_stateful_unlock(
                signed_tx, 0, contract_utxo.script, contract_utxo.satoshis,
                tx_change_amount=change_amount,
                pi=prevouts_indices,
            )
            extra_unlocks: list[str] = []
            for i, mu in enumerate(extra_contract_utxos):
                extra_args = resolved_per_input_args[i] if resolved_per_input_args and i < len(resolved_per_input_args) else None
                eu, _, _ = _build_stateful_unlock(
                    signed_tx, i + 1, mu.script, mu.satoshis, extra_args,
                    tx_change_amount=change_amount,
                    pi=prevouts_indices,
                )
                extra_unlocks.append(eu)

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
                data_outputs=resolved_data_outputs or None,
                # Rebuild path must honor the override too: a preimage computed
                # on a rebuilt tx with locktime 0 would mismatch the final tx.
                locktime=opts.locktime,
                # Same for sequence — the second-pass preimage must see the
                # final input sequences (issue #131).
                sequence=opts.sequence,
            )
            signed_tx = tx_hex

            # Re-sign P2PKH funding inputs after rebuild (funding_signer — #134)
            p2pkh_start_idx = 1 + len(extra_contract_utxos)
            for i in range(p2pkh_start_idx, input_count):
                utxo_idx = i - p2pkh_start_idx
                if utxo_idx < len(additional_utxos):
                    utxo = additional_utxos[utxo_idx]
                    sig = funding_signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
                    unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
                    signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

            # Second pass: recompute with final tx (preimage changes with unlock size)
            final_input0_unlock, op_sig, preimage = _build_stateful_unlock(
                signed_tx, 0, contract_utxo.script, contract_utxo.satoshis,
                tx_change_amount=change_amount,
                pi=prevouts_indices,
            )
            final_op_push_tx_sig = op_sig
            final_preimage = preimage
            signed_tx = insert_unlocking_script(signed_tx, 0, final_input0_unlock)

            for i, mu in enumerate(extra_contract_utxos):
                extra_args = resolved_per_input_args[i] if resolved_per_input_args and i < len(resolved_per_input_args) else None
                final_merge_unlock, _, _ = _build_stateful_unlock(
                    signed_tx, i + 1, mu.script, mu.satoshis, extra_args,
                    tx_change_amount=change_amount,
                    pi=prevouts_indices,
                )
                signed_tx = insert_unlocking_script(signed_tx, i + 1, final_merge_unlock)

            # Re-sign P2PKH funding inputs after second pass (funding_signer — #134)
            for i in range(p2pkh_start_idx, input_count):
                utxo_idx = i - p2pkh_start_idx
                if utxo_idx < len(additional_utxos):
                    utxo = additional_utxos[utxo_idx]
                    sig = funding_signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
                    unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
                    signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

            # Update resolved_args with real prevouts so finalize_call can
            # rebuild the primary unlock with correct allPrevouts values.
            if prevouts_indices:
                all_prevouts_hex = _extract_all_prevouts(signed_tx)
                for idx in prevouts_indices:
                    resolved_args[idx] = all_prevouts_hex

        elif needs_op_push_tx or sig_indices:
            # Stateless: keep placeholder sigs, compute OP_PUSH_TX
            if needs_op_push_tx:
                sig_hex, preimage_hex = compute_op_push_tx(
                    signed_tx, 0, contract_utxo.script, contract_utxo.satoshis, code_sep_idx,
                    method_sig_hash_type,
                )
                final_op_push_tx_sig = sig_hex
                resolved_args[preimage_index] = preimage_hex
            # Don't sign Sig params -- keep placeholders
            real_unlocking_script = self.build_unlocking_script(method_name, resolved_args)
            if needs_op_push_tx and final_op_push_tx_sig:
                real_unlocking_script = self._build_stateful_prefix(final_op_push_tx_sig, False) + real_unlocking_script
                tmp_tx = insert_unlocking_script(signed_tx, 0, real_unlocking_script)
                final_sig, final_pre = compute_op_push_tx(
                    tmp_tx, 0, contract_utxo.script, contract_utxo.satoshis, code_sep_idx,
                    method_sig_hash_type,
                )
                resolved_args[preimage_index] = final_pre
                final_op_push_tx_sig = final_sig
                final_preimage = final_pre
                real_unlocking_script = self._build_stateful_prefix(final_sig, False) + \
                    self.build_unlocking_script(method_name, resolved_args)
            signed_tx = insert_unlocking_script(signed_tx, 0, real_unlocking_script)
            if not final_preimage and needs_op_push_tx:
                final_preimage = resolved_args[preimage_index]

        # Compute sighash from preimage (C19: the true BIP-143 digest external
        # signers must sign -- hash256(preimage), NOT sha256(preimage)).
        sighash = _compute_bip143_sighash(final_preimage)

        return PreparedCall(
            sighash=sighash,
            preimage=final_preimage,
            op_push_tx_sig=final_op_push_tx_sig,
            tx_hex=signed_tx,
            sig_indices=sig_indices,
            method_name=method_name,
            resolved_args=resolved_args,
            method_selector_hex=method_selector_hex,
            is_stateful=is_stateful,
            parent_stateful=parent_stateful,
            is_terminal=False,
            needs_op_push_tx=needs_op_push_tx,
            method_needs_change=method_needs_change,
            method_uses_code_part=method_uses_code_part,
            change_pkh_hex=change_pkh_hex,
            change_amount=change_amount,
            method_needs_new_amount=method_needs_new_amount,
            new_amount=new_satoshis,
            preimage_index=preimage_index,
            contract_utxo=contract_utxo,
            new_locking_script=new_locking_script,
            new_satoshis=new_satoshis,
            has_multi_output=bool(has_multi_output),
            contract_outputs=contract_outputs or [],
            code_sep_idx=code_sep_idx,
            intent_witness_hex=witness_hex,
        )

    def finalize_call(
        self,
        prepared: PreparedCall,
        signatures: dict[int, str],
        provider: Provider | None = None,
    ) -> tuple[str, TransactionData]:
        """Complete a prepared call by injecting external signatures and broadcasting.

        Args:
            prepared:    The PreparedCall returned by prepare_call().
            signatures:  Map from arg index to DER signature hex (with sighash byte).
                         Each key must be one of prepared.sig_indices.
            provider:    Optional provider override.
        """
        provider = provider or self._provider
        if provider is None:
            raise RuntimeError("finalize_call: no provider")

        # Replace placeholder sigs with real signatures
        resolved_args = list(prepared.resolved_args)
        for idx in prepared.sig_indices:
            if idx in signatures:
                resolved_args[idx] = signatures[idx]

        # Assemble the primary unlocking script
        if prepared.is_stateful:
            args_hex = ''
            for arg in resolved_args:
                args_hex += _encode_arg(arg)
            change_hex = ''
            if prepared.method_needs_change and prepared.change_pkh_hex:
                change_hex = encode_push_data(prepared.change_pkh_hex) + _encode_script_number(prepared.change_amount)
            new_amount_hex = ''
            if prepared.method_needs_new_amount:
                new_amount_hex = _encode_script_number(prepared.new_amount)
            primary_unlock = (
                self._build_stateful_prefix(prepared.op_push_tx_sig, prepared.method_uses_code_part) +
                args_hex +
                change_hex +
                new_amount_hex +
                encode_push_data(prepared.preimage) +
                prepared.intent_witness_hex +
                prepared.method_selector_hex
            )
        elif prepared.needs_op_push_tx:
            if prepared.preimage_index >= 0:
                resolved_args[prepared.preimage_index] = prepared.preimage
            primary_unlock = self._build_stateful_prefix(prepared.op_push_tx_sig, False) + \
                self.build_unlocking_script(prepared.method_name, resolved_args)
        else:
            primary_unlock = self.build_unlocking_script(prepared.method_name, resolved_args)

        final_tx = insert_unlocking_script(prepared.tx_hex, 0, primary_unlock)

        txid = provider.broadcast(final_tx)

        # Update tracked UTXO
        if prepared.is_stateful and prepared.has_multi_output and prepared.contract_outputs:
            self._current_utxo = Utxo(
                txid=txid, output_index=0,
                satoshis=prepared.contract_outputs[0]['satoshis'],
                script=prepared.contract_outputs[0]['script'],
            )
        elif prepared.is_stateful and prepared.new_locking_script:
            # The state continuation is normally output 0, but a method that also
            # calls self.add_raw_output(...) (finding G1) can push raw outputs
            # ahead of it. When contract_outputs is populated (the raw-output
            # path) it records the real source order and each output's satoshis,
            # so track the continuation at its actual index and value (which may
            # legitimately be 0). Empty contract_outputs (the common case) keeps
            # the legacy index-0 / new_satoshis-fallback behaviour unchanged.
            cont_idx = -1
            if prepared.contract_outputs:
                for i, o in enumerate(prepared.contract_outputs):
                    if o['script'] == prepared.new_locking_script:
                        cont_idx = i
                        break
            if cont_idx >= 0:
                self._current_utxo = Utxo(
                    txid=txid, output_index=cont_idx,
                    satoshis=prepared.contract_outputs[cont_idx]['satoshis'],
                    script=prepared.new_locking_script,
                )
            else:
                self._current_utxo = Utxo(
                    txid=txid, output_index=0,
                    satoshis=prepared.new_satoshis or prepared.contract_utxo.satoshis,
                    script=prepared.new_locking_script,
                )
        elif prepared.is_terminal:
            self._current_utxo = None
        else:
            self._current_utxo = None

        try:
            tx = provider.get_transaction(txid)
        except Exception:
            tx = TransactionData(txid=txid, version=1, raw=final_tx)

        return txid, tx

    @classmethod
    def from_utxo(
        cls,
        artifact: RunarArtifact,
        utxo: Utxo,
    ) -> RunarContract:
        """Reconnect to an existing deployed contract from a known UTXO.

        This is the synchronous equivalent of from_txid() -- use it when the
        UTXO data is already available (e.g. from an overlay service or cache)
        without needing a Provider to fetch the transaction.
        """
        # Issue #119: recover the real baked-in constructor args from the
        # deployed script rather than seeding zeros. Readonly ctor params feed
        # the state-continuation formula and adjust_code_sep_offset, so zero
        # placeholders make a restored stateful spend unspendable. Params with
        # no ctor slot (mutable state fields) fall back to 0 and are overwritten
        # by extract_state_from_script below.
        restored_args = restore_constructor_args(artifact, utxo.script)
        contract = cls(artifact, restored_args)

        if artifact.state_fields:
            last_op_return = find_last_op_return(utxo.script)
            if last_op_return != -1:
                contract._code_script = utxo.script[:last_op_return]
            else:
                contract._code_script = utxo.script
        else:
            contract._code_script = utxo.script

        # Detect inscription envelope in the code portion. Keep it in _code_script
        # (do NOT strip) so that stateful continuation outputs preserve it.
        if contract._code_script:
            parsed_inscription = parse_inscription_envelope(contract._code_script)
            if parsed_inscription:
                contract._inscription = parsed_inscription

        contract._current_utxo = Utxo(
            txid=utxo.txid, output_index=utxo.output_index,
            satoshis=utxo.satoshis, script=utxo.script,
        )

        if artifact.state_fields:
            state = extract_state_from_script(artifact, utxo.script)
            if state is not None:
                contract._state = state

        return contract

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
        return RunarContract.from_utxo(artifact, Utxo(
            txid=txid, output_index=output_index,
            satoshis=output.satoshis, script=output.script,
        ))

    def get_locking_script(self) -> str:
        """Return the full locking script hex."""
        # Use stored code script from chain if available (reconnected contract).
        # When loaded from chain, _code_script already contains the inscription
        # envelope (if any). When built from the template, we splice it in.
        built_from_template = not self._code_script
        script = self._code_script or self._build_code_script()

        # Inject inscription envelope between code and state (template-built only;
        # chain-loaded _code_script already includes it).
        if built_from_template and self._inscription:
            script += build_inscription_envelope(
                self._inscription.content_type,
                self._inscription.data,
            )

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

    # -- Ordinals --

    def with_inscription(self, inscription: Inscription) -> 'RunarContract':
        """Attach a 1sat ordinals inscription to this contract.

        The inscription envelope is injected into the locking script between
        the compiled code and the state section (if any). Once deployed, the
        inscription is immutable -- it persists identically across all state
        transitions.
        """
        self._inscription = inscription
        return self

    @property
    def inscription(self) -> Inscription | None:
        """Returns the current inscription, if any."""
        return self._inscription

    # -- Terminal method (prepare path) --

    def _prepare_terminal(
        self,
        method_name: str,
        resolved_args: list,
        signer: Signer,
        opts: CallOptions,
        is_stateful: bool,
        parent_stateful: bool,
        needs_op_push_tx: bool,
        method_needs_change: bool,
        method_uses_code_part: bool,
        sig_indices: list[int],
        prevouts_indices: list[int],
        preimage_index: int,
        method_selector_hex: str,
        change_pkh_hex: str,
        contract_utxo: Utxo,
        witness_hex: str = '',
    ) -> PreparedCall:
        """Handle the terminal method code path for prepare_call."""
        # Normalize terminal outputs
        term_outputs = []
        for item in opts.terminal_outputs:
            if isinstance(item, TerminalOutput):
                term_outputs.append(item)
            elif isinstance(item, dict):
                term_outputs.append(TerminalOutput(
                    script_hex=item['scriptHex'] if 'scriptHex' in item else item['script_hex'],
                    satoshis=item['satoshis'],
                ))
            else:
                term_outputs.append(item)

        # Build placeholder unlocking script (witness_hex suffixed for sizing
        # — the real ABI-correct unlock is built by
        # build_stateful_terminal_unlock below for stateful methods).
        if needs_op_push_tx:
            term_unlock_script = self._build_stateful_prefix('00' * 72, False) + \
                self.build_unlocking_script(method_name, resolved_args)
        else:
            term_unlock_script = self.build_unlocking_script(method_name, resolved_args)
        term_unlock_script += witness_hex

        # Funding (and terminal fee) inputs are signed by funding_signer when
        # set (issue #134). The method's own Sig args stay with the connected
        # signer. Defaults to the connected signer.
        funding_signer = opts.funding_signer or signer

        # Resolve funding UTXOs for terminal methods
        funding_utxos = opts.funding_utxos or []

        # Terminal calls (auction close/claim/withdraw) typically assert
        # extractLocktime(preimage) >= deadline. Default 0 preserves legacy
        # behavior for contracts that don't check locktime.
        terminal_locktime = opts.locktime if opts.locktime is not None else 0

        # Sequence (issue #131): all-final inputs make nLockTime a consensus
        # no-op — when a non-zero locktime is set, default to 0xfffffffe so the
        # terminal method's extractLocktime assertion is actually enforced.
        term_sequence_hex = _to_le32(resolve_input_sequence(opts.locktime, opts.sequence))

        # Fee input (issue #118): a single plain P2PKH UTXO added BEFORE the
        # OP_PUSH_TX preimage is computed (so hashPrevouts covers it), consumed
        # entirely as fee — no change output. It sits at index 1, right after
        # the primary contract input, so the covenant's terminal output
        # assertions (which don't touch the input side) stay valid.
        fee_utxo = opts.fee_utxo

        # Build raw terminal transaction: contract input + optional fee input +
        # optional funding inputs, exact outputs.
        def build_terminal_tx(unlock: str) -> str:
            num_inputs = 1 + (1 if fee_utxo else 0) + len(funding_utxos)
            tx = ''
            tx += _to_le32(1)  # version
            tx += _encode_varint(num_inputs)
            # Input 0: contract UTXO
            tx += _reverse_hex(contract_utxo.txid)
            tx += _to_le32(contract_utxo.output_index)
            tx += _encode_varint(len(unlock) // 2)
            tx += unlock
            tx += term_sequence_hex
            # Fee input (unsigned placeholder; signed after tx is final)
            if fee_utxo:
                tx += _reverse_hex(fee_utxo.txid)
                tx += _to_le32(fee_utxo.output_index)
                tx += '00'  # empty scriptSig
                tx += term_sequence_hex
            # Funding inputs (unsigned placeholders)
            for fu in funding_utxos:
                tx += _reverse_hex(fu.txid)
                tx += _to_le32(fu.output_index)
                tx += '00'  # empty scriptSig
                tx += term_sequence_hex
            tx += _encode_varint(len(term_outputs))
            for out in term_outputs:
                tx += _to_le64(out.satoshis)
                tx += _encode_varint(len(out.script_hex) // 2)
                tx += out.script_hex
            tx += _to_le32(terminal_locktime)  # locktime
            return tx

        term_tx = build_terminal_tx(term_unlock_script)
        final_op_push_tx_sig = ''
        final_preimage = ''

        term_code_sep_idx = self._get_code_sep_index(self._find_method_index(method_name))
        # Issue #123: terminal preimages also honour the declared @sighash mode.
        term_sig_hash_type = self._method_sig_hash_type(method_name)

        if is_stateful:
            # Build stateful terminal unlock with PLACEHOLDER user sigs
            def build_stateful_terminal_unlock(tx: str) -> tuple[str, str, str]:
                op_sig, preimage = compute_op_push_tx(tx, 0, contract_utxo.script, contract_utxo.satoshis, term_code_sep_idx, term_sig_hash_type)
                # Keep placeholder Sig params (don't sign for primary)
                args_hex = ''
                for arg in resolved_args:
                    args_hex += _encode_arg(arg)
                # Terminal: 0 change
                change_hex = ''
                if method_needs_change and change_pkh_hex:
                    change_hex = encode_push_data(change_pkh_hex) + _encode_script_number(0)
                unlock = (
                    self._build_stateful_prefix(op_sig, False) +
                    args_hex +
                    change_hex +
                    encode_push_data(preimage) +
                    witness_hex +
                    method_selector_hex
                )
                return unlock, op_sig, preimage

            # First pass
            first_unlock, _, _ = build_stateful_terminal_unlock(term_tx)
            term_tx = build_terminal_tx(first_unlock)

            # Second pass
            final_unlock, op_sig, preimage = build_stateful_terminal_unlock(term_tx)
            term_tx = insert_unlocking_script(term_tx, 0, final_unlock)
            final_op_push_tx_sig = op_sig
            final_preimage = preimage

        elif needs_op_push_tx or sig_indices:
            # Stateless terminal -- keep placeholder sigs
            if needs_op_push_tx:
                sig_hex, preimage_hex = compute_op_push_tx(
                    term_tx, 0, contract_utxo.script, contract_utxo.satoshis, term_code_sep_idx,
                    term_sig_hash_type,
                )
                final_op_push_tx_sig = sig_hex
                resolved_args[preimage_index] = preimage_hex

            # Don't sign Sig params -- keep 72-byte placeholders
            real_unlock = self.build_unlocking_script(method_name, resolved_args)
            if needs_op_push_tx and final_op_push_tx_sig:
                real_unlock = self._build_stateful_prefix(final_op_push_tx_sig, False) + real_unlock
                tmp_tx = insert_unlocking_script(term_tx, 0, real_unlock)
                final_sig, final_pre = compute_op_push_tx(
                    tmp_tx, 0, contract_utxo.script, contract_utxo.satoshis, term_code_sep_idx,
                    term_sig_hash_type,
                )
                resolved_args[preimage_index] = final_pre
                final_op_push_tx_sig = final_sig
                final_preimage = final_pre
                real_unlock = self._build_stateful_prefix(final_sig, False) + \
                    self.build_unlocking_script(method_name, resolved_args)
            term_tx = insert_unlocking_script(term_tx, 0, real_unlock)
            if not final_preimage and needs_op_push_tx:
                final_preimage = resolved_args[preimage_index]

        # Sign the fee input (issue #118). Its BIP-143 P2PKH sighash covers only
        # hashPrevouts / hashOutputs / its own outpoint — NOT input 0's scriptSig
        # — so it stays valid even after finalize_call rewrites input 0. Owned by
        # funding_signer (composes with #134). The fee input sits at index 1,
        # right after the primary contract input.
        if fee_utxo:
            fee_input_idx = 1
            fee_sig = funding_signer.sign(
                term_tx, fee_input_idx, fee_utxo.script, fee_utxo.satoshis,
            )
            fee_pub_key = funding_signer.get_public_key()
            fee_unlock = encode_push_data(fee_sig) + encode_push_data(fee_pub_key)
            term_tx = insert_unlocking_script(term_tx, fee_input_idx, fee_unlock)

        # Compute sighash from preimage (C19: the true BIP-143 digest external
        # signers must sign -- hash256(preimage), NOT sha256(preimage)).
        sighash = _compute_bip143_sighash(final_preimage)

        return PreparedCall(
            sighash=sighash,
            preimage=final_preimage,
            op_push_tx_sig=final_op_push_tx_sig,
            tx_hex=term_tx,
            sig_indices=sig_indices,
            method_name=method_name,
            resolved_args=resolved_args,
            method_selector_hex=method_selector_hex,
            is_stateful=is_stateful,
            parent_stateful=parent_stateful,
            is_terminal=True,
            needs_op_push_tx=needs_op_push_tx,
            method_needs_change=method_needs_change,
            method_uses_code_part=method_uses_code_part,
            change_pkh_hex=change_pkh_hex,
            change_amount=0,
            method_needs_new_amount=False,
            new_amount=0,
            preimage_index=preimage_index,
            contract_utxo=contract_utxo,
            new_locking_script='',
            new_satoshis=0,
            has_multi_output=False,
            contract_outputs=[],
            code_sep_idx=term_code_sep_idx,
            intent_witness_hex=witness_hex,
        )

    # -- Code separator helpers --

    def _get_code_part_hex(self) -> str:
        """Get the code part (code script without state).

        Includes the inscription envelope if one is attached -- this is required
        for stateful contracts where the on-chain hashOutputs verification
        includes the envelope as part of the codePart.
        """
        if self._code_script:
            return self._code_script
        code = self._build_code_script()
        if self._inscription:
            code += build_inscription_envelope(
                self._inscription.content_type,
                self._inscription.data,
            )
        return code

    def _adjust_code_sep_offset(self, base_offset: int) -> int:
        """Adjust code separator byte offset for constructor arg and codeSepIndex
        slot substitution. Both slot types replace OP_0 (1 byte) with encoded
        push data, shifting subsequent byte offsets."""
        shift = 0
        if self.artifact.constructor_slots:
            for slot in self.artifact.constructor_slots:
                if slot.byte_offset < base_offset:
                    encoded = _encode_arg(self._constructor_args[slot.param_index])
                    shift += len(encoded) // 2 - 1  # encoded bytes minus 1-byte placeholder
        # Account for codeSepIndex slot expansions
        for template_offset, adjusted_value in self._resolved_code_sep_slot_values():
            if template_offset < base_offset:
                encoded = _encode_script_number(adjusted_value)
                shift += len(encoded) // 2 - 1
        return base_offset + shift

    def _resolved_code_sep_slot_values(self) -> list[tuple[int, int]]:
        """Resolve the adjusted codeSep index values for all codeSepIndex slots,
        processing them in ascending template byte-offset order so that each
        slot's value correctly accounts for earlier slots' expansions."""
        if not self.artifact.code_sep_index_slots:
            return []
        # Sort by template byte offset ascending (left-to-right in the script)
        sorted_slots = sorted(self.artifact.code_sep_index_slots, key=lambda s: s.byte_offset)
        result: list[tuple[int, int]] = []
        for slot in sorted_slots:
            # Compute the fully-adjusted codeSep index: constructor expansion +
            # expansion from earlier codeSepIndex slots that precede this slot's codeSepIndex.
            shift = 0
            if self.artifact.constructor_slots:
                for cs in self.artifact.constructor_slots:
                    if cs.byte_offset < slot.code_sep_index:
                        encoded = _encode_arg(self._constructor_args[cs.param_index])
                        shift += len(encoded) // 2 - 1
            for prev_offset, prev_value in result:
                if prev_offset < slot.code_sep_index:
                    prev_encoded = _encode_script_number(prev_value)
                    shift += len(prev_encoded) // 2 - 1
            result.append((slot.byte_offset, slot.code_sep_index + shift))
        return result

    def _get_code_sep_index(self, method_index: int) -> int:
        """Get the byte offset of an OP_CODESEPARATOR for a method, or -1 if none.

        When ``_code_script`` is set (the contract is loaded from chain, or the
        deploy script has already been built from real constructor args), walk
        the actual script and return the true on-chain byte position. This is
        required because ``from_txid`` populates constructor args with dummy
        placeholders — the real arg bytes are already baked into the on-chain
        locking script — so ``_adjust_code_sep_offset`` computes a shift of zero
        and returns the wrong offset whenever the OP_CODESEPARATOR sits after
        constructor slots that expand at deploy time (e.g. PubKey args = 1 → 34
        bytes). The symptom of using the wrong offset is NULLFAIL at OP_CHECKSIG
        for terminal methods.

        Falls back to the legacy template-adjusted offset for synthetic /
        unit-test paths that have no ``_code_script`` available.
        """
        if self._code_script:
            if self.artifact.code_separator_indices:
                real_offsets = _find_codesep_offsets(self._code_script)
                if 0 <= method_index < len(self.artifact.code_separator_indices) and method_index < len(real_offsets):
                    return real_offsets[method_index]
            if self.artifact.code_separator_index is not None:
                real_offsets = _find_codesep_offsets(self._code_script)
                if real_offsets:
                    return real_offsets[0]

        if self.artifact.code_separator_indices and 0 <= method_index < len(self.artifact.code_separator_indices):
            return self._adjust_code_sep_offset(self.artifact.code_separator_indices[method_index])
        if self.artifact.code_separator_index is not None:
            return self._adjust_code_sep_offset(self.artifact.code_separator_index)
        return -1

    def _has_code_separator(self) -> bool:
        return self.artifact.code_separator_index is not None or bool(self.artifact.code_separator_indices)

    def _build_stateful_prefix(self, op_sig_hex: str, needs_code_part: bool) -> str:
        """Build prefix: optionally _codePart.

        BUG-100 fix: the OP_PUSH_TX signature is now derived on-chain from the
        preimage (see codegen _emit_check_preimage_binding), so NO signature is
        pushed here — the unlocking script carries only _codePart (if needed) and
        the preimage. The op_sig_hex parameter is retained for call-site
        compatibility but ignored.
        """
        del op_sig_hex  # no longer pushed; signature derived on-chain
        prefix = ''
        if needs_code_part and self._has_code_separator():
            prefix += encode_push_data(self._get_code_part_hex())
        return prefix

    def _find_method_index(self, name: str) -> int:
        """Find the index of a public method by name."""
        public_methods = self._get_public_methods()
        for i, m in enumerate(public_methods):
            if m.name == name:
                return i
        return 0

    # -- Private helpers --

    def _build_code_script(self) -> str:
        script = self.artifact.script

        has_constructor_slots = bool(self.artifact.constructor_slots)
        has_code_sep_slots = bool(self.artifact.code_sep_index_slots)

        if has_constructor_slots or has_code_sep_slots:
            # Build a unified list of all template slot substitutions, then
            # process them in descending byte-offset order so each splice
            # doesn't invalidate the positions of earlier (higher-offset) entries.
            subs: list[tuple[int, str]] = []

            # Constructor arg slots: replace OP_0 placeholder with encoded arg
            if has_constructor_slots:
                for slot in self.artifact.constructor_slots:
                    subs.append((
                        slot.byte_offset,
                        _encode_arg(self._constructor_args[slot.param_index]),
                    ))

            # CodeSepIndex slots: replace OP_0 placeholder with encoded adjusted
            # codeSeparatorIndex.
            if has_code_sep_slots:
                resolved = self._resolved_code_sep_slot_values()
                for template_offset, adjusted_value in resolved:
                    subs.append((
                        template_offset,
                        _encode_script_number(adjusted_value),
                    ))

            # Sort descending by byte offset and apply
            subs.sort(key=lambda s: s[0], reverse=True)
            for byte_offset, encoded in subs:
                hex_offset = byte_offset * 2
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

    def _method_sig_hash_type(self, method_name: str) -> int:
        """Issue #123: resolve the BIP-143 sighash type for ``method_name`` from
        the ABI (default 0x41 = ALL|FORKID). Drives both the OP_PUSH_TX binding
        derivation and the SDK-built BIP-143 preimage so they commit to the same
        fields the on-chain covenant expects.
        """
        for m in self.artifact.abi.methods:
            if m.name == method_name:
                return m.sig_hash_type if m.sig_hash_type is not None else 0x41
        return 0x41


# ---------------------------------------------------------------------------
# Argument encoding
# ---------------------------------------------------------------------------

def _revive_json_value(value, field_type: str):
    """Revive a value that may have been serialized as a BigInt string ("0n")
    when the artifact JSON was loaded without a custom reviver."""
    if isinstance(value, str) and field_type in ('bigint', 'int'):
        if value.endswith('n'):
            return int(value[:-1])
        return int(value)
    return value


def _unwrap_fixed_array_leaf_type(type_str: str) -> str:
    """Return the innermost scalar type of a nested FixedArray string."""
    current = type_str.strip()
    while current.startswith("FixedArray<"):
        inner = current[len("FixedArray<"):-1]
        depth = 0
        split_at = -1
        for i in range(len(inner) - 1, -1, -1):
            ch = inner[i]
            if ch == ">":
                depth += 1
            elif ch == "<":
                depth -= 1
            elif ch == "," and depth == 0:
                split_at = i
                break
        if split_at < 0:
            return current
        current = inner[:split_at].strip()
    return current


def _deep_revive(value, leaf_type: str):
    """Revive nested arrays of bigint strings to Python ints."""
    if isinstance(value, list):
        return [_deep_revive(v, leaf_type) for v in value]
    return _revive_json_value(value, leaf_type)


def _flatten_fixed_array_state(state: dict, state_fields: list) -> dict:
    """Expand grouped FixedArray state into synthetic scalar leaves.

    The ANF interpreter only knows the expanded scalar property names
    (``board__0..board__8``). Callers keep the user-facing grouped form
    (``board = [...]``) so we have to flatten on the way in.
    """
    out = dict(state)
    if not state_fields:
        return out
    for field in state_fields:
        fa = getattr(field, 'fixed_array', None)
        if not fa:
            continue
        value = state.get(field.name)
        if not isinstance(value, (list, tuple)):
            continue
        dims = _parse_fixed_array_dims(field.type)
        flat = _flatten_nested(value, dims)
        synthetic_names = fa['syntheticNames']
        for i, synth in enumerate(synthetic_names):
            if synth not in out:
                out[synth] = flat[i]
    return out


def _regroup_fixed_array_state(state: dict, state_fields: list) -> dict:
    """Rebuild grouped FixedArray entries from synthetic scalar leaves."""
    out = dict(state)
    if not state_fields:
        return out
    for field in state_fields:
        fa = getattr(field, 'fixed_array', None)
        if not fa:
            continue
        synthetic_names = fa['syntheticNames']
        flat: list = [None] * len(synthetic_names)
        saw_any = False
        for i, synth in enumerate(synthetic_names):
            if synth in out:
                flat[i] = out[synth]
                saw_any = True
        if not saw_any:
            continue
        prior = state.get(field.name)
        dims = _parse_fixed_array_dims(field.type)
        if isinstance(prior, (list, tuple)):
            prior_flat = _flatten_nested(prior, dims)
            for i in range(len(flat)):
                if flat[i] is None:
                    flat[i] = prior_flat[i]
        rebuilt, _ = _regroup_nested(flat, dims)
        out[field.name] = rebuilt
    return out


def _flatten_fixed_array_args(args: list, abi_params: list) -> list:
    """Expand grouped FixedArray constructor args to positional leaves."""
    out: list = []
    for i, value in enumerate(args):
        param = abi_params[i] if i < len(abi_params) else None
        if (
            param is not None
            and getattr(param, 'fixed_array', None)
            and isinstance(value, (list, tuple))
        ):
            dims = _parse_fixed_array_dims(param.type)
            if dims:
                out.extend(_flatten_nested(value, dims))
            else:
                out.extend(list(value))
        else:
            out.append(value)
    return out


def _normalize_witness_bytes(value) -> str:
    """Normalize a witness-value input (hex string or bytes-like) into a
    lowercase hex string suitable for ``encode_push_data``. Hex inputs may
    optionally carry a ``0x`` prefix and any casing.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if not isinstance(value, str):
        raise TypeError(
            f"witness value: expected str or bytes-like, got {type(value).__name__}"
        )
    h = value
    if h.startswith(('0x', '0X')):
        h = h[2:]
    if len(h) % 2 != 0:
        raise ValueError(
            f"witness value: hex string must have even length (got {len(h)})"
        )
    try:
        int(h, 16) if h else None
    except ValueError as exc:
        raise ValueError("witness value: invalid hex characters") from exc
    return h.lower()


def _encode_arg(value) -> str:
    if is_empty_sig(value):
        # OP_0 — empty signature push for the failing OR-CHECKSIG branch (#106).
        return '00'
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


def _build_named_args(user_params: list, resolved_args: list) -> dict:
    """Map positional resolved_args to a dict keyed by parameter name."""
    result: dict = {}
    for i, param in enumerate(user_params):
        if i < len(resolved_args):
            result[param.name] = resolved_args[i]
    return result


def _find_codesep_offsets(script_hex: str) -> list[int]:
    """Walk a hex-encoded script and return the byte offsets of every
    OP_CODESEPARATOR (0xab) that sits at a real opcode boundary (i.e. not inside
    push-data). Correctly skips all BSV push opcodes (0x01..0x4b,
    OP_PUSHDATA1/2/4).

    Used by ``_get_code_sep_index`` to recover the true on-chain byte offsets
    when the in-memory constructor args don't reflect what was actually baked
    into the locking script (e.g. after ``from_txid`` populates dummy
    placeholders).
    """
    out: list[int] = []
    off = 0
    n = len(script_hex)

    def _b(i: int) -> int:
        try:
            return int(script_hex[i:i + 2], 16)
        except ValueError:
            return 0

    while off + 2 <= n:
        op = _b(off)
        byte_pos = off // 2
        if op == 0xAB:
            out.append(byte_pos)
            off += 2
        elif 0x01 <= op <= 0x4B:
            off += 2 + op * 2
        elif op == 0x4C:
            if off + 4 > n:
                break
            push_len = _b(off + 2)
            off += 4 + push_len * 2
        elif op == 0x4D:
            if off + 6 > n:
                break
            lo = _b(off + 2)
            hi = _b(off + 4)
            push_len = lo | (hi << 8)
            off += 6 + push_len * 2
        elif op == 0x4E:
            if off + 10 > n:
                break
            b0 = _b(off + 2)
            b1 = _b(off + 4)
            b2 = _b(off + 6)
            b3 = _b(off + 8)
            push_len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
            off += 10 + push_len * 2
        else:
            off += 2
    return out


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
