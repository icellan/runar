"""Runar SDK — native Python code generation from compiled artifacts.

Generates typed Python wrapper classes from RunarArtifact, mirroring the
template-based approach used by the TypeScript SDK.  Zero external
dependencies (only ``re`` and ``typing`` from stdlib).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Union

from runar.sdk.types import RunarArtifact, AbiMethod, AbiParam

# ---------------------------------------------------------------------------
# Minimal Mustache renderer
# ---------------------------------------------------------------------------
# Supports: {{var}}, {{#section}}...{{/section}}, {{^section}}...{{/section}}
# No HTML escaping, no partials, no lambdas.

Context = Dict[str, Any]


def _resolve(context: Context, key: str) -> Any:
    """Resolve a dotted key against a context dict."""
    if key == '.':
        return context.get('.')
    parts = key.split('.')
    current: Any = context
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


_SECTION_RE = re.compile(
    r'\{\{([#^])(\w+(?:\.\w+)*)\}\}([\s\S]*?)\{\{/\2\}\}'
)
_VAR_RE = re.compile(r'\{\{(\w+(?:\.\w+)*|\.)\}\}')


def _render_section(template: str, context: Context) -> str:
    """Render sections and variable interpolation."""

    result = template
    changed = True
    while changed:
        changed = False

        def _replace_section(m: re.Match) -> str:  # type: ignore[type-arg]
            nonlocal changed
            changed = True
            section_type = m.group(1)
            key = m.group(2)
            body = m.group(3)
            value = _resolve(context, key)

            if section_type == '^':
                # Inverted section: render if falsy / empty list
                if not value or (isinstance(value, list) and len(value) == 0):
                    return _render_section(body, context)
                return ''

            # Normal section
            if isinstance(value, list):
                parts: list[str] = []
                for item in value:
                    if isinstance(item, dict):
                        merged = {**context, **item}
                        parts.append(_render_section(body, merged))
                    else:
                        parts.append(_render_section(body, {**context, '.': item}))
                return ''.join(parts)

            if value and isinstance(value, dict):
                return _render_section(body, {**context, **value})

            if value:
                return _render_section(body, context)

            return ''

        result = _SECTION_RE.sub(_replace_section, result)

    # Variable interpolation
    def _replace_var(m: re.Match) -> str:  # type: ignore[type-arg]
        key = m.group(1)
        value = _resolve(context, key)
        if value is None:
            return ''
        return str(value)

    result = _VAR_RE.sub(_replace_var, result)
    return result


def render_mustache(template: str, context: Context) -> str:
    """Render a Mustache template with the given context."""
    return _render_section(template, context)


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------

_PYTHON_TYPE_MAP: Dict[str, str] = {
    'bigint': 'int',
    'boolean': 'bool',
    'Sig': 'str',
    'PubKey': 'str',
    'ByteString': 'str',
    'Addr': 'str',
    'Ripemd160': 'str',
    'Sha256': 'str',
    'Point': 'str',
    'SigHashPreimage': 'str',
}


def _map_type(abi_type: str) -> str:
    """Map an ABI type string to a Python type annotation string."""
    return _PYTHON_TYPE_MAP.get(abi_type, 'Any')


# ---------------------------------------------------------------------------
# Name conversion utilities
# ---------------------------------------------------------------------------

def _to_snake_case(name: str) -> str:
    """Convert camelCase to snake_case: 'releaseBySeller' -> 'release_by_seller'."""
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s)
    return s.lower()


def _to_pascal_case(name: str) -> str:
    """Convert camelCase to PascalCase: 'releaseBySeller' -> 'ReleaseBySeller'."""
    return name[0].upper() + name[1:] if name else name


_SNAKE_RESERVED = {'connect', 'deploy', 'contract', 'get_locking_script'}


def _safe_method_name(name: str) -> str:
    """Generate a safe snake_case method name, avoiding collisions with wrapper class methods."""
    snake = _to_snake_case(name)
    if snake in _SNAKE_RESERVED:
        return f'call_{snake}'
    return snake


# ---------------------------------------------------------------------------
# Param classification
# ---------------------------------------------------------------------------

def _classify_params(method: AbiMethod, is_stateful: bool) -> List[Dict[str, Any]]:
    """Classify method params into user-visible and hidden (auto-computed)."""
    result: List[Dict[str, Any]] = []
    for p in method.params:
        hidden = (
            p.type == 'Sig' or
            (is_stateful and (
                p.type == 'SigHashPreimage' or
                p.name == '_changePKH' or
                p.name == '_changeAmount' or
                p.name == '_newAmount'
            ))
        )
        result.append({
            'name': p.name,
            'abi_type': p.type,
            'py_type': _map_type(p.type),
            'hidden': hidden,
        })
    return result


def _get_user_params(method: AbiMethod, is_stateful: bool) -> List[Dict[str, Any]]:
    """Get only user-visible params for a method."""
    return [p for p in _classify_params(method, is_stateful) if not p['hidden']]


def _get_sdk_arg_params(method: AbiMethod, is_stateful: bool) -> List[Dict[str, Any]]:
    """Get params that match the SDK's args array.

    All params except SigHashPreimage, _changePKH, _changeAmount, _newAmount
    for stateful contracts.  Sig params ARE included (passed as None).
    """
    classified = _classify_params(method, is_stateful)
    if not is_stateful:
        return classified
    return [
        p for p in classified
        if p['abi_type'] != 'SigHashPreimage'
        and p['name'] != '_changePKH'
        and p['name'] != '_changeAmount'
        and p['name'] != '_newAmount'
    ]


# ---------------------------------------------------------------------------
# Terminal detection
# ---------------------------------------------------------------------------

def _is_terminal_method(method: AbiMethod, is_stateful: bool) -> bool:
    """Determine if a method is terminal (no state continuation output).

    Uses the explicit is_terminal attribute if present, falls back to
    checking for absence of _changePKH in the params.
    """
    if not is_stateful:
        return True
    # Check for explicit is_terminal attribute
    if hasattr(method, 'is_terminal') and method.is_terminal is not None:  # type: ignore[attr-defined]
        return method.is_terminal  # type: ignore[attr-defined]
    # Fallback: terminal if no _changePKH param
    return not any(p.name == '_changePKH' for p in method.params)


# ---------------------------------------------------------------------------
# Artifact analysis
# ---------------------------------------------------------------------------

def _is_stateful_artifact(artifact: RunarArtifact) -> bool:
    return len(artifact.state_fields) > 0


def _get_public_methods(artifact: RunarArtifact) -> List[AbiMethod]:
    return [m for m in artifact.abi.methods if m.is_public]


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _build_codegen_context(artifact: RunarArtifact) -> Context:
    """Build a Mustache template context dict from a RunarArtifact."""
    is_stateful = _is_stateful_artifact(artifact)
    public_methods = _get_public_methods(artifact)

    has_stateful_methods = is_stateful and any(
        not _is_terminal_method(m, is_stateful) for m in public_methods
    )
    has_terminal_methods = any(
        _is_terminal_method(m, is_stateful) for m in public_methods
    )

    # Constructor params
    ctor_params = artifact.abi.constructor_params
    constructor_params: List[Dict[str, Any]] = []
    for i, p in enumerate(ctor_params):
        constructor_params.append({
            'name': _to_snake_case(p.name),
            'type': _map_type(p.type),
            'abiType': p.type,
            'isLast': i == len(ctor_params) - 1,
        })

    has_big_int_params = any(p.type == 'bigint' for p in ctor_params)

    # Constructor args expression
    constructor_args_expr = ', '.join(p['name'] for p in constructor_params)

    # Methods
    methods: List[Dict[str, Any]] = []
    for method in public_methods:
        user_params_raw = _get_user_params(method, is_stateful)
        sdk_args_raw = _get_sdk_arg_params(method, is_stateful)
        terminal = _is_terminal_method(method, is_stateful)
        method_name = _safe_method_name(method.name)

        # User params
        user_params: List[Dict[str, Any]] = []
        for i, p in enumerate(user_params_raw):
            user_params.append({
                'name': _to_snake_case(p['name']),
                'type': p['py_type'],
                'abiType': p['abi_type'],
                'isLast': i == len(user_params_raw) - 1,
            })

        if any(p['abi_type'] == 'bigint' for p in user_params_raw):
            has_big_int_params = True

        # SDK args expression
        sdk_args_parts: List[str] = []
        for p in sdk_args_raw:
            if p['hidden']:
                sdk_args_parts.append('None')
            else:
                sdk_args_parts.append(_to_snake_case(p['name']))
        sdk_args_expr = ', '.join(sdk_args_parts)

        # Sig params (for prepare/finalize)
        sig_params_raw = [p for p in sdk_args_raw if p['abi_type'] == 'Sig']
        sig_params: List[Dict[str, Any]] = []
        for i, sp in enumerate(sig_params_raw):
            idx = next(
                j for j, p in enumerate(sdk_args_raw) if p['name'] == sp['name']
            )
            sig_params.append({
                'name': _to_snake_case(sp['name']),
                'argIndex': idx,
                'isLast': i == len(sig_params_raw) - 1,
            })

        sig_entries_expr = ', '.join(
            f'{sp["argIndex"]}: {sp["name"]}' for sp in sig_params
        )

        # Prepare params (user params minus Sig)
        prepare_user_params = [p for p in user_params if p['abiType'] != 'Sig']
        for i in range(len(prepare_user_params)):
            prepare_user_params[i] = {
                **prepare_user_params[i],
                'isLast': i == len(prepare_user_params) - 1,
            }

        capitalized_name = _to_pascal_case(method.name)

        methods.append({
            'originalName': method.name,
            'name': method_name,
            'capitalizedName': capitalized_name,
            'isTerminal': terminal,
            'isStatefulMethod': not terminal and is_stateful,
            'hasSigParams': len(sig_params) > 0,
            'hasUserParams': len(user_params) > 0,
            'userParams': user_params,
            'sdkArgsExpr': sdk_args_expr,
            'sigParams': sig_params,
            'sigEntriesExpr': sig_entries_expr,
            'hasPrepareUserParams': len(prepare_user_params) > 0,
            'prepareUserParams': prepare_user_params,
        })

    return {
        'contractName': artifact.contract_name,
        'contractNameSnake': _to_snake_case(artifact.contract_name),
        'isStateful': is_stateful,
        'hasStatefulMethods': has_stateful_methods,
        'hasTerminalMethods': has_terminal_methods,
        'hasConstructorParams': len(constructor_params) > 0,
        'hasBigIntParams': has_big_int_params,
        'constructorParams': constructor_params,
        'constructorArgsExpr': constructor_args_expr,
        'methods': methods,
    }


# ---------------------------------------------------------------------------
# Python template (embedded from codegen/templates/wrapper.py.mustache)
# ---------------------------------------------------------------------------

_PYTHON_TEMPLATE = (
    '# Generated by: runar codegen\n'
    '# Source: {{contractName}}\n'
    '# Do not edit manually.\n'
    '\n'
    'from __future__ import annotations\n'
    'from dataclasses import dataclass, field\n'
    'from typing import Optional, Any\n'
    '\n'
    'from runar.sdk import (\n'
    '    RunarContract, RunarArtifact, Provider, Signer,\n'
    '    TransactionData, DeployOptions, CallOptions, PreparedCall,\n'
    '    TerminalOutput as SdkTerminalOutput,\n'
    ')\n'
    'from runar.sdk.deployment import build_p2pkh_script\n'
    '\n'
    '\n'
    '{{#hasTerminalMethods}}'
    '@dataclass\n'
    'class TerminalOutput:\n'
    '    """Terminal output -- accepts address (converted to P2PKH) or raw script_hex."""\n'
    '    satoshis: int\n'
    '    address: str = \'\'\n'
    '    script_hex: str = \'\'\n'
    '\n'
    '\n'
    'def _resolve_outputs(outputs: list[TerminalOutput]) -> list[SdkTerminalOutput]:\n'
    '    resolved = []\n'
    '    for o in outputs:\n'
    '        script_hex = o.script_hex or build_p2pkh_script(o.address)\n'
    '        resolved.append(SdkTerminalOutput(script_hex=script_hex, satoshis=o.satoshis))\n'
    '    return resolved\n'
    '\n'
    '\n'
    '{{/hasTerminalMethods}}'
    '{{#hasStatefulMethods}}'
    '@dataclass\n'
    'class {{contractName}}StatefulCallOptions:\n'
    '    """Options for stateful method calls on {{contractName}}."""\n'
    '    satoshis: int = 0\n'
    '    change_address: str = \'\'\n'
    '    change_pub_key: str = \'\'\n'
    '    new_state: dict | None = None\n'
    '    outputs: list[dict] | None = None\n'
    '\n'
    '    def _to_call_options(self) -> CallOptions:\n'
    '        return CallOptions(\n'
    '            satoshis=self.satoshis or None,\n'
    '            change_address=self.change_address or None,\n'
    '            change_pub_key=self.change_pub_key or None,\n'
    '            new_state=self.new_state,\n'
    '            outputs=self.outputs,\n'
    '        )\n'
    '\n'
    '\n'
    '{{/hasStatefulMethods}}'
    'class {{contractName}}Contract:\n'
    '    """Typed wrapper for the {{contractName}} contract."""\n'
    '\n'
    '{{#hasConstructorParams}}'
    '    def __init__(self, artifact: RunarArtifact, *, {{#constructorParams}}{{name}}: {{type}}{{^isLast}}, {{/isLast}}{{/constructorParams}}):\n'
    '        self._inner = RunarContract(artifact, [{{constructorArgsExpr}}])\n'
    '{{/hasConstructorParams}}'
    '{{^hasConstructorParams}}'
    '    def __init__(self, artifact: RunarArtifact):\n'
    '        self._inner = RunarContract(artifact, [])\n'
    '{{/hasConstructorParams}}'
    '\n'
    '    @classmethod\n'
    '    def from_txid(\n'
    '        cls,\n'
    '        artifact: RunarArtifact,\n'
    '        txid: str,\n'
    '        output_index: int,\n'
    '        provider: Provider,\n'
    '    ) -> {{contractName}}Contract:\n'
    '        inner = RunarContract.from_txid(artifact, txid, output_index, provider)\n'
    '        instance = cls.__new__(cls)\n'
    '        instance._inner = inner\n'
    '        return instance\n'
    '\n'
    '    def connect(self, provider: Provider, signer: Signer) -> None:\n'
    '        self._inner.connect(provider, signer)\n'
    '\n'
    '    def deploy(\n'
    '        self,\n'
    '        provider: Provider | None = None,\n'
    '        signer: Signer | None = None,\n'
    '        options: DeployOptions | None = None,\n'
    '    ) -> tuple[str, TransactionData]:\n'
    '        return self._inner.deploy(provider, signer, options)\n'
    '\n'
    '    def get_locking_script(self) -> str:\n'
    '        return self._inner.get_locking_script()\n'
    '\n'
    '    @property\n'
    '    def contract(self) -> RunarContract:\n'
    '        return self._inner\n'
    '\n'
    '{{#methods}}'
    '    def {{name}}(\n'
    '        self,\n'
    '{{#userParams}}'
    '        {{name}}: {{type}},\n'
    '{{/userParams}}'
    '{{#isStatefulMethod}}'
    '        options: {{contractName}}StatefulCallOptions | None = None,\n'
    '{{/isStatefulMethod}}'
    '{{#isTerminal}}'
    '        outputs: list[TerminalOutput] | None = None,\n'
    '{{/isTerminal}}'
    '        provider: Provider | None = None,\n'
    '        signer: Signer | None = None,\n'
    '    ) -> tuple[str, TransactionData]:\n'
    '{{#isTerminal}}'
    '        call_opts = CallOptions(terminal_outputs=_resolve_outputs(outputs)) if outputs else None\n'
    "        return self._inner.call('{{originalName}}', [{{sdkArgsExpr}}], provider, signer, call_opts)\n"
    '{{/isTerminal}}'
    '{{#isStatefulMethod}}'
    '        call_opts = options._to_call_options() if options else None\n'
    "        return self._inner.call('{{originalName}}', [{{sdkArgsExpr}}], provider, signer, call_opts)\n"
    '{{/isStatefulMethod}}'
    '\n'
    '{{#hasSigParams}}'
    '    def prepare_{{name}}(\n'
    '        self,\n'
    '{{#prepareUserParams}}'
    '        {{name}}: {{type}},\n'
    '{{/prepareUserParams}}'
    '{{#isStatefulMethod}}'
    '        options: {{contractName}}StatefulCallOptions | None = None,\n'
    '{{/isStatefulMethod}}'
    '{{#isTerminal}}'
    '        outputs: list[TerminalOutput] | None = None,\n'
    '{{/isTerminal}}'
    '        provider: Provider | None = None,\n'
    '        signer: Signer | None = None,\n'
    '    ) -> PreparedCall:\n'
    '{{#isTerminal}}'
    '        call_opts = CallOptions(terminal_outputs=_resolve_outputs(outputs)) if outputs else None\n'
    "        return self._inner.prepare_call('{{originalName}}', [{{sdkArgsExpr}}], provider, signer, call_opts)\n"
    '{{/isTerminal}}'
    '{{#isStatefulMethod}}'
    '        call_opts = options._to_call_options() if options else None\n'
    "        return self._inner.prepare_call('{{originalName}}', [{{sdkArgsExpr}}], provider, signer, call_opts)\n"
    '{{/isStatefulMethod}}'
    '\n'
    '    def finalize_{{name}}(\n'
    '        self,\n'
    '        prepared: PreparedCall,\n'
    '{{#sigParams}}'
    '        {{name}}: str,\n'
    '{{/sigParams}}'
    '        provider: Provider | None = None,\n'
    '    ) -> tuple[str, TransactionData]:\n'
    '        return self._inner.finalize_call(prepared, { {{sigEntriesExpr}} }, provider)\n'
    '\n'
    '{{/hasSigParams}}'
    '{{/methods}}'
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_python(artifact: RunarArtifact) -> str:
    """Generate a typed Python wrapper class from a compiled Runar artifact.

    The generated class wraps ``RunarContract`` and exposes typed methods
    for each public contract method, with appropriate options types for
    terminal vs state-mutating methods.

    Args:
        artifact: A compiled ``RunarArtifact``.

    Returns:
        A string containing the generated Python source code.
    """
    context = _build_codegen_context(artifact)
    return render_mustache(_PYTHON_TEMPLATE, context)
