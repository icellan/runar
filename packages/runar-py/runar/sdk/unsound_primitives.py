"""R-062 / CL-BUG-105 — deploy-time gate on builtins the project does not claim
are sound.

The compiler refuses to emit a script reaching ``verifySP1FRI`` unless the
author wrote ``@acknowledgeUnsoundSP1FriVerifier`` or the invoker passed
``--acknowledge-unsound-sp1-fri`` (R-012). That acknowledgement stopped at
whoever ran the compiler: the artifact handed on afterwards looked like any
other, carried no marker of the gap, and every SDK funded it in silence — which
is how an acknowledged proof-of-concept verifier reaches a value-bearing
deployment with no friction.

The compiler now stamps ``unsoundPrimitives`` into the artifact. This guard is
the SDK half: the deploy path calls it BEFORE any signing or broadcast, and the
caller must name each listed primitive to proceed.

Deploy only, deliberately. Spending an already-deployed contract is how funds
are RECOVERED from one, and refusing that would strand coins whose risk was
taken at deploy time. The friction belongs where the value first enters.
"""

from __future__ import annotations

from typing import Sequence


def assert_unsound_primitives_acknowledged(
    artifact,
    acknowledged: Sequence[str] | None,
    context: str,
) -> None:
    """Raise ``RuntimeError`` unless every unsound primitive the artifact
    declares appears in *acknowledged*."""
    declared = list(getattr(artifact, 'unsound_primitives', None) or [])
    if not declared:
        return

    ok = set(acknowledged or ())
    missing = [p for p in declared if p not in ok]
    if not missing:
        return

    plural = '' if len(missing) == 1 else 's'
    quoted = ', '.join(f"'{m}'" for m in missing)
    raise RuntimeError(
        f"{context}: this artifact reaches {len(missing)} builtin{plural} the compiler "
        f"does not claim is sound: {', '.join(missing)}. The compiler emitted it only "
        f"because the gap was acknowledged at COMPILE time; funding it is a second "
        f"decision, and this SDK will not make it for you. Pass "
        f"DeployOptions(acknowledge_unsound=[{quoted}]) to proceed"
    )
