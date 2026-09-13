/**
 * R-062 / CL-BUG-105 — deploy-time gate on builtins the project does not claim
 * are sound.
 *
 * The compiler refuses to emit a script reaching `verifySP1FRI` unless the
 * author wrote `@acknowledgeUnsoundSP1FriVerifier` or the invoker passed
 * `--acknowledge-unsound-sp1-fri` (R-012). That acknowledgement stopped at
 * whoever ran the compiler: the artifact handed on afterwards looked like any
 * other, carried no marker of the gap, and every SDK funded it in silence —
 * which is how an acknowledged proof-of-concept verifier reaches a
 * value-bearing deployment with no friction.
 *
 * The compiler now stamps `unsoundPrimitives` into the artifact. This guard is
 * the SDK half: every deploy path calls it BEFORE any signing or broadcast, and
 * the caller must name each listed primitive to proceed.
 *
 * Deploy only, deliberately. Spending an already-deployed contract is how funds
 * are RECOVERED from one, and refusing that would strand coins whose risk was
 * taken at deploy time. The friction belongs where the value first enters.
 */

import type { RunarArtifact } from 'runar-ir-schema';

/**
 * Throw unless every unsound primitive the artifact declares appears in
 * `acknowledged`.
 *
 * @param artifact     the artifact about to be funded
 * @param acknowledged primitives the caller explicitly accepts (DeployOptions.acknowledgeUnsound)
 * @param context      call site for the message, e.g. `"Counter.deploy"`
 */
export function assertUnsoundPrimitivesAcknowledged(
  artifact: RunarArtifact,
  acknowledged: readonly string[] | undefined,
  context: string,
): void {
  const declared = artifact.unsoundPrimitives ?? [];
  if (declared.length === 0) return;

  const ok = new Set(acknowledged ?? []);
  const missing = declared.filter((p) => !ok.has(p));
  if (missing.length === 0) return;

  throw new Error(
    `${context}: this artifact reaches ${missing.length} builtin${missing.length === 1 ? '' : 's'} ` +
      `the compiler does not claim is sound: ${missing.join(', ')}. ` +
      `The compiler emitted it only because the gap was acknowledged at COMPILE time; ` +
      `funding it is a second decision, and this SDK will not make it for you. ` +
      `Pass acknowledgeUnsound: [${missing.map((p) => `'${p}'`).join(', ')}] to proceed.`,
  );
}
