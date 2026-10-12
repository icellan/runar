// Shared missing-driver gate for the three ANF cross-interpreter suites
// (cross-interpreter.test.ts, -strict, -real-crypto).
//
// Policy (N-166):
//   - CI: a missing driver FAILS the suite at load. "CI" means `CI` is set to
//     anything but '', '0' or 'false' (case-insensitive) — not only the
//     literal 'true' GitHub sets — or GITHUB_ACTIONS=true. A runner exporting
//     CI=1 used to drop tiers silently.
//   - RUNAR_ANF_DRIVERS_STRICT=1: same hard failure locally (checkpoints).
//   - Otherwise: the suite skips that driver's describe block and warns once
//     per missing driver, by name, with its setup hint, so the dropped tier
//     is visible rather than an anonymous "skipped" count. Inventoried in
//     docs/test-skips.md.
//
// Kept out of the suites so the gate can be unit-tested against an injected
// env without spawning drivers (driver-gate.test.ts).

export interface GateDriver {
  name: string;
  setupHint: string;
}

type Env = Record<string, string | undefined>;

export function isCiEnv(env: Env): boolean {
  const ci = env.CI;
  if (ci !== undefined && !['', '0', 'false'].includes(ci.toLowerCase())) return true;
  return env.GITHUB_ACTIONS === 'true';
}

export function driversRequired(env: Env): boolean {
  return isCiEnv(env) || env.RUNAR_ANF_DRIVERS_STRICT === '1';
}

/**
 * Throws when drivers are required (CI / strict) and any is missing;
 * otherwise warns once per missing driver.
 */
export function enforceDriverGate(
  label: string,
  missing: readonly GateDriver[],
  env: Env,
  warn: (line: string) => void = console.warn,
): void {
  if (missing.length === 0) return;
  if (driversRequired(env)) {
    throw new Error(
      `${label} drivers missing in CI / strict mode: ${missing.map(c => c.name).join(', ')}.\n` +
      missing.map(c => `  - ${c.name}: ${c.setupHint}`).join('\n'),
    );
  }
  for (const c of missing) {
    warn(
      `WARNING: ${label}: ${c.name} driver not built — its tier is SKIPPED, not verified. ` +
      `${c.setupHint} Set RUNAR_ANF_DRIVERS_STRICT=1 to fail instead.`,
    );
  }
}
