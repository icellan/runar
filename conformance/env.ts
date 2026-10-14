// Shared CI-detection predicate for conformance/.
//
// Moved here from anf-interpreter/driver-gate.ts (N-250): isCiEnv started
// life as a helper for the ANF cross-interpreter driver gate (N-166), but
// after the N-236 sweep it was imported by ~44 unrelated conformance suites
// plus analyzer/run.ts and runner/runner.ts — none of which care about ANF
// drivers. This file is the neutral home; driver-gate.ts re-exports isCiEnv
// for backward compatibility only.
//
// "CI" means `CI` is set to anything but '', '0' or 'false' (case-
// insensitive) — not only the literal 'true' GitHub sets — or
// GITHUB_ACTIONS=true. A runner exporting CI=1 used to drop tiers silently.

export type Env = Record<string, string | undefined>;

export function isCiEnv(env: Env): boolean {
  const ci = env.CI;
  if (ci !== undefined && !['', '0', 'false'].includes(ci.toLowerCase())) return true;
  return env.GITHUB_ACTIONS === 'true';
}
