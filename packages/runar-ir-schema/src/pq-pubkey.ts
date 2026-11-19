/**
 * D12 PQ-F1: public-key lengths the post-quantum verifiers require.
 *
 * `verifyWOTS(msg, sig, pk)` splits `pk` as pubSeed(32) || pkRoot(32)
 * (wots-codegen.ts), and `verifySLHDSA_SHA2_*(msg, sig, pk)` as
 * PK.seed(n) || PK.root(n) with n = 16 / 24 / 32 (slh-dsa-codegen.ts). A key of
 * any other length deploys fine and then refuses every honest signature, so
 * the output is unspendable. Callers check a constructor value that flows
 * DIRECTLY (as a property load) into the verifier's pk operand; a key that is
 * only committed by hash cannot be checked before the spend.
 */
import type { ANFBinding, ANFProgram } from './anf-ir.js';

export const PQ_PUBKEY_BYTES: Readonly<Record<string, number>> = {
  verifyWOTS: 64,
  verifySLHDSA_SHA2_128s: 32,
  verifySLHDSA_SHA2_128f: 32,
  verifySLHDSA_SHA2_192s: 48,
  verifySLHDSA_SHA2_192f: 48,
  verifySLHDSA_SHA2_256s: 64,
  verifySLHDSA_SHA2_256f: 64,
};

export interface PqPubKeyRequirement {
  /** Property (constructor parameter) whose value is the verifier's pk. */
  property: string;
  /** Verifier builtin name. */
  verifier: string;
  /** Required byte length. */
  bytes: number;
}

/**
 * Every property that reaches a PQ verifier's pk operand directly, with the
 * length that verifier needs. Walks nested if / loop bodies and follows
 * `@ref:` aliases.
 */
export function pqPubKeyRequirements(anf: ANFProgram): PqPubKeyRequirement[] {
  const out: PqPubKeyRequirement[] = [];
  const seen = new Set<string>();
  for (const method of anf.methods) {
    const propOf = new Map<string, string>();
    const walk = (bindings: ANFBinding[]): void => {
      for (const b of bindings) {
        const v = b.value as unknown as Record<string, unknown>;
        if (v.kind === 'load_prop' && typeof v.name === 'string') {
          propOf.set(b.name, v.name);
        } else if (v.kind === 'load_const' && typeof v.value === 'string' && v.value.startsWith('@ref:')) {
          const target = propOf.get(v.value.slice('@ref:'.length));
          if (target !== undefined) propOf.set(b.name, target);
        } else if (v.kind === 'call' && typeof v.func === 'string' && v.func in PQ_PUBKEY_BYTES) {
          const args = v.args as string[] | undefined;
          const prop = args && args[2] !== undefined ? propOf.get(args[2]) : undefined;
          if (prop !== undefined) {
            const key = `${prop}\u0000${v.func}`;
            if (!seen.has(key)) {
              seen.add(key);
              out.push({ property: prop, verifier: v.func, bytes: PQ_PUBKEY_BYTES[v.func]! });
            }
          }
        }
        for (const nested of ['then', 'else', 'body'] as const) {
          const n = v[nested];
          if (Array.isArray(n)) walk(n as ANFBinding[]);
        }
      }
    };
    walk(method.body);
  }
  return out;
}

/**
 * The refusal message for a wrong-length PQ public key, or null when the
 * value is fine (or not a hex string — other checks own that case).
 */
export function pqPubKeyLengthError(req: PqPubKeyRequirement, value: unknown): string | null {
  if (typeof value !== 'string' || value.length % 2 !== 0) return null;
  const got = value.length / 2;
  if (got === req.bytes) return null;
  return (
    `'${req.property}' is passed as the public key of ${req.verifier}, which needs exactly ` +
    `${req.bytes} bytes, but the value is ${got} bytes. A locking script built from it would ` +
    `refuse every valid signature, so the output could never be spent.`
  );
}
