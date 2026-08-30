/**
 * Regenerate `conformance/ec-flag-parity/expected.json` from the TypeScript
 * reference compiler.
 *
 * Derived artifact — never hand-edit the JSON. See that directory's README.
 */
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const compiler = join(here, '..', '..', 'packages', 'runar-compiler', 'dist', 'index.js');
const C = await import(compiler);

/** Every EC / NIST-curve emitter the flags can reach. */
const EMITTERS = {
  EcAdd: C.emitEcAdd, EcMul: C.emitEcMul, EcMulGen: C.emitEcMulGen,
  EcNegate: C.emitEcNegate, EcOnCurve: C.emitEcOnCurve,
  EcModReduce: C.emitEcModReduce, EcEncodeCompressed: C.emitEcEncodeCompressed,
  EcMakePoint: C.emitEcMakePoint, EcPointX: C.emitEcPointX, EcPointY: C.emitEcPointY,
  P256Add: C.emitP256Add, P256Mul: C.emitP256Mul, P256MulGen: C.emitP256MulGen,
  P256Negate: C.emitP256Negate, P256OnCurve: C.emitP256OnCurve,
  P256EncodeCompressed: C.emitP256EncodeCompressed,
  VerifyECDSA_P256: C.emitVerifyECDSA_P256,
  P384Add: C.emitP384Add, P384Mul: C.emitP384Mul, P384MulGen: C.emitP384MulGen,
  P384Negate: C.emitP384Negate, P384OnCurve: C.emitP384OnCurve,
  P384EncodeCompressed: C.emitP384EncodeCompressed,
  VerifyECDSA_P384: C.emitVerifyECDSA_P384,
};

/**
 * The flag combinations a user can actually select. `sink` includes the pool
 * because the cheap subtraction references the prime twice — without a pooled
 * slot it is a regression, so the compiler never offers sinking alone.
 */
export const VARIANTS = {
  off: {},
  pool: { constantPool: true },
  sink: { constantPool: true, reductionSinking: true },
  comb: { constantPool: true, reductionSinking: true, fixedBaseComb: true },
};

function measure(scriptHex) {
  return {
    bytes: scriptHex.length / 2,
    sha256: createHash('sha256').update(Buffer.from(scriptHex, 'hex')).digest('hex'),
  };
}

export function buildParity() {
  const out = { variants: VARIANTS, emitters: {} };
  for (const [name, emit] of Object.entries(EMITTERS)) {
    out.emitters[name] = {};
    for (const [vn, vo] of Object.entries(VARIANTS)) {
      const ops = [];
      emit(op => ops.push(op), vo);
      const raw = measure(C.emitMethod({ name: 't', ops }).scriptHex);
      // Post-peephole bytes: what the compiler actually ships.
      //
      // Six tiers reproduce the RAW emitter output op for op, so the raw hash is
      // the sharpest gate available to them. The Zig tier cannot: its peephole
      // folds only i64 `push_int` chains, so it emits `k + 3n` pre-folded where
      // the reference emits three `+n` steps that its own peephole collapses.
      // Same shipped bytes, different pre-peephole spelling — so Zig is gated on
      // this hash instead. See conformance/ec-flag-parity/README.md.
      const optimised = C.optimizeStackIR(ops);
      out.emitters[name][vn] = {
        ...raw,
        postPeephole: measure(C.emitMethod({ name: 't', ops: optimised }).scriptHex),
      };
    }
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const target = join(here, '..', 'ec-flag-parity', 'expected.json');
  writeFileSync(target, JSON.stringify(buildParity(), null, 2) + '\n');
  console.log(`wrote ${target}`);
}
