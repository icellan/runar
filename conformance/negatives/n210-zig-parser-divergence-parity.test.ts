import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, type Tier } from './tier-harness.js';

/**
 * N-210 — the .runar.zig surface parser, seven-tier parity (F-207).
 *
 * The TS reference (01-parse-zig.ts) and the Zig-native tier
 * (parse_zig.zig) already agreed on three shapes that Go, Rust, Python,
 * Ruby and Java either refused outright or mishandled:
 *
 *   - a bare `&` not followed by `.{` is Zig's address-of operator used
 *     for slice coercion (`&x`, `&[_]T{...}`). The TS reference strips it
 *     in `parseUnary` and parses the real operand -- it never reaches
 *     `parsePrimary`'s own, narrower `&.{...}` special case. The five
 *     lagging tiers had no equivalent arm in their unary parser: Go and
 *     Rust's catch-all (N-144) turned it into a parse ERROR (consume the
 *     `&`, leave the operand dangling, then choke on the stray token);
 *     Python, Ruby and Java's catch-all silently manufactured
 *     `Identifier(name: "&")` with no diagnostic and the same dangling
 *     operand. Either way, a legal `.runar.zig` contract the TS reference
 *     accepts was refused (or, isolated at the parser level, silently
 *     corrupted) by the other five tiers.
 *   - `[_]T{...}` -- Zig's typed array literal with inferred length -- had
 *     no dedicated handling in the same five tiers at all: the element
 *     type's leading `[` fell into the plain `[elem, ...]` array-literal
 *     branch, which choked on the bare `_` it found instead of a `]`.
 *   - a stale parser-level rule stripped a property's initializer whenever
 *     its NAME matched some constructor PARAMETER name, in Go, Rust,
 *     Python, Ruby and Java's Zig parsers. The TS reference deliberately
 *     removed this (01-parse-zig.ts:424-434): the decision belongs to
 *     `04-anf-lower.ts`'s `constructorAssignedProperties`, which is keyed
 *     on the actual constructor ASSIGNMENT (a bare `this.x = x`), not a
 *     name coincidence. The stale rule was not just a byte-level
 *     divergence -- it is demonstrated below to make the
 *     constructor-param-count validator reject an otherwise legal contract
 *     outright, in every one of the five lagging tiers.
 *
 * What this proves:
 *   - every available tier parses and compiles each shape to the SAME
 *     bytes as the TS reference, in both fold modes;
 *   - the third fixture, which every lagging tier used to refuse with a
 *     validator error ("Property 'lo' must be assigned in the
 *     constructor"), now compiles on every tier.
 * What it does NOT prove: any `.runar.zig` shape other than these three,
 *   or anything about the other eight source formats.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/** Claim 1: a bare `&` (address-of / slice-coercion) must be stripped,
 *  compiling identically to the same source with `&` simply omitted. */
const AMP_PREFIX = `const runar = @import("runar");

pub const AmpPrefix = struct {
    pub const Contract = runar.SmartContract;

    t: i64,

    pub fn init(t: i64) AmpPrefix {
        return .{ .t = t };
    }

    pub fn unlock(self: AmpPrefix, x: i64) void {
        runar.assert(&x == self.t);
    }
};
`;

/** Claim 2: `&[_]T{...}` must compile to the SAME bytes as the equivalent
 *  `&.{...}` anonymous-struct-literal form (MultiSig2of3's own idiom). */
const INFERRED_ARRAY = `const runar = @import("runar");

pub const InferredArray = struct {
    pub const Contract = runar.SmartContract;

    pk1: runar.PubKey,
    pk2: runar.PubKey,
    pk3: runar.PubKey,

    pub fn init(pk1: runar.PubKey, pk2: runar.PubKey, pk3: runar.PubKey) InferredArray {
        return .{ .pk1 = pk1, .pk2 = pk2, .pk3 = pk3 };
    }

    pub fn unlock(self: *const InferredArray, sig1: runar.Sig, sig2: runar.Sig) void {
        runar.assert(runar.checkMultiSig(
            &[_]runar.Sig{ sig1, sig2 },
            &.{ self.pk1, self.pk2, self.pk3 },
        ));
    }
};
`;

/** Claim 3: ctor param `lo` is assigned to the DIFFERENT property
 *  `renamed`; the `lo` PROPERTY (same name, never touched by the
 *  constructor) must keep its own literal initializer. Before the fix,
 *  the stale name-match strip wiped it, and the compiler then rejected the
 *  contract outright: "Property 'lo' must be assigned in the
 *  constructor". */
const INIT_SURVIVES = `const runar = @import("runar");

pub const InitSurvivesC = struct {
    pub const Contract = runar.StatefulSmartContract;

    lo: i64 = 99,
    renamed: i64 = 0,
    hi: i64 = 0,

    pub fn init(lo: i64, hi: i64) InitSurvivesC {
        return .{ .renamed = lo, .hi = hi };
    }

    pub fn bump(self: *InitSurvivesC, delta: i64) void {
        self.lo = self.lo - delta;
        self.renamed = self.renamed + delta;
        self.hi = self.hi + delta;
        self.addOutput(1000, self.lo, self.renamed, self.hi);
    }
};
`;

/** [case name, file name, source, pinned TS hex (fold OFF and ON agree)]. */
const POSITIVE: Array<[string, string, string, string]> = [
  ['bare `&` strips to the operand', 'AmpPrefix.runar.zig', AMP_PREFIX, '009c'],
  [
    '`&[_]T{...}` matches `&.{...}`',
    'InferredArray.runar.zig',
    INFERRED_ARRAY,
    '00000000557a557a52567a567a567a53ae',
  ],
  [
    'ctor-param name collision does not strip an unrelated property',
    'InitSurvivesC.runar.zig',
    INIT_SURVIVES,
    '61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f8201199d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f75820118947f77587f7c817c587f7c817c815279577994537a755279577993537a755279577a93537a7502e8035379537953795a79016a7e537a58807e7b58807e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e567a567a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa547a820128947f7701207f758777777777',
  ],
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n210-zig-parser-divergence-'));
});

let seq = 0;
function write(name: string, src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, name);
  writeFileSync(p, src);
  return p;
}

describe('N-210 .runar.zig parser divergence — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (process.env.CI === 'true') expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const [name, file, src, pin] of POSITIVE) {
      for (const tier of tiers) {
        it(`${tier.id} (${mode}) compiles ${name} to the TS bytes`, () => {
          expect(compileHex(tier, write(file, src))).toBe(pin);
        });
      }
    }
  }
});
