/**
 * A contract property whose name collides with a known global constant must
 * resolve to the PROPERTY, in every tier.
 *
 * `03-typecheck.ts` resolved a bare identifier in this order:
 *
 *     local env -> builtin function -> KNOWN_GLOBALS -> contract property
 *
 * The six peer tiers use the opposite order for the last two — property
 * before global. The propTypes arm exists because the Java and Solidity
 * frontends emit `strikePrice` for `this.strikePrice`, so a bare identifier
 * IS how a property is referenced on those surfaces. Putting KNOWN_GLOBALS
 * first means a property named `EC_P`, `EC_N`, `EC_G` or `SigHash` is
 * silently read as the global instead.
 *
 * Measured on a Java-surface contract declaring `Bigint EC_G` and calling
 * `ecMul(EC_G, k)`:
 *
 *     go, rust, python, zig, ruby, java   reject: argument 1 of ecMul():
 *                                          expected 'Point', got 'bigint'
 *     typescript                           exit 0 — emitted a 424 KB script
 *
 * TypeScript typed the bigint property as the global `Point` and compiled an
 * EC scalar multiply over a value that is not a point. Six tiers reject the
 * source; one ships a locking script for it.
 *
 * The Solidity surface does NOT reach this path — its parser rewrites the
 * bare name to a property access before typecheck — which is why the
 * divergence survived: the shape that exposes it only arrives via `.runar.java`.
 *
 * The control for the reorder is the corpus, not a case in this file: no
 * contract anywhere references a known global as a bare identifier in a
 * compiled expression (`SigHash.ALL` is a property access, and `EC_N` is
 * imported-but-unused in ec-demo), and a bare `EC_G` is refused by all seven
 * tiers alike at stack lowering. So the reorder can only change behaviour for
 * a name that IS a property — which is the case below. The 78-fixture golden
 * conformance run is what proves the corpus is unmoved.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const SHADOWING_JAVA = `
class Shadow extends SmartContract {

    @Readonly Bigint EC_G;

    Shadow(Bigint EC_G) {
        super(EC_G);
        this.EC_G = EC_G;
    }

    @Public
    void check(Bigint k) {
        Point p = ecMul(EC_G, k);
        assertThat(ecPointX(p).gt(Bigint.of(0)));
    }
}
`;

describe('a property shadows a same-named known global', () => {
  it('rejects the bigint property used as a Point, matching all six peer tiers', () => {
    const r = compile(SHADOWING_JAVA, { fileName: 'Shadow.runar.java' });
    expect(r.success).toBe(false);
    const msg = r.diagnostics.map((d) => d.message).join('\n');
    expect(msg).toMatch(/ecMul\(\).*expected 'Point', got 'bigint'/);
  });

  it('emits no locking script for a source the peer tiers refuse', () => {
    const r = compile(SHADOWING_JAVA, { fileName: 'Shadow.runar.java' });
    expect(r.scriptHex).toBeUndefined();
  });

});
