/**
 * N-302: the readonly-field DCE warning (N-247) told every user to annotate the
 * field `/** @embedAlways *\/`, a TS-only comment spelling that the 8 non-TS
 * surfaces refuse since N-093. The wording is now surface-neutral: it names the
 * `embedAlways` directive without prescribing a spelling (each surface's native
 * spelling is in docs/language-reference.md), identically in all 7 tiers.
 *
 * Proves: for a .runar.sol and a .runar.ts contract with an unreferenced
 * readonly field, the TS reference's warning names `embedAlways` and does not
 * contain the TS comment syntax. Does NOT prove: peer-tier text parity (that is
 * n247-dce-warning-wording.test.ts, which compares every built peer CLI to TS).
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const SOL = `pragma runar ^0.1.0;

contract Meta is SmartContract {
    Addr immutable pubKeyHash;
    ByteString immutable metadataId;

    constructor(Addr _pubKeyHash, ByteString _metadataId) {
        pubKeyHash = _pubKeyHash;
        metadataId = _metadataId;
    }

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
`;

const TS = `import { SmartContract, assert, Addr, PubKey, Sig, ByteString, hash160, checkSig } from 'runar-lang';

class Meta extends SmartContract {
  readonly pubKeyHash: Addr;
  readonly metadataId: ByteString;

  constructor(pubKeyHash: Addr, metadataId: ByteString) {
    super(pubKeyHash, metadataId);
    this.pubKeyHash = pubKeyHash;
    this.metadataId = metadataId;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;

describe('N-302: DCE warning is surface-neutral', () => {
  for (const [fileName, src] of [
    ['Meta.runar.sol', SOL],
    ['Meta.runar.ts', TS],
  ] as const) {
    it(`${fileName}: warning names embedAlways, not the TS comment syntax`, () => {
      const r = compile(src, { fileName });
      const w = r.diagnostics.find(
        (d) => d.severity === 'warning' && d.message.includes("readonly field 'metadataId'"),
      );
      expect(w, JSON.stringify(r.diagnostics)).toBeDefined();
      expect(w!.message).toContain('embedAlways');
      expect(w!.message).not.toContain('/**');
      expect(w!.message).not.toContain('@embedAlways');
    });
  }
});
