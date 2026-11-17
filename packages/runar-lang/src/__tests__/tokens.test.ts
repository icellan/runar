// ---------------------------------------------------------------------------
// Tests for runar-lang/tokens — the runtime surface of the two token contracts
//
// GK-DOC-009: these used to be abstract stubs whose methods threw "cannot be
// called at runtime". They are now complete StatefulSmartContract contracts.
// What they compile to, and how they behave under TestContract, is pinned in
// tests/gk-doc-009-runar-lang-tokens-compile.test.ts (that test needs the
// compiler, which runar-lang must not depend on). This file only checks the
// package surface: the classes are exported, are stateful contracts, and
// store their constructor arguments.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { StatefulSmartContract } from '../index.js';
import { FungibleToken, NonFungibleToken } from '../tokens/index.js';

describe('FungibleToken', () => {
  it('is a StatefulSmartContract and stores its four properties', () => {
    const token = new FungibleToken('ownerPK' as never, 100n, 5n, 'deadbeef' as never);
    expect(token).toBeInstanceOf(StatefulSmartContract);
    expect(token.owner).toBe('ownerPK');
    expect(token.balance).toBe(100n);
    expect(token.mergeBalance).toBe(5n);
    expect(token.tokenId).toBe('deadbeef');
  });

  it('exposes transfer, send and merge spending methods (no split stub)', () => {
    const proto = FungibleToken.prototype as unknown as Record<string, unknown>;
    expect(typeof proto.transfer).toBe('function');
    expect(typeof proto.send).toBe('function');
    expect(typeof proto.merge).toBe('function');
    expect(proto.split).toBeUndefined();
  });
});

describe('NonFungibleToken', () => {
  it('is a StatefulSmartContract and stores owner, tokenId and metadata', () => {
    const nft = new NonFungibleToken('ownerPK' as never, 'tokenABC' as never, 'meta' as never);
    expect(nft).toBeInstanceOf(StatefulSmartContract);
    expect(nft.owner).toBe('ownerPK');
    expect(nft.tokenId).toBe('tokenABC');
    expect(nft.metadata).toBe('meta');
  });

  it('exposes transfer and burn spending methods', () => {
    const proto = NonFungibleToken.prototype as unknown as Record<string, unknown>;
    expect(typeof proto.transfer).toBe('function');
    expect(typeof proto.burn).toBe('function');
  });
});
