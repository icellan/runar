import { describe, it, expect } from 'vitest';
import { BSV20, BSV21 } from '../ordinals/bsv20.js';

/** Convert hex to UTF-8 string. */
function hexToUtf8(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

describe('BSV20', () => {
  it('builds a deploy inscription', () => {
    const inscription = BSV20.deploy({ tick: 'RUNAR', max: '21000000', lim: '1000' });
    expect(inscription.contentType).toBe('application/bsv-20');
    const json = JSON.parse(hexToUtf8(inscription.data));
    expect(json).toEqual({
      p: 'bsv-20',
      op: 'deploy',
      tick: 'RUNAR',
      max: '21000000',
      lim: '1000',
    });
  });

  it('builds a deploy inscription without optional fields', () => {
    const inscription = BSV20.deploy({ tick: 'TEST', max: '1000' });
    const json = JSON.parse(hexToUtf8(inscription.data));
    expect(json).toEqual({
      p: 'bsv-20',
      op: 'deploy',
      tick: 'TEST',
      max: '1000',
    });
    expect(json.lim).toBeUndefined();
    expect(json.dec).toBeUndefined();
  });

  it('builds a deploy inscription with decimals', () => {
    const inscription = BSV20.deploy({ tick: 'USDT', max: '100000000', dec: '8' });
    const json = JSON.parse(hexToUtf8(inscription.data));
    expect(json.dec).toBe('8');
  });

  it('builds a mint inscription', () => {
    const inscription = BSV20.mint({ tick: 'RUNAR', amt: '1000' });
    expect(inscription.contentType).toBe('application/bsv-20');
    const json = JSON.parse(hexToUtf8(inscription.data));
    expect(json).toEqual({
      p: 'bsv-20',
      op: 'mint',
      tick: 'RUNAR',
      amt: '1000',
    });
  });

  it('builds a transfer inscription', () => {
    const inscription = BSV20.transfer({ tick: 'RUNAR', amt: '50' });
    expect(inscription.contentType).toBe('application/bsv-20');
    const json = JSON.parse(hexToUtf8(inscription.data));
    expect(json).toEqual({
      p: 'bsv-20',
      op: 'transfer',
      tick: 'RUNAR',
      amt: '50',
    });
  });
});

describe('BSV21', () => {
  it('builds a deploy+mint inscription', () => {
    const inscription = BSV21.deployMint({ amt: '1000000', dec: '18', sym: 'RNR' });
    expect(inscription.contentType).toBe('application/bsv-20');
    const json = JSON.parse(hexToUtf8(inscription.data));
    expect(json).toEqual({
      p: 'bsv-20',
      op: 'deploy+mint',
      amt: '1000000',
      dec: '18',
      sym: 'RNR',
    });
  });

  it('builds a deploy+mint without optional fields', () => {
    const inscription = BSV21.deployMint({ amt: '500' });
    const json = JSON.parse(hexToUtf8(inscription.data));
    expect(json).toEqual({
      p: 'bsv-20',
      op: 'deploy+mint',
      amt: '500',
    });
    expect(json.dec).toBeUndefined();
    expect(json.sym).toBeUndefined();
  });

  it('builds a transfer inscription', () => {
    const inscription = BSV21.transfer({
      id: '3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1',
      amt: '100',
    });
    expect(inscription.contentType).toBe('application/bsv-20');
    const json = JSON.parse(hexToUtf8(inscription.data));
    expect(json).toEqual({
      p: 'bsv-20',
      op: 'transfer',
      id: '3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1',
      amt: '100',
    });
  });
});
