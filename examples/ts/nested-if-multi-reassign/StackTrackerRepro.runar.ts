import { SmartContract, assert, substr, bin2num, num2bin, cat } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class StackTrackerRepro extends SmartContract {
  constructor() { super(); }

  public walk(buf: ByteString, count: bigint, target: ByteString) {
    let p: bigint = 0n;
    let found: boolean = false;

    if (0n < count) {
      const x: bigint = bin2num(cat(substr(buf, p, 1n), num2bin(0n, 1n)));
      const blob: ByteString = substr(buf, p, 1n + x);
      if (blob === target) { found = true; }
      p = p + 1n + x;
    }
    if (1n < count) {
      const x: bigint = bin2num(cat(substr(buf, p, 1n), num2bin(0n, 1n)));
      const blob: ByteString = substr(buf, p, 1n + x);
      if (blob === target) { found = true; }
      p = p + 1n + x;
    }
    if (2n < count) {
      const x: bigint = bin2num(cat(substr(buf, p, 1n), num2bin(0n, 1n)));
      const blob: ByteString = substr(buf, p, 1n + x);
      if (blob === target) { found = true; }
      p = p + 1n + x;
    }
    if (3n < count) {
      const x: bigint = bin2num(cat(substr(buf, p, 1n), num2bin(0n, 1n)));
      const blob: ByteString = substr(buf, p, 1n + x);
      if (blob === target) { found = true; }
      p = p + 1n + x;
    }
    if (4n < count) {
      const x: bigint = bin2num(cat(substr(buf, p, 1n), num2bin(0n, 1n)));
      const blob: ByteString = substr(buf, p, 1n + x);
      if (blob === target) { found = true; }
      p = p + 1n + x;
    }
    if (5n < count) {
      const x: bigint = bin2num(cat(substr(buf, p, 1n), num2bin(0n, 1n)));
      const blob: ByteString = substr(buf, p, 1n + x);
      if (blob === target) { found = true; }
      p = p + 1n + x;
    }
    if (6n < count) {
      const x: bigint = bin2num(cat(substr(buf, p, 1n), num2bin(0n, 1n)));
      const blob: ByteString = substr(buf, p, 1n + x);
      if (blob === target) { found = true; }
      p = p + 1n + x;
    }
    if (7n < count) {
      const x: bigint = bin2num(cat(substr(buf, p, 1n), num2bin(0n, 1n)));
      const blob: ByteString = substr(buf, p, 1n + x);
      if (blob === target) { found = true; }
      p = p + 1n + x;
    }

    assert(found);
  }

  public other(x: ByteString) { assert(x === x); }
}

export default StackTrackerRepro;
