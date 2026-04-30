import { SmartContract, assert, substr, bin2num, num2bin, cat } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class StackTrackerReproV10min extends SmartContract {
  constructor() { super(); }

  public verifyMneeTxContainsBothOutputs(
    rawTx: ByteString,
    expectedMneeOutputBytes: ByteString,
    expectedExtraDataOutputBytes: ByteString,
  ) {
    let p: bigint = 46n;

    const outCount: bigint = bin2num(cat(substr(rawTx, p, 1n), num2bin(0n, 1n)));
    assert(outCount < 0xfdn);
    assert(outCount <= 8n);
    p = p + 1n;

    let foundMnee: boolean = false;
    let foundExtra: boolean = false;

    if (0n < outCount) {
      const scriptLen: bigint = bin2num(cat(substr(rawTx, p + 8n, 1n), num2bin(0n, 1n)));
      assert(scriptLen < 0xfdn);
      const blobLen: bigint = 8n + 1n + scriptLen;
      const blob: ByteString = substr(rawTx, p, blobLen);
      if (blob === expectedMneeOutputBytes) { foundMnee = true; }
      if (blob === expectedExtraDataOutputBytes) { foundExtra = true; }
      p = p + blobLen;
    }
    if (1n < outCount) {
      const scriptLen: bigint = bin2num(cat(substr(rawTx, p + 8n, 1n), num2bin(0n, 1n)));
      assert(scriptLen < 0xfdn);
      const blobLen: bigint = 8n + 1n + scriptLen;
      const blob: ByteString = substr(rawTx, p, blobLen);
      if (blob === expectedMneeOutputBytes) { foundMnee = true; }
      if (blob === expectedExtraDataOutputBytes) { foundExtra = true; }
      p = p + blobLen;
    }

    assert(foundMnee);
    assert(foundExtra);
  }

  public other(x: ByteString) { assert(x === x); }
}

export default StackTrackerReproV10min;
