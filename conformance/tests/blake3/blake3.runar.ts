import { SmartContract, assert, blake3Compress, blake3Hash } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Blake3Test extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verifyCompress(chainingValue: ByteString, block: ByteString) {
    const result = blake3Compress(chainingValue, block);
    assert(result === this.expected);
  }

  public verifyHash(message: ByteString) {
    const result = blake3Hash(message);
    assert(result === this.expected);
  }
}
