# frozen_string_literal: true

require_relative 'codegen_helper'

# Codegen unit tests for hash-family builtin opcodes: hash160, hash256,
# sha256, ripemd160. Each is a single-opcode builtin lowered by
# compilers/ruby/lib/runar_compiler/codegen/stack.rb. The Stack-IR + emit
# pipeline must produce the matching OP_* opcode in the final ASM.
#
# Companion to the sha256-compress/finalize tests in test_sha256.rb which
# cover the multi-KB unrolled hash variants.

class TestHashBuiltinsCodegen < Minitest::Test
  include CodegenTestHelpers

  def test_hash160_emits_op_hash160
    source = <<~TS
      import { SmartContract, assert, hash160 } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class H160 extends SmartContract {
        readonly expected: ByteString;

        constructor(expected: ByteString) {
          super(expected);
          this.expected = expected;
        }

        public check(data: ByteString): void {
          assert(hash160(data) === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'H160.runar.ts')
    assert_includes artifact.asm, 'OP_HASH160',
                    "hash160 builtin must emit OP_HASH160"
  end

  def test_hash256_emits_op_hash256
    source = <<~TS
      import { SmartContract, assert, hash256 } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class H256 extends SmartContract {
        readonly expected: ByteString;

        constructor(expected: ByteString) {
          super(expected);
          this.expected = expected;
        }

        public check(data: ByteString): void {
          assert(hash256(data) === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'H256.runar.ts')
    assert_includes artifact.asm, 'OP_HASH256',
                    "hash256 builtin must emit OP_HASH256"
  end

  def test_sha256_emits_op_sha256
    source = <<~TS
      import { SmartContract, assert, sha256 } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class S256 extends SmartContract {
        readonly expected: ByteString;

        constructor(expected: ByteString) {
          super(expected);
          this.expected = expected;
        }

        public check(data: ByteString): void {
          assert(sha256(data) === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'S256.runar.ts')
    assert_includes artifact.asm, 'OP_SHA256',
                    "sha256 builtin must emit OP_SHA256"
  end

  def test_ripemd160_emits_op_ripemd160
    source = <<~TS
      import { SmartContract, assert, ripemd160 } from 'runar-lang';
      import type { ByteString } from 'runar-lang';

      class R160 extends SmartContract {
        readonly expected: ByteString;

        constructor(expected: ByteString) {
          super(expected);
          this.expected = expected;
        }

        public check(data: ByteString): void {
          assert(ripemd160(data) === this.expected);
        }
      }
    TS

    artifact = compile_ts_source(source, 'R160.runar.ts')
    assert_includes artifact.asm, 'OP_RIPEMD160',
                    "ripemd160 builtin must emit OP_RIPEMD160"
  end

  def test_p2pkh_chains_dup_hash160_equalverify_checksig
    # Canonical P2PKH spend path: assertion of hash160(pk) and checkSig must
    # produce the chained OP_DUP OP_HASH160 ... OP_EQUALVERIFY OP_CHECKSIG.
    source = <<~TS
      import { SmartContract, assert, hash160, checkSig } from 'runar-lang';
      import type { PubKey, Sig, Addr } from 'runar-lang';

      class P2PKH extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(sig: Sig, pubKey: PubKey): void {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS

    artifact = compile_ts_source(source, 'P2PKH.runar.ts')
    asm = artifact.asm
    assert_includes asm, 'OP_HASH160'
    assert_includes asm, 'OP_EQUALVERIFY'
    assert_includes asm, 'OP_CHECKSIG'
  end
end
