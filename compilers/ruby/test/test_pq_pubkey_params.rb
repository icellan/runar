# frozen_string_literal: true

# PQ-F1: the artifact lists every constructor param passed directly as the
# public key of verifyWOTS / verifySLHDSA_SHA2_*, with the exact byte length
# that verifier needs, so every SDK can refuse a wrong-length key before
# deploying (stateless artifacts carry no ANF to walk).
#
# Proves: the exact JSON text of `pqPubKeyParams` (key order included) for a
# stateless WOTS contract, an SLH-DSA-192f contract, and a key behind a local
# alias plus a key read in a private helper; absent for a key passed as a
# method argument.
# Does not prove: cross-tier equality (conformance/negatives/artifact-flag-parity.test.ts).

require_relative "test_helper"
require "json"
require "tmpdir"

class TestPqPubKeyParams < Minitest::Test
  def pq(src)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "C.runar.ts")
      File.write(path, src)
      d = JSON.parse(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
      d.key?("pqPubKeyParams") ? JSON.generate(d["pqPubKeyParams"]) : nil
    end
  end

  def test_stateless_wots
    assert_equal '[{"index":0,"name":"pk","scheme":"verifyWOTS","length":64}]', pq(<<~TS)
      import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
      class C extends SmartContract {
        readonly pk: ByteString;
        constructor(pk: ByteString) { super(pk); this.pk = pk; }
        public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }
      }
    TS
  end

  def test_slh_192f
    assert_equal '[{"index":0,"name":"pk","scheme":"verifySLHDSA_SHA2_192f","length":48}]', pq(<<~TS)
      import { SmartContract, ByteString, assert, verifySLHDSA_SHA2_192f } from 'runar-lang';
      class C extends SmartContract {
        readonly pk: ByteString;
        constructor(pk: ByteString) { super(pk); this.pk = pk; }
        public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_192f(msg, sig, this.pk)); }
      }
    TS
  end

  def test_alias_and_helper
    want = '[{"index":1,"name":"a","scheme":"verifyWOTS","length":64},' \
           '{"index":2,"name":"b","scheme":"verifyWOTS","length":64}]'
    assert_equal want, pq(<<~TS)
      import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
      class C extends SmartContract {
        readonly tag: bigint;
        readonly a: ByteString;
        readonly b: ByteString;
        constructor(tag: bigint, a: ByteString, b: ByteString) { super(tag, a, b); this.tag = tag; this.a = a; this.b = b; }
        private checkB(msg: ByteString, sig: ByteString): boolean { return verifyWOTS(msg, sig, this.b); }
        public spend(msg: ByteString, sig: ByteString, sig2: ByteString) {
          assert(this.checkB(msg, sig2));
          const k = this.a;
          assert(verifyWOTS(msg, sig, k));
          assert(this.tag > 0n);
        }
      }
    TS
  end

  def test_key_as_method_arg_is_absent
    assert_nil pq(<<~TS)
      import { SmartContract, ByteString, Sha256, assert, sha256, verifyWOTS } from 'runar-lang';
      class C extends SmartContract {
        readonly h: Sha256;
        constructor(h: Sha256) { super(h); this.h = h; }
        public spend(msg: ByteString, sig: ByteString, pk: ByteString) { assert(sha256(pk) === this.h); assert(verifyWOTS(msg, sig, pk)); }
      }
    TS
  end
end
