# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# D12 PQ-F1: a wrong-length WOTS+ / SLH-DSA public key deployed silently and
# the output refused the owner's valid signature forever (the compiled
# verifier splits the key at fixed offsets). RunarContract now refuses, at
# construction, a constructor arg loaded straight into the pk operand of
# verifyWOTS (64 bytes) or verifySLHDSA_SHA2_* (32 / 48 / 64 bytes).
#
# Proves: wrong lengths are refused and the right length is accepted for WOTS
# and two SLH-DSA sets, on artifacts that carry ANF (stateful).
# Does not prove: stateless artifacts (no ANF in the artifact), hash-committed
# keys, keys passed as method args.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'D12: PQ public key length is checked at construction' do
  # rubocop:enable RSpec/DescribeClass
  def pq_artifact(dir, verify)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    path = File.join(dir, 'Pq.runar.ts')
    File.write(path, <<~TS)
      import { StatefulSmartContract, ByteString, assert, #{verify} } from 'runar-lang';

      class Pq extends StatefulSmartContract {
        readonly pk: ByteString;
        n: bigint;
        constructor(pk: ByteString, n: bigint) { super(pk, n); this.pk = pk; this.n = n; }
        public spend(msg: ByteString, sig: ByteString) {
          assert(#{verify}(msg, sig, this.pk));
          this.n = this.n + 1n;
        }
      }
    TS
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  [['verifyWOTS', 64], ['verifySLHDSA_SHA2_128s', 32], ['verifySLHDSA_SHA2_192f', 48]].each do |verify, want|
    it "refuses a wrong-length #{verify} public key" do
      Dir.mktmpdir do |dir|
        art = pq_artifact(dir, verify)
        expect { Runar::SDK::RunarContract.new(art, ['ab' * want, 0]) }.not_to raise_error
        [0, want - 1, want + 1, want / 2, want * 2].each do |bad|
          expect { Runar::SDK::RunarContract.new(art, ['ab' * bad, 0]) }
            .to raise_error(Runar::SDK::InvalidConstructorArgError, /public key/), "#{verify} len #{bad}"
        end
      end
    end
  end

  # PQ-F1 (artifact field): the check reads +pqPubKeyParams+, so a STATELESS
  # artifact (no ANF) is refused too, with the message shared by all seven
  # SDKs; an older stateful artifact without the field falls back to the ANF.
  def artifact_hash(dir, name, src)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    path = File.join(dir, "#{name}.runar.ts")
    File.write(path, src)
    JSON.parse(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  it 'refuses a wrong-length key on a stateless artifact with the shared message' do
    Dir.mktmpdir do |dir|
      h = artifact_hash(dir, 'SW', <<~TS)
        import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
        class SW extends SmartContract {
          readonly pk: ByteString;
          constructor(pk: ByteString) { super(pk); this.pk = pk; }
          public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }
        }
      TS
      expect(h).not_to have_key('anf')
      art = Runar::SDK::RunarArtifact.from_hash(h)
      want = "RunarContract: constructor arg 'pk' is the verifyWOTS public key and must be exactly 64 bytes, got 32. " \
             'A locking script built from it would refuse every valid signature, so the output could never be spent (PQ-F1)'
      expect { Runar::SDK::RunarContract.new(art, ['ab' * 32]) }
        .to raise_error(Runar::SDK::InvalidConstructorArgError) { |e| expect(e.message).to eq(want) }
      [0, 63, 65].each do |bad|
        expect { Runar::SDK::RunarContract.new(art, ['ab' * bad]) }
          .to raise_error(Runar::SDK::InvalidConstructorArgError, /PQ-F1/)
      end
      expect { Runar::SDK::RunarContract.new(art, ['ab' * 64]) }.not_to raise_error
    end
  end

  it 'falls back to the ANF for a stateful artifact without the field' do
    Dir.mktmpdir do |dir|
      h = artifact_hash(dir, 'LW', <<~TS)
        import { StatefulSmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
        class LW extends StatefulSmartContract {
          readonly pk: ByteString;
          n: bigint;
          constructor(pk: ByteString, n: bigint) { super(pk, n); this.pk = pk; this.n = n; }
          public spend(msg: ByteString, sig: ByteString) { const k = this.pk; assert(verifyWOTS(msg, sig, k)); this.n = this.n + 1n; }
        }
      TS
      h.delete('pqPubKeyParams')
      art = Runar::SDK::RunarArtifact.from_hash(h)
      expect { Runar::SDK::RunarContract.new(art, ['ab' * 32, 0]) }
        .to raise_error(Runar::SDK::InvalidConstructorArgError, /must be exactly 64 bytes, got 32/)
      expect { Runar::SDK::RunarContract.new(art, ['ab' * 64, 0]) }.not_to raise_error
    end
  end
end
