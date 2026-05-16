# frozen_string_literal: true

require 'spec_helper'

# Runar.compile_check requires the +runar_compiler+ gem, which is not published
# — it lives in-tree at compilers/ruby/lib.  Make it loadable here so the spec
# exercises the real frontend instead of the LoadError branch.
COMPILER_LIB = File.expand_path('../../../../compilers/ruby/lib', __dir__)
$LOAD_PATH.unshift(COMPILER_LIB) unless $LOAD_PATH.include?(COMPILER_LIB)

REPO_ROOT = File.expand_path('../../../..', __dir__)

RSpec.describe 'Runar.compile_check' do
  # ---------------------------------------------------------------------------
  # Happy path — a real, well-formed contract round-trips Parse / Validate /
  # TypeCheck without errors.
  # ---------------------------------------------------------------------------
  describe 'with valid contract source' do
    let(:p2pkh_path) { File.join(REPO_ROOT, 'examples', 'ruby', 'p2pkh', 'P2PKH.runar.rb') }

    it 'accepts a path to a valid .runar.rb contract' do
      skip "#{p2pkh_path} not found" unless File.file?(p2pkh_path)
      expect(Runar.compile_check(p2pkh_path)).to be true
    end

    it 'accepts a source string with an explicit file name' do
      source = <<~RUBY
        require 'runar'

        class P2PKH < Runar::SmartContract
          prop :pub_key_hash, Addr

          def initialize(pub_key_hash)
            super(pub_key_hash)
            @pub_key_hash = pub_key_hash
          end

          runar_public sig: Sig, pub_key: PubKey
          def unlock(sig, pub_key)
            assert hash160(pub_key) == @pub_key_hash
            assert check_sig(sig, pub_key)
          end
        end
      RUBY

      expect(Runar.compile_check(source, 'P2PKH.runar.rb')).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # Failure paths — Parse / Validate / TypeCheck rejections each surface as
  # RuntimeError with a descriptive, file-name-prefixed message.
  # ---------------------------------------------------------------------------
  describe 'with invalid contract source' do
    it 'rejects a source with no class declaration' do
      expect { Runar.compile_check("x = 1\ny = 2\n", 'bad.runar.rb') }
        .to raise_error(RuntimeError, /parse errors in bad\.runar\.rb/)
    end

    it 'rejects a call to an unknown builtin' do
      source = <<~RUBY
        require 'runar'

        class Bad < Runar::SmartContract
          prop :pub_key_hash, Addr

          def initialize(pub_key_hash)
            super(pub_key_hash)
            @pub_key_hash = pub_key_hash
          end

          runar_public sig: Sig, pub_key: PubKey
          def unlock(sig, pub_key)
            _ = totally_not_a_builtin(sig)
            assert check_sig(sig, pub_key)
          end
        end
      RUBY

      expect { Runar.compile_check(source, 'Bad.runar.rb') }
        .to raise_error(RuntimeError, /type check errors.*unknown function/i)
    end
  end

  # ---------------------------------------------------------------------------
  # Optional-dependency path — if runar_compiler is missing the helper raises
  # a friendly LoadError with installation instructions.
  # ---------------------------------------------------------------------------
  describe 'when runar_compiler is not installed' do
    it 'raises a descriptive LoadError' do
      # Force the inner `require 'runar_compiler'` to fail, regardless of
      # whether the gem is currently on the load path.
      allow(Runar).to receive(:require).and_call_original
      expect(Runar).to receive(:require)
        .with('runar_compiler')
        .and_raise(LoadError, 'cannot load such file -- runar_compiler')

      expect { Runar.compile_check('', 'foo.runar.rb') }
        .to raise_error(LoadError, /runar_compiler/)
    end
  end
end
