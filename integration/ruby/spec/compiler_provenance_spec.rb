# frozen_string_literal: true

# F-276: `compile_contract` must build every artifact with the native Ruby
# compiler (compilers/ruby), not shell out to the TypeScript reference
# compiler via Node.js. The Ruby CLI stamps `compilerVersion` with a
# `-ruby` suffix (see compilers/ruby/lib/runar_compiler/cli.rb); the TS
# compiler stamps a bare semver with no suffix. This proves provenance,
# not bytes: the two compilers already agree byte-for-byte on every source
# this suite references (see tests/f276-integration-source-parity.test.ts),
# so a hex comparison would not go red for this defect.
#
# `.runar.ts` sources are deliberately included here, not just `.runar.rb`
# ones: `compile_contract` used to special-case `.runar.rb` and fall back
# to the TS reference compiler for everything else, on the belief that the
# Ruby compiler's TS-surface parser had codegen divergences for complex
# contracts (TicTacToe was named explicitly). The offline proof found no
# divergence for any of the 29 source paths this suite compiles, including
# TicTacToe and StateCovenant, so the fallback was retired rather than kept
# around unverified.
#
# This spec does NOT need a live node — it only compiles. It is still
# collected behind the suite's global `before(:suite)` node-availability
# check (see spec_helper.rb), which `rspec` cannot bypass short of a
# running regtest node, so it has never actually been executed as RSpec.
# The RED (before the fix) / GREEN (after) behaviour it encodes was
# verified directly instead, from `integration/ruby/`:
#
#   bundle exec ruby -Ispec -e "
#     require 'rspec'; require 'spec_helper'; include IntegrationHelpers
#     puts compile_contract('examples/ts/p2pkh/P2PKH.runar.ts').compiler_version
#   "
#
# `require 'spec_helper'` only *registers* the suite's `before(:suite)`
# hook with RSpec.configure — it does not run it outside an actual RSpec
# example run, so this bypasses the node gate while still exercising the
# exact `compile_contract` production code path. Before the fix this
# printed a bare semver (the TS compiler); after, a `-ruby`-suffixed one.

require 'spec_helper'

RSpec.describe 'compile_contract compiler provenance' do # rubocop:disable RSpec/DescribeClass
  [
    'examples/ts/p2pkh/P2PKH.runar.ts',
    'examples/ts/state-covenant/StateCovenant.runar.ts',
    'examples/ts/tic-tac-toe/TicTacToe.runar.ts'
  ].each do |rel_path|
    it "compiles #{rel_path} with the native Ruby compiler" do
      artifact = compile_contract(rel_path)
      expect(artifact.compiler_version).to end_with('-ruby')
    end
  end

  it 'compiles a native .runar.rb source with the native Ruby compiler' do
    artifact = compile_contract('examples/ruby/p2pkh/P2PKH.runar.rb')
    expect(artifact.compiler_version).to end_with('-ruby')
  end
end
