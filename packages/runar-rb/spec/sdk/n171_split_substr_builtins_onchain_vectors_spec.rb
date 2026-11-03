# frozen_string_literal: true

require 'json'
require 'pathname'
require 'spec_helper'
require 'runar/sdk'

# N-171 (sibling of F-274): `split`/`substr` must return what the COMPILED
# SCRIPT returns, for every vector in the shared on-chain file
# packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json.
#
# That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
# packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts.
#
# `split` has no native wrapper at all -- `Runar::Builtins` defines no
# `split` method, matching F-274's "Python's native package has no
# left/right" precedent for a missing function -- so `split` rows exercise
# ONLY the SDK ANF interpreter. `substr` rows exercise BOTH
# `Runar::Builtins#substr` (the native runtime a .runar.rb contract calls
# under rspec) and the SDK ANF interpreter.
#
# R67: the interpreter's `substr` used to be excluded here. Its one caller
# via `extractScriptCode` (`FungibleToken#merge`) got an empty dummy
# scriptCode, turning a realistic `substr(sc, ...)` call into a POSITIVE
# overflow the old clamp had to swallow to avoid breaking
# `RunarContract#call('merge')`. `extractScriptCode` now returns the
# contract's own REAL codePart (`contract.rb`'s `call`, via
# `Thread.current[:runar_mock_preimage_bytes]`), so the interpreter's
# `substr` can be fully abort-faithful without starving `merge` of a
# realistic scriptCode.
#
# Proves: for every `substr` row, both the native runtime and the SDK ANF
# interpreter return the on-chain value, or raise where the script aborts;
# for every `split` row, the SDK ANF interpreter does the same -- covering
# start/index/length = 0, interior, at the boundary, past the end, negative,
# and an empty `data` input.
# Does not prove: inputs outside the file, or the script itself (the
# oracle).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-171 split/substr return the on-chain value for every shared vector' do
  # rubocop:enable RSpec/DescribeClass
  vectors_path = Pathname.new(__dir__).ascend.map do |dir|
    dir.join('packages', 'runar-zig', 'src', 'fixtures', 'n171-split-substr-builtins-onchain.json')
  end.find(&:file?)
  raise 'could not locate n171-split-substr-builtins-onchain.json' unless vectors_path

  data = JSON.parse(vectors_path.read)
  rows = data['cases'].map { |c| [c['fn'], c['data'], c['a'], c['b'], c['expect']] }

  let(:ctx) { Object.new.extend(Runar::Builtins) }
  let(:mod) { Runar::SDK::ANFInterpreter }

  rows.each do |fn, hex, a, b, want|
    label = "#{fn}(#{hex.inspect}, #{a}#{fn == 'substr' ? ", #{b}" : ''}) -> #{want.inspect}"
    interp_args = fn == 'substr' ? [hex, a, b] : [hex, a]

    if fn == 'substr'
      it "native #{label}" do
        if want == 'abort'
          expect { ctx.substr(hex, a, b) }.to raise_error(StandardError)
        else
          expect(ctx.substr(hex, a, b)).to eq(want)
        end
      end
    end

    it "interpreter #{label}" do
      if want == 'abort'
        expect { mod.eval_call(fn, interp_args) }.to raise_error(StandardError)
      else
        expect(mod.eval_call(fn, interp_args)).to eq(want)
      end
    end
  end
end
