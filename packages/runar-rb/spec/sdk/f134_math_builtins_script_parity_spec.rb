# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# F-134: the native math builtins (Runar::Builtins, what a .runar.rb contract
# calls under rspec) and the SDK ANF interpreter (what derives a call's
# post-state) must compute what the compiled script computes.
#
# The expected column was established by EXECUTING the TS compiler's script
# for each builtin in @bsv/sdk's Spend (fold ON and OFF, identical): OP_DIV /
# OP_MOD truncate toward zero; a zero divisor aborts; pow aborts outside
# 0 <= exp <= 32; sqrt aborts on n < 0 and n >= 2^495. :abort means the
# script fails, so the runtime must raise rather than return a number.
#
# Proves: for each listed input both Ruby runtimes return the script's value
# or raise where the script aborts, and truncating division stays exact past
# float precision. Does not prove: agreement outside the table, or anything
# about the script itself (it is the oracle here).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'F-134 math builtins match the compiled script' do
  # rubocop:enable RSpec/DescribeClass
  let(:ctx) { Object.new.extend(Runar::Builtins) }
  let(:mod) { Runar::SDK::ANFInterpreter }

  # [anf name, native name, args, script result]
  vectors = [
    ['divmod', :divmod, [-7, 2], -3],
    ['divmod', :divmod, [7, -2], -3],
    ['divmod', :divmod, [-7, -2], 3],
    ['divmod', :divmod, [1, 0], :abort],
    ['mulDiv', :mul_div, [-7, 1, 2], -3],
    ['mulDiv', :mul_div, [7, 1, -2], -3],
    ['mulDiv', :mul_div, [1, 1, 0], :abort],
    ['percentOf', :percent_of, [-1, 5000], 0],
    ['percentOf', :percent_of, [-15_000, 1], -1],
    ['percentOf', :percent_of, [1, -5000], 0],
    ['pow', :pow, [2, -1], :abort],
    ['pow', :pow, [2, 0], 1],
    ['pow', :pow, [-2, 3], -8],
    ['pow', :pow, [2, 32], 4_294_967_296],
    ['pow', :pow, [2, 33], :abort],
    ['sqrt', :sqrt, [-1], :abort],
    ['sqrt', :sqrt, [0], 0],
    ['sqrt', :sqrt, [8], 2],
    ['sqrt', :sqrt, [1 << 495], :abort],
    ['safediv', :safediv, [-7, 2], -3],
    ['safediv', :safediv, [1, 0], :abort],
    ['safemod', :safemod, [-7, 2], -1],
    ['safemod', :safemod, [7, -2], 1],
    ['safemod', :safemod, [1, 0], :abort],
  ]

  vectors.each do |anf_name, native, args, want|
    label = "#{anf_name}(#{args.map { |a| a == 1 << 495 ? '2**495' : a }.join(', ')})"

    it "native #{label} -> #{want}" do
      if want == :abort
        expect { ctx.public_send(native, *args) }.to raise_error(StandardError)
      else
        got = ctx.public_send(native, *args)
        expect(got).to be_a(Integer)
        expect(got).to eq(want)
      end
    end

    it "interpreter #{label} -> #{want}" do
      if want == :abort
        expect { mod.eval_call(anf_name, args) }.to raise_error(StandardError)
      else
        got = mod.eval_call(anf_name, args)
        expect(got).to be_a(Integer)
        expect(got).to eq(want)
      end
    end
  end

  it 'truncating division is exact beyond float precision' do
    a = -(10**30) - 7
    want = -((10**30 + 7) / 3)
    expect(mod.eval_call('divmod', [a, 3])).to eq(want)
    expect(mod.eval_call('mulDiv', [a, 1, 3])).to eq(want)
    expect(mod.eval_call('safediv', [a, 3])).to eq(want)
    expect(ctx.divmod(a, 3)).to eq(want)
    expect(ctx.mul_div(a, 1, 3)).to eq(want)
    expect(ctx.safediv(a, 3)).to eq(want)
  end
end
