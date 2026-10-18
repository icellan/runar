# frozen_string_literal: true

require 'spec_helper'

# N-183: Runar::EC.ec_make_point must apply the compiled script's R-156 gate:
# each coordinate must satisfy 0 <= v < p, or the script aborts. Before the fix
# Ruby formatted any integer with '%064x' (x = p built a point, -1 built
# "-000...1", 2^256 built a 65-char coordinate).
#
# Proves: boundary operands (p, p+1, -1, 2^256 on either half) raise
# ArgumentError, and p - 1 / 0 / a real curve point still build.
# Does not prove: the script itself (the runar-testing r156 test pins it).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-183 ec_make_point field-element gate' do
  # rubocop:enable RSpec/DescribeClass
  p_field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  gy = 0x4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE
  be32 = ->(n) { format('%064x', n) }

  {
    'x = p' => [p_field, gy],
    'x = p + 1' => [p_field + 1, gy],
    'y = p' => [1, p_field],
    'y = p + 1' => [1, p_field + 1],
    'x = -1' => [-1, gy],
    'y = -1' => [1, -1],
    'x = 2^256' => [2**256, gy],
    'y = 2^256 + 1' => [1, (2**256) + 1]
  }.each do |why, (x, y)|
    it "refuses #{why}" do
      expect { Runar::EC.ec_make_point(x, y) }.to raise_error(ArgumentError, /field element/)
    end
  end

  it 'still builds p - 1, 0 and a real curve point' do
    expect(Runar::EC.ec_make_point(p_field - 1, p_field - 1)).to eq(be32.call(p_field - 1) * 2)
    expect(Runar::EC.ec_make_point(0, 0)).to eq('0' * 128)
    expect(Runar::EC.ec_make_point(1, gy)).to eq(be32.call(1) + be32.call(gy))
  end
end
