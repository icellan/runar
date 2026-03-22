# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'ConvergenceProof.runar'

RSpec.describe ConvergenceProof do
  it 'proves convergence of two commitments' do
    # R_A = (T + o_A) * G, R_B = (T + o_B) * G
    # delta_o = o_A - o_B
    t = 42
    o_a = 100
    o_b = 60
    delta_o = o_a - o_b # 40

    r_a = ec_mul_gen(t + o_a)
    r_b = ec_mul_gen(t + o_b)

    c = ConvergenceProof.new(r_a, r_b)
    expect { c.prove_convergence(delta_o) }.not_to raise_error
  end
end
