# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# The issue #106 OR-CHECKSIG gate must recognise BOTH lowerings of `||`.
#
# It went blind once already: it tested for OP_BOOLOR, and NEW-014 stopped the
# compiler emitting that opcode, so the NULLFAIL warning silently never fired.
RSpec.describe 'issue #106 OR-CHECKSIG gate' do
  def gate(asm)
    artifact = Runar::SDK::RunarArtifact.allocate
    artifact.instance_variable_set(:@asm, asm)
    contract = Runar::SDK::RunarContract.allocate
    contract.instance_variable_set(:@artifact, artifact)
    contract.send(:likely_or_checksig?)
  end

  {
    'legacy OP_BOOLOR form'      => ['OP_DUP OP_BOOLOR OP_CHECKSIG', true],
    'NEW-014 branch form'        => ['OP_IF OP_CHECKSIG OP_ELSE OP_CHECKSIG OP_ENDIF', true],
    'multi-sig is excluded'      => ['OP_IF OP_CHECKSIG OP_CHECKMULTISIG', false],
    'branching without CHECKSIG' => ['OP_IF OP_DUP OP_ELSE OP_DROP OP_ENDIF', false],
    'CHECKSIG without a choice'  => ['OP_DUP OP_HASH160 OP_CHECKSIG', false],
    'lowercase asm still matches' => ['op_if op_checksig op_endif', true],
    'absent asm cannot claim'    => ['', false]
  }.each do |name, (asm, want)|
    it name do
      expect(gate(asm)).to eq(want)
    end
  end
end
