# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# N-070 (extract half) — +interpret_script_element+ must know every ABI type
# spelling the compiler can emit.
#
# Two holes, identical in shape across all seven SDK tiers:
#
#   RabinSig / RabinPubKey — +bigint+ ALIASES (runar-lang/src/types.ts:68-71)
#     that +verifyRabinSig+ consumes with OP_MOD, i.e. as a Script NUMBER.
#     Absent from the +case+, so a restored contract's modulus came back as the
#     little-endian hex blob '1581e97df4102211' instead of the number. Feed that
#     back into a call and the rebuilt locking script no longer matches chain.
#
#   boolean — the CANONICAL Rúnar primitive name; only the alias 'bool' was
#     handled. A boolean slot fell through to the byte branch, so +true+ came
#     back as the string '01' and +false+ as ''. Java's ContractScript was the
#     only tier of seven that tested both spellings.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-070: extract_constructor_args slot types' do
  # rubocop:enable RSpec/DescribeClass
  MODULUS = 1_234_567_890_123_456_789
  RABIN_PUSH = '081581e97df4102211' # minimal LE sign-magnitude, 8 bytes
  BLOB = '04deadbeef'

  # Template: ab-free, <modulus@0> 7c <flag@2> 7c <blob@4> ac
  def artifact(rabin_type, bool_type)
    Runar::SDK::RunarArtifact.new(
      script: '00' + '7c' + '00' + '7c' + '00' + 'ac',
      constructor_slots: [
        Runar::SDK::ConstructorSlot.new(param_index: 0, byte_offset: 0),
        Runar::SDK::ConstructorSlot.new(param_index: 1, byte_offset: 2),
        Runar::SDK::ConstructorSlot.new(param_index: 2, byte_offset: 4)
      ],
      abi: Runar::SDK::ABI.new(
        constructor_params: [
          Runar::SDK::ABIParam.new(name: 'modulus', type: rabin_type),
          Runar::SDK::ABIParam.new(name: 'flag', type: bool_type),
          Runar::SDK::ABIParam.new(name: 'blob', type: 'ByteString')
        ]
      )
    )
  end

  def script(flag_opcode)
    RABIN_PUSH + '7c' + flag_opcode + '7c' + BLOB + 'ac'
  end

  %w[RabinPubKey RabinSig].each do |type_name|
    it "extracts a #{type_name} slot as a script number, not a hex blob" do
      args = Runar::SDK::ScriptUtils.extract_constructor_args(artifact(type_name, 'boolean'), script('51'))
      expect(args['modulus']).to eq(MODULUS)
    end
  end

  { '51' => true, '00' => false }.each do |opcode, want|
    it "extracts a canonical `boolean` slot pushed as #{opcode} as #{want}" do
      args = Runar::SDK::ScriptUtils.extract_constructor_args(artifact('RabinPubKey', 'boolean'), script(opcode))
      expect(args['flag']).to be(want)
    end

    it "agrees between the `boolean` and `bool` spellings for #{opcode}" do
      canonical = Runar::SDK::ScriptUtils.extract_constructor_args(artifact('RabinPubKey', 'boolean'), script(opcode))
      alias_spelled = Runar::SDK::ScriptUtils.extract_constructor_args(artifact('RabinPubKey', 'bool'), script(opcode))
      expect(canonical['flag']).to be(alias_spelled['flag'])
    end
  end

  # --- CONTROLS: the classes that already worked must not move. -------------

  %w[bigint int].each do |type_name|
    it "CONTROL: a #{type_name} slot is unchanged" do
      args = Runar::SDK::ScriptUtils.extract_constructor_args(artifact(type_name, 'bool'), script('51'))
      expect(args['modulus']).to eq(MODULUS)
    end
  end

  it 'CONTROL: a ByteString slot still comes back as its hex payload' do
    # The offset walk past the wide Rabin push must still land on it.
    args = Runar::SDK::ScriptUtils.extract_constructor_args(artifact('RabinPubKey', 'boolean'), script('51'))
    expect(args['blob']).to eq('deadbeef')
  end

  it 'CONTROL: S1 single-opcode byte reconstruction still applies' do
    s1 = Runar::SDK::ScriptUtils.extract_constructor_args(
      artifact('RabinPubKey', 'boolean'), RABIN_PUSH + '7c' + '51' + '7c' + '55' + 'ac'
    )
    expect(s1['blob']).to eq('05')
  end
end
