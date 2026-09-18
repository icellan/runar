# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# R-062 / CL-BUG-105 — see lib/runar/sdk/errors.rb for the finding.
#
# Mirrors packages/runar-sdk/src/__tests__/unsound-primitives.test.ts.
RSpec.describe 'R-062 unsound-primitive deploy guard' do
  def artifact(*primitives)
    Runar::SDK::RunarArtifact.new(
      version: 'runar-v1.0.0-rc.1',
      contract_name: 'Sp1Rollup',
      script: '51',
      unsound_primitives: primitives
    )
  end

  def guard(art, ack, context = 'Sp1Rollup.deploy')
    Runar::SDK.assert_unsound_primitives_acknowledged(art, ack, context)
  end

  it 'lets an ordinary artifact deploy, acknowledged or not' do
    [nil, [], ['verifySP1FRI']].each do |ack|
      expect { guard(artifact, ack, 'Counter.deploy') }.not_to raise_error
    end
    expect { guard(nil, nil, 'Counter.deploy') }.not_to raise_error
  end

  it 'refuses an unsound artifact the caller has not acknowledged' do
    expect { guard(artifact('verifySP1FRI'), nil) }
      .to raise_error(Runar::SDK::UnsoundPrimitiveError, /verifySP1FRI/)
    expect { guard(artifact('verifySP1FRI'), []) }
      .to raise_error(Runar::SDK::UnsoundPrimitiveError, /acknowledge_unsound/)
    expect { guard(artifact('verifySP1FRI'), []) }
      .to raise_error(Runar::SDK::UnsoundPrimitiveError, /Sp1Rollup\.deploy/)
  end

  it 'requires the acknowledgement to name every primitive' do
    expect { guard(artifact('verifySP1FRI'), ['verifySP1FRI']) }.not_to raise_error

    expect { guard(artifact('verifySP1FRI', 'someFutureStub'), ['verifySP1FRI']) }
      .to raise_error(Runar::SDK::UnsoundPrimitiveError, /someFutureStub/)

    expect { guard(artifact('verifySP1FRI'), ['somethingElse']) }
      .to raise_error(Runar::SDK::UnsoundPrimitiveError, /verifySP1FRI/)
  end

  it 'carries the marker through artifact JSON parsing, and omits it otherwise' do
    marked = Runar::SDK::RunarArtifact.from_hash(
      'version' => 'v', 'contractName' => 'Sp1Rollup', 'script' => '51',
      'unsoundPrimitives' => ['verifySP1FRI']
    )
    expect(marked.unsound_primitives).to eq(['verifySP1FRI'])

    plain = Runar::SDK::RunarArtifact.from_hash(
      'version' => 'v', 'contractName' => 'Counter', 'script' => '51'
    )
    expect(plain.unsound_primitives).to eq([])
  end
end
