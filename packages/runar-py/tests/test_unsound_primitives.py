"""R-062 / CL-BUG-105 — see runar/sdk/unsound_primitives.py for the finding.

Mirrors packages/runar-sdk/src/__tests__/unsound-primitives.test.ts.
"""

import pytest

from runar.sdk.types import RunarArtifact
from runar.sdk.unsound_primitives import assert_unsound_primitives_acknowledged


def artifact(*primitives: str) -> RunarArtifact:
    return RunarArtifact(
        version='runar-v1.0.0-rc.1',
        compiler_version='1.0.0-rc.1-go',
        contract_name='Sp1Rollup',
        script='51',
        asm='OP_1',
        build_timestamp='2026-09-13T00:00:00Z',
        unsound_primitives=list(primitives),
    )


def test_ordinary_artifact_deploys_either_way():
    for ack in (None, [], ['verifySP1FRI']):
        assert_unsound_primitives_acknowledged(artifact(), ack, 'Counter.deploy')


def test_refuses_unacknowledged():
    with pytest.raises(RuntimeError) as excinfo:
        assert_unsound_primitives_acknowledged(artifact('verifySP1FRI'), None, 'Sp1Rollup.deploy')
    message = str(excinfo.value)
    assert 'verifySP1FRI' in message
    assert 'Sp1Rollup.deploy' in message
    assert 'acknowledge_unsound' in message


def test_acknowledgement_must_name_every_primitive():
    assert_unsound_primitives_acknowledged(
        artifact('verifySP1FRI'), ['verifySP1FRI'], 'Sp1Rollup.deploy'
    )

    with pytest.raises(RuntimeError) as excinfo:
        assert_unsound_primitives_acknowledged(
            artifact('verifySP1FRI', 'someFutureStub'), ['verifySP1FRI'], 'Sp1Rollup.deploy'
        )
    assert 'someFutureStub' in str(excinfo.value)

    with pytest.raises(RuntimeError):
        assert_unsound_primitives_acknowledged(
            artifact('verifySP1FRI'), ['somethingElse'], 'Sp1Rollup.deploy'
        )


def test_marker_survives_from_dict():
    loaded = RunarArtifact.from_dict({
        'version': 'runar-v1.0.0-rc.1',
        'contractName': 'Sp1Rollup',
        'script': '51',
        'unsoundPrimitives': ['verifySP1FRI'],
    })
    assert loaded.unsound_primitives == ['verifySP1FRI']

    plain = RunarArtifact.from_dict({'version': 'v', 'contractName': 'C', 'script': '51'})
    assert plain.unsound_primitives == []
