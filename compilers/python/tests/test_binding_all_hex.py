"""The compact @bindingVariant all blob is 376 bytes, matching TS/Go."""

from runar_compiler.codegen.stack import _CHECK_PREIMAGE_BINDING_ALL_HEX, _CHECK_PREIMAGE_BINDING_HEX


def test_all_blob_is_376_bytes():
    assert len(_CHECK_PREIMAGE_BINDING_ALL_HEX) == 752
    assert len(_CHECK_PREIMAGE_BINDING_ALL_HEX) // 2 == 376


def test_all_blob_is_smaller_than_lows():
    assert len(_CHECK_PREIMAGE_BINDING_ALL_HEX) < len(_CHECK_PREIMAGE_BINDING_HEX)
