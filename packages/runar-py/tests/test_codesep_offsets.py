"""Issue #42: terminal-method sighash subscript byte-walker.

The on-chain script trims its sighash subscript at the method's
OP_CODESEPARATOR. ``_find_codesep_offsets`` must recover the true byte position
by walking the script, correctly skipping push-data (which may itself contain a
0xab byte) and all BSV push opcodes.
"""

from runar.sdk.contract import _find_codesep_offsets


def test_find_codesep_offsets_real_byte_position():
    # 51            OP_1
    # 02 ab cd      push 2 bytes (0xab inside push-data, must be ignored)
    # ab            OP_CODESEPARATOR  <- real, byte offset 4
    # ac            OP_CHECKSIG
    assert _find_codesep_offsets('5102abcdabac') == [4]


def test_find_codesep_offsets_pushdata1():
    # 4c (OP_PUSHDATA1) 02 (len) abab (data, contains 0xab) ab (real codesep)
    assert _find_codesep_offsets('4c02ababab') == [4]


def test_sighash_subscript_trimmed_at_real_codesep_byte_position():
    # Issue #42: the user-sig subscript for a stateful terminal method
    # (e.g. Auction.close) must be trimmed at the real on-chain codesep byte
    # position recovered by _find_codesep_offsets — even when push-data contains
    # a stray 0xab byte.
    full_script = '5102abcdabac'  # real codesep at byte index 4
    offsets = _find_codesep_offsets(full_script)
    assert offsets == [4]
    code_sep_idx = offsets[0]

    subscript = full_script
    if code_sep_idx >= 0:
        trim_pos = (code_sep_idx + 1) * 2
        if trim_pos <= len(subscript):
            subscript = subscript[trim_pos:]
    # Only the OP_CHECKSIG (ac) after the separator remains.
    assert subscript == 'ac'
