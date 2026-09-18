"""R-299 (CL-GAP-095): the SLH-DSA delegation masks a real ImportError as
"module not available".

``stack.py`` wrapped BOTH the import and the call:

    try:
        from runar_compiler.codegen.slh_dsa import emit_verify_slh_dsa
        emit_verify_slh_dsa(lambda op: self.emit_op(op), param_key)
    except ImportError:
        raise RuntimeError("SLH-DSA codegen module not available. ...")

so an ImportError raised INSIDE the codegen module — a missing transitive
dependency, a typo'd import in that module, a partially installed package —
came back as "SLH-DSA codegen module not available. Please implement
runar_compiler.codegen.slh_dsa", which is false: the module is right there. The
author is sent to write a module that already exists while the real cause is
discarded, and there was no ``from exc`` to recover it.

The sibling EC handler in the same file (:4685) wraps only the import, which is
what makes this an inconsistency inside one file rather than a house style.

These tests do not simulate the failure with a mock of the lowering. They put a
module into ``sys.modules`` that raises ImportError from the CALL, and compile a
real contract through the real pipeline, which is the only way to see which of
the two failures the handler reports.
"""

import sys
import types

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

SOURCE = """
import { SmartContract, assert, verifySLHDSA_SHA2_128f } from 'runar-lang';

class SlhDsaProbe extends SmartContract {
  readonly pubkey: ByteString;

  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }

  public spend(msg: ByteString, sig: ByteString) {
    assert(verifySLHDSA_SHA2_128f(msg, sig, this.pubkey));
  }
}
"""

MODULE = "runar_compiler.codegen.slh_dsa"


def compile_probe():
    return compile_from_source_str_with_result(SOURCE, "SlhDsaProbe.runar.ts")


def diagnostics(result) -> str:
    return "\n".join(d.message for d in result.diagnostics)


@pytest.fixture
def restore_module():
    """Swap the module out and put the real one back, whatever the test does."""
    saved = sys.modules.get(MODULE)
    yield
    if saved is None:
        sys.modules.pop(MODULE, None)
    else:
        sys.modules[MODULE] = saved


def test_the_real_module_still_compiles():
    """Control. Without it, every assertion below passes on a broken pipeline."""
    res = compile_probe()
    assert res.success, diagnostics(res)
    assert res.artifact is not None and res.artifact.script


def test_an_import_error_from_inside_the_codegen_is_not_reported_as_a_missing_module(
    restore_module,
):
    stub = types.ModuleType(MODULE)

    def exploding_emit(_emit, _param_key):
        raise ImportError("No module named 'hashlib_ng'")

    stub.emit_verify_slh_dsa = exploding_emit
    sys.modules[MODULE] = stub

    res = compile_probe()
    assert not res.success, "the exploding codegen module was not noticed at all"

    msg = diagnostics(res)
    assert "Please implement" not in msg, (
        "the compiler told the author to implement a module that is present, "
        "and discarded the real ImportError: " + msg
    )
    assert "hashlib_ng" in msg, (
        "the real cause is not recoverable from the diagnostic: " + msg
    )


def test_a_genuinely_missing_module_still_says_so(restore_module):
    """The message the handler was written for must survive the narrowing."""

    class RefusingFinder:
        """Make the import itself fail, the way an absent module would."""

        def find_module(self, fullname, path=None):  # py2-style hook, ignored
            return None

        def find_spec(self, fullname, path=None, target=None):
            if fullname == MODULE:
                raise ImportError(f"No module named {fullname!r}")
            return None

    sys.modules.pop(MODULE, None)
    finder = RefusingFinder()
    sys.meta_path.insert(0, finder)
    try:
        res = compile_probe()
    finally:
        sys.meta_path.remove(finder)

    assert not res.success
    msg = diagnostics(res)
    assert "SLH-DSA codegen module not available" in msg, msg
