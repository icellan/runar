from pathlib import Path


def test_compile():
    """Only compile-check is feasible: the runar Python runtime does not
    expose p256_mul/p256_add/p256_mul_gen/p256_on_curve as host functions, so
    the contract module cannot be loaded for native invocation. The frontend
    still parses, validates, and type-checks it as valid Runar."""
    from runar import compile_check
    source_path = str(Path(__file__).parent / "P256Primitives.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "P256Primitives.runar.py")
