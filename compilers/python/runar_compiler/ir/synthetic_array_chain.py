"""N-096 -- the ``syntheticArrayChain`` validity rule for ``--ir`` input.

Port of ``packages/runar-compiler/src/ir/synthetic-array-chain.ts``: same rule,
same order, same words (``conformance/negatives/ir-synthetic-array-chain.test.ts``).

1. at most ``MAX_SYNTHETIC_ARRAY_DEPTH`` levels (the regrouper's 1024 passes
   are the only nesting bound the pipeline has);
2. every level has ``0 <= index < length``;
3. level k's base is level k-1's ``<base>__<index>``, and the property is
   named ``<innermost base>__<innermost index>``;
4. the leaves sharing a root are exactly one expansion: contiguous, row-major
   from element 0, one type and one list of level lengths, and complete.

Before this rule this tier published the F-105 probe's 1100-level property as
a scalar constructor parameter.
"""

from __future__ import annotations

from .types import ANFProgram

#: The deepest chain the regrouper's 1024-pass cap can consume.
MAX_SYNTHETIC_ARRAY_DEPTH = 1023


def _refuse(prop: str, detail: str) -> ValueError:
    return ValueError(
        f"IR validation: malformed syntheticArrayChain on property '{prop}': {detail}"
    )


def _leaf_name(root: str, tup: list[int]) -> str:
    return root + "".join(f"__{i}" for i in tup)


def _complete(fam: dict) -> bool:
    return all(i == l - 1 for i, l in zip(fam["tuple"], fam["lengths"]))


def _next(fam: dict) -> list[int]:
    t = list(fam["tuple"])
    for k in range(len(t) - 1, -1, -1):
        if t[k] + 1 < fam["lengths"][k]:
            t[k] += 1
            return t
        t[k] = 0
    return t


def _expects(root: str, typ: str, lengths: list[int], tup: list[int]) -> str:
    return (
        f"'{root}' expects its element '{_leaf_name(root, tup)}' here "
        f"(type {typ}, level lengths [{', '.join(str(l) for l in lengths)}])"
    )


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_levels(name: str, chain: list) -> None:
    if len(chain) > MAX_SYNTHETIC_ARRAY_DEPTH:
        raise _refuse(name, f"{len(chain)} levels exceed the limit of {MAX_SYNTHETIC_ARRAY_DEPTH}")
    for k, lvl in enumerate(chain):
        if (
            not isinstance(lvl, dict)
            or not isinstance(lvl.get("base"), str)
            or not _is_int(lvl.get("index"))
            or not _is_int(lvl.get("length"))
        ):
            raise _refuse(name, f"level {k} is not a {{base: string, index: integer, length: integer}} object")
        index, length = lvl["index"], lvl["length"]
        if not (0 <= index < length):
            raise _refuse(
                name,
                f"level {k} has index {index} and length {length}; "
                "expand-fixed-arrays writes 0 <= index < length",
            )
        if k > 0:
            want = f"{chain[k - 1]['base']}__{chain[k - 1]['index']}"
            if lvl["base"] != want:
                raise _refuse(name, f"level {k} has base '{lvl['base']}'; expand-fixed-arrays writes '{want}'")
    inner = chain[-1]
    want = f"{inner['base']}__{inner['index']}"
    if name != want:
        raise _refuse(
            name,
            f"its innermost level is element {inner['index']} of '{inner['base']}'; "
            f"expand-fixed-arrays names that property '{want}'",
        )


def assert_synthetic_array_chains(program: ANFProgram) -> None:
    """Raise the shared diagnostic for the first chain the rule refuses."""
    open_fam: dict | None = None
    seen: set[str] = set()

    def close() -> None:
        nonlocal open_fam
        if open_fam is not None and not _complete(open_fam):
            raise _refuse(
                open_fam["last"],
                f"'{open_fam['root']}' ends here, before its element "
                f"'{_leaf_name(open_fam['root'], _next(open_fam))}'",
            )
        open_fam = None

    for prop in program.properties:
        chain = prop.synthetic_array_chain or []
        if not isinstance(chain, list):
            raise _refuse(prop.name, "the chain is not an array")
        root = chain[0].get("base") if chain and isinstance(chain[0], dict) else None
        if open_fam is not None and root != open_fam["root"]:
            close()
        if not chain:
            continue
        _check_levels(prop.name, chain)
        tup = [lvl["index"] for lvl in chain]
        lengths = [lvl["length"] for lvl in chain]

        if open_fam is not None:
            if _complete(open_fam):
                raise _refuse(prop.name, f"'{open_fam['root']}' already ended before this property")
            want = _next(open_fam)
            if prop.type != open_fam["type"] or lengths != open_fam["lengths"] or tup != want:
                raise _refuse(prop.name, _expects(open_fam["root"], open_fam["type"], open_fam["lengths"], want))
            open_fam["tuple"] = want
            open_fam["last"] = prop.name
            continue

        if root in seen:
            raise _refuse(prop.name, f"'{root}' already ended before this property")
        start = [0] * len(chain)
        if tup != start:
            raise _refuse(prop.name, _expects(root, prop.type, lengths, start))
        seen.add(root)
        open_fam = {"root": root, "type": prop.type, "lengths": lengths, "tuple": tup, "last": prop.name}
    close()
