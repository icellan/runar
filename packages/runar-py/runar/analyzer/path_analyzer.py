"""Path enumeration and per-path analysis per spec §7."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .stack_analyzer import analyze_stack_linear, stack_effect
from .types import (
    BranchFrame,
    CompletedBranch,
    ExecutionPath,
    Finding,
    ParsedOpcode,
)


# Verification opcodes (spec §7.5): if a collected path contains none of
# these, UNCONDITIONALLY_SUCCEEDS is emitted.
_VERIFICATION_OPS = {
    0x69,  # OP_VERIFY
    0x6a,  # OP_RETURN
    0x88,  # OP_EQUALVERIFY
    0x9d,  # OP_NUMEQUALVERIFY
    0xac,  # OP_CHECKSIG
    0xad,  # OP_CHECKSIGVERIFY
    0xae,  # OP_CHECKMULTISIG
    0xaf,  # OP_CHECKMULTISIGVERIFY
}

_SIGCHECK_OPS = {0xac, 0xad, 0xae, 0xaf}

_IF_OPS = {0x63, 0x64}            # OP_IF, OP_NOTIF
_BRANCH_MARKERS = {0x63, 0x64, 0x67, 0x68}  # +OP_ELSE +OP_ENDIF

MAX_PATHS = 256


@dataclass
class PathAnalysisResult:
    paths: List[ExecutionPath]
    findings: List[Finding]


# Spec v1.2 §5.1: render symbolically when 2^num_branches overflows the
# canonical TS reference's safe-integer range.
_LARGE_BRANCH_THRESHOLD = 53


def _match_branches(
    opcodes: List[ParsedOpcode],
) -> Tuple[List[CompletedBranch], List[Finding]]:
    """Walk opcodes to pair OP_IF/OP_NOTIF with OP_ELSE/OP_ENDIF.

    Emits UNBALANCED_IF_ENDIF findings for stray markers or unclosed
    frames.
    """
    findings: List[Finding] = []
    stack: List[BranchFrame] = []
    completed: List[CompletedBranch] = []

    for i, op in enumerate(opcodes):
        if op.opcode in _IF_OPS:
            stack.append(
                BranchFrame(
                    if_index=i, else_index=-1, is_notif=(op.opcode == 0x64)
                )
            )
        elif op.opcode == 0x67:  # OP_ELSE
            if not stack:
                findings.append(
                    Finding(
                        severity="error",
                        code="UNBALANCED_IF_ENDIF",
                        message="OP_ELSE without matching OP_IF",
                        offset=op.offset,
                        opcode=op.name,
                    )
                )
            else:
                stack[-1].else_index = i
        elif op.opcode == 0x68:  # OP_ENDIF
            if not stack:
                findings.append(
                    Finding(
                        severity="error",
                        code="UNBALANCED_IF_ENDIF",
                        message="OP_ENDIF without matching OP_IF",
                        offset=op.offset,
                        opcode=op.name,
                    )
                )
            else:
                frame = stack.pop()
                completed.append(
                    CompletedBranch(
                        if_index=frame.if_index,
                        else_index=frame.else_index,
                        endif_index=i,
                        is_notif=frame.is_notif,
                    )
                )

    # Unclosed frames at end of walk.
    for frame in stack:
        if_op = opcodes[frame.if_index]
        findings.append(
            Finding(
                severity="error",
                code="UNBALANCED_IF_ENDIF",
                message=(
                    f"{if_op.name} at offset {if_op.offset} "
                    f"has no matching OP_ENDIF"
                ),
                offset=if_op.offset,
                opcode=if_op.name,
            )
        )

    return completed, findings


def _path_description(
    choices: List[bool], if_opcodes: List[ParsedOpcode]
) -> str:
    parts: List[str] = []
    for idx, op in enumerate(if_opcodes):
        choice = choices[idx] if idx < len(choices) else True
        label = "IF" if op.opcode == 0x63 else "NOTIF"
        parts.append(f"{label}[{'true' if choice else 'false'}] at {op.offset}")
    return " -> ".join(parts)


def _collect_path_opcodes(
    opcodes: List[ParsedOpcode], choices: List[bool]
) -> List[ParsedOpcode]:
    """Traverse opcodes, taking THEN or ELSE bodies per choices vector.

    OP_IF / OP_NOTIF / OP_ELSE / OP_ENDIF themselves are NOT included.
    """
    # We do this iteratively without precomputing index maps. We track
    # nested IF depth so we can skip the correct ELSE/ENDIF.
    out: List[ParsedOpcode] = []
    i = 0
    n = len(opcodes)
    # Stack of "current decision still active": when we are inside a
    # branch we've chosen, we need to know what to do on ELSE/ENDIF.
    # We use an iterative skip approach instead — easier to reason about.

    choices_idx = 0
    # Each entry: True if we are in the THEN body and should skip on
    # ELSE; False if we are in the ELSE body and should consume ELSE
    # already handled (so should NOT skip on ELSE — should error if
    # nested ELSE but we don't here).
    skip_stack: List[bool] = []

    while i < n:
        op = opcodes[i]
        if op.opcode in _IF_OPS:
            # Take next decision.
            choice = (
                choices[choices_idx] if choices_idx < len(choices) else True
            )
            choices_idx += 1
            if choice:
                # Execute THEN body; on ELSE marker jump to ENDIF.
                skip_stack.append(True)  # in THEN — skip on ELSE
                i += 1
                continue
            else:
                # Skip THEN body — jump to ELSE+1 or ENDIF+1.
                # Walk forward respecting nesting.
                depth = 1
                j = i + 1
                while j < n and depth > 0:
                    o = opcodes[j].opcode
                    if o == 0x63 or o == 0x64:
                        depth += 1
                    elif o == 0x67 and depth == 1:
                        # Found matching ELSE: enter ELSE body.
                        depth = 0
                        break
                    elif o == 0x68:
                        depth -= 1
                        if depth == 0:
                            # No ELSE — done with this IF block entirely.
                            break
                    j += 1
                if j >= n:
                    # Unbalanced (shouldn't happen if structural ok); stop.
                    break
                if opcodes[j].opcode == 0x67:
                    # We're entering the ELSE body.
                    skip_stack.append(False)  # in ELSE
                    i = j + 1
                else:
                    # opcodes[j].opcode == 0x68 (ENDIF) — no ELSE existed.
                    i = j + 1
                continue
        elif op.opcode == 0x67:  # OP_ELSE
            # We're encountering ELSE while inside an active THEN body.
            # Skip to matching ENDIF.
            depth = 1
            j = i + 1
            while j < n and depth > 0:
                o = opcodes[j].opcode
                if o == 0x63 or o == 0x64:
                    depth += 1
                elif o == 0x68:
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j >= n:
                break
            if skip_stack:
                skip_stack.pop()
            i = j + 1
            continue
        elif op.opcode == 0x68:  # OP_ENDIF
            # End of current IF block (we executed either THEN-no-ELSE
            # or ELSE body).
            if skip_stack:
                skip_stack.pop()
            i += 1
            continue
        else:
            out.append(op)
            i += 1

    return out


def _flat_delta(
    opcodes: List[ParsedOpcode], start: int, end_exclusive: int
) -> Tuple[int, bool]:
    """Sum (pushes - pops) over opcodes[start:end_exclusive].

    Returns (delta, has_nested_branch). If the range contains a nested
    OP_IF/OP_NOTIF, the delta is undefined per spec §7.6.
    """
    delta = 0
    has_nested = False
    for j in range(start, end_exclusive):
        op = opcodes[j]
        if op.opcode in _IF_OPS:
            has_nested = True
            continue
        # OP_ELSE/OP_ENDIF (shouldn't appear inside well-structured
        # range) contribute 0.
        if op.opcode == 0x67 or op.opcode == 0x68:
            continue
        pops, pushes = stack_effect(op)
        delta += pushes - pops
    return delta, has_nested


def _branch_depth_findings(
    opcodes: List[ParsedOpcode], completed: List[CompletedBranch]
) -> List[Finding]:
    findings: List[Finding] = []
    for branch in completed:
        endif_op = opcodes[branch.endif_index]
        if branch.else_index < 0:
            # No ELSE.
            delta, nested = _flat_delta(
                opcodes, branch.if_index + 1, branch.endif_index
            )
            if nested:
                continue
            if delta != 0:
                msg = (
                    f"OP_IF body has net stack delta {delta}; "
                    "without an OP_ELSE the depth after OP_ENDIF "
                    "depends on the branch condition"
                )
                findings.append(
                    Finding(
                        severity="warning",
                        code="INCONSISTENT_BRANCH_DEPTH",
                        message=msg,
                        offset=endif_op.offset,
                        opcode="OP_ENDIF",
                    )
                )
        else:
            then_delta, then_nested = _flat_delta(
                opcodes, branch.if_index + 1, branch.else_index
            )
            else_delta, else_nested = _flat_delta(
                opcodes, branch.else_index + 1, branch.endif_index
            )
            if then_nested or else_nested:
                continue
            if then_delta != else_delta:
                msg = (
                    f"IF/ELSE branches leave different stack depths "
                    f"(THEN: {then_delta}, ELSE: {else_delta}) — "
                    "code after OP_ENDIF will see a depth that depends "
                    "on which branch ran"
                )
                findings.append(
                    Finding(
                        severity="warning",
                        code="INCONSISTENT_BRANCH_DEPTH",
                        message=msg,
                        offset=endif_op.offset,
                        opcode="OP_ENDIF",
                    )
                )
    return findings


def analyze_paths(opcodes: List[ParsedOpcode]) -> PathAnalysisResult:
    """Path enumeration + per-path analysis (spec §7)."""
    structural_findings: List[Finding] = []
    completed, branch_findings = _match_branches(opcodes)
    structural_findings.extend(branch_findings)

    # If structural errors exist, no paths.
    if any(f.code == "UNBALANCED_IF_ENDIF" for f in structural_findings):
        return PathAnalysisResult(paths=[], findings=structural_findings)

    if_opcodes = [op for op in opcodes if op.opcode in _IF_OPS]
    num_branches = len(if_opcodes)

    paths: List[ExecutionPath] = []
    per_path_findings: List[Finding] = []
    structural_findings_extra: List[Finding] = []

    if num_branches == 0:
        # Linear single path.
        # Strip IF/NOTIF/ELSE/ENDIF (defensive — none should be present).
        collected = [op for op in opcodes if op.opcode not in _BRANCH_MARKERS]
        linear = analyze_stack_linear(collected, initial_depth=0)

        # Per-path findings get path="linear (no branches)".
        desc = "linear (no branches)"
        for f in linear.findings:
            f.path = desc
            per_path_findings.append(f)

        has_check = any(op.opcode in _SIGCHECK_OPS for op in collected)
        path_obj = ExecutionPath(
            id=0,
            description=desc,
            branch_choices=[],
            reachable=True,
            has_check_sig=has_check,
            stack_depth_at_end=linear.final_depth,
        )
        paths.append(path_obj)

        if collected and not any(
            op.opcode in _VERIFICATION_OPS for op in collected
        ):
            per_path_findings.append(
                Finding(
                    severity="warning",
                    code="UNCONDITIONALLY_SUCCEEDS",
                    message=(
                        "Execution path has no verification opcode — "
                        "any unlocking input will satisfy it"
                    ),
                    path=desc,
                )
            )
    else:
        use_exact_count = num_branches < _LARGE_BRANCH_THRESHOLD
        if use_exact_count:
            exact = 1 << num_branches
            truncated = exact > MAX_PATHS
            n_paths = min(exact, MAX_PATHS)
            paths_clause = f"2^{num_branches} = {exact} paths"
        else:
            truncated = True
            n_paths = MAX_PATHS
            paths_clause = f"more than 2^{_LARGE_BRANCH_THRESHOLD} paths"

        if truncated:
            structural_findings_extra.append(
                Finding(
                    severity="warning",
                    code="PATHS_TRUNCATED",
                    message=(
                        f"Script has {num_branches} branch points "
                        f"({paths_clause}); "
                        f"analysis truncated to the first {MAX_PATHS}. "
                        "Consider reducing branching or splitting the "
                        "contract into smaller spending paths."
                    ),
                )
            )

        for combo in range(n_paths):
            # `combo` is bounded by MAX_PATHS = 256, so bits at positions
            # >= 8 are mathematically always 0. We explicitly clamp to
            # b < 31 to match the canonical TS reference, where JS `>>`
            # would otherwise mask the shift count to 5 bits and wrap.
            choices = [
                (((combo >> b) & 1) == 1) if b < 31 else False
                for b in range(num_branches)
            ]
            desc = _path_description(choices, if_opcodes)
            collected = _collect_path_opcodes(opcodes, choices)
            linear = analyze_stack_linear(collected, initial_depth=0)

            for f in linear.findings:
                f.path = desc
                per_path_findings.append(f)

            has_check = any(op.opcode in _SIGCHECK_OPS for op in collected)
            paths.append(
                ExecutionPath(
                    id=combo,
                    description=desc,
                    branch_choices=choices,
                    reachable=True,
                    has_check_sig=has_check,
                    stack_depth_at_end=linear.final_depth,
                )
            )

            if collected and not any(
                op.opcode in _VERIFICATION_OPS for op in collected
            ):
                per_path_findings.append(
                    Finding(
                        severity="warning",
                        code="UNCONDITIONALLY_SUCCEEDS",
                        message=(
                            "Execution path has no verification opcode — "
                            "any unlocking input will satisfy it"
                        ),
                        path=desc,
                    )
                )

    # Branch-depth findings appended after per-path findings.
    branch_depth_findings = _branch_depth_findings(opcodes, completed)

    # Order per spec §11.1 (within source the orchestrator appends):
    # pathFindings = structural (UNBALANCED) + per-path + branch-depth +
    #                PATHS_TRUNCATED. We replicate the TS reference's
    #                ordering: structural first, then per-path, then
    #                branch-depth. PATHS_TRUNCATED slots into structural.
    all_findings: List[Finding] = []
    all_findings.extend(structural_findings)
    all_findings.extend(structural_findings_extra)
    all_findings.extend(per_path_findings)
    all_findings.extend(branch_depth_findings)

    return PathAnalysisResult(paths=paths, findings=all_findings)
