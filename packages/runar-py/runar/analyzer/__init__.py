"""Bitcoin Script static analyzer (Python implementation).

See spec/script-analyzer-format.md for the normative cross-tier contract.
Public entry point: `analyze_script(hex_script, options=None) -> AnalyzerReport`.
"""

from __future__ import annotations

from typing import List, Optional

from .opcode_concerns import analyze_opcode_concerns
from .path_analyzer import analyze_paths
from .script_parser import collapse_raw_script_spans, normalize_hex, parse_script
from .sig_analyzer import analyze_sig_hygiene
from .stack_analyzer import analyze_stack_linear
from .types import (
    AnalyzeOptions,
    AnalyzerReport,
    ExecutionPath,
    Finding,
    ParsedOpcode,
    RawScriptSpan,
    Summary,
)

__all__ = [
    "analyze_script",
    "AnalyzerReport",
    "AnalyzeOptions",
    "Finding",
    "ExecutionPath",
    "RawScriptSpan",
    "Summary",
    "ParsedOpcode",
]


_SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2}


def _sort_findings(findings: List[Finding]) -> List[Finding]:
    """Stable sort by (severityRank, offsetRank). Spec §11.1.

    Python's `list.sort` is stable.
    """
    indexed = list(enumerate(findings))

    def key(item):
        idx, f = item
        sev_rank = _SEVERITY_RANK[f.severity]
        # offset_rank: f.offset if present else +infinity (largest).
        off_rank = f.offset if f.offset is not None else float("inf")
        return (sev_rank, off_rank, idx)

    indexed.sort(key=key)
    return [f for _, f in indexed]


def analyze_script(
    hex_script: str, options: Optional[AnalyzeOptions] = None
) -> AnalyzerReport:
    """Analyze a hex-encoded Bitcoin Script and return a structured report.

    Spec §11.
    """
    normalized = normalize_hex(hex_script)
    script_size_bytes = len(normalized) // 2

    if script_size_bytes == 0:
        # Empty-script special case (spec §2.1).
        return AnalyzerReport(
            script="",
            script_size=0,
            findings=[
                Finding(
                    severity="error",
                    code="INVALID_TERMINAL_STACK",
                    message="Empty script — no opcodes to execute",
                )
            ],
            paths=[],
            summary=Summary(
                total_paths=0,
                reachable_paths=0,
                paths_with_check_sig=0,
                paths_without_check_sig=0,
                max_stack_depth=0,
                script_size_bytes=0,
            ),
        )

    opcodes: List[ParsedOpcode] = parse_script(normalized)
    if options is not None and options.raw_script_spans:
        opcodes = collapse_raw_script_spans(opcodes, options.raw_script_spans)

    all_findings: List[Finding] = []

    # Step 1: path analysis.
    path_result = analyze_paths(opcodes)
    all_findings.extend(path_result.findings)

    # Step 2: linear-stack fallback only if zero paths AND no
    # UNBALANCED_IF_ENDIF.
    if not path_result.paths and not any(
        f.code == "UNBALANCED_IF_ENDIF" for f in path_result.findings
    ):
        linear = analyze_stack_linear(opcodes, initial_depth=0)
        all_findings.extend(linear.findings)

    # Step 3: sig hygiene.
    all_findings.extend(analyze_sig_hygiene(opcodes, path_result.paths))

    # Step 4: opcode concerns.
    all_findings.extend(analyze_opcode_concerns(opcodes, script_size_bytes))

    # Summary.
    paths = path_result.paths
    reachable_paths = [p for p in paths if p.reachable]
    paths_with_check = [p for p in reachable_paths if p.has_check_sig]
    paths_without_check = [
        p for p in reachable_paths if not p.has_check_sig
    ]

    # Spec §8.3 text says `max(p.stackDepthAtEnd)`; the goldens show the
    # TS reference floors this at 0 (probably initialized via
    # `Math.max(0, ...depths)` in the reference). Match the goldens.
    if paths:
        max_stack_depth = max(0, max(p.stack_depth_at_end for p in paths))
    else:
        max_stack_depth = 0

    summary = Summary(
        total_paths=len(paths),
        reachable_paths=len(reachable_paths),
        paths_with_check_sig=len(paths_with_check),
        paths_without_check_sig=len(paths_without_check),
        max_stack_depth=max_stack_depth,
        script_size_bytes=script_size_bytes,
    )

    return AnalyzerReport(
        script=normalized,
        script_size=script_size_bytes,
        findings=_sort_findings(all_findings),
        paths=paths,
        summary=summary,
    )
