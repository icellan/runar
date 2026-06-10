"""Emit an AnalyzerReport as canonical JSON per spec §3.5.

Output rules:
- 2-space indentation
- LF line endings
- Single trailing newline
- UTF-8, no BOM
- Non-ASCII emitted verbatim (no \\uXXXX escaping)
- Key order per §3.1/§3.2/§3.3/§3.4
- Optional keys (offset, opcode, path) OMITTED when absent
- Solidus '/' NOT escaped
"""

from __future__ import annotations

import json
from collections import OrderedDict
from typing import Any, Optional

from .types import AnalyzerReport, ExecutionPath, Finding, Summary


def _finding_to_dict(f: Finding) -> "OrderedDict[str, Any]":
    out: "OrderedDict[str, Any]" = OrderedDict()
    out["severity"] = f.severity
    out["code"] = f.code
    out["message"] = f.message
    if f.offset is not None:
        out["offset"] = f.offset
    if f.opcode is not None:
        out["opcode"] = f.opcode
    if f.path is not None:
        out["path"] = f.path
    return out


def _path_to_dict(p: ExecutionPath) -> "OrderedDict[str, Any]":
    out: "OrderedDict[str, Any]" = OrderedDict()
    out["id"] = p.id
    out["description"] = p.description
    out["branchChoices"] = list(p.branch_choices)
    out["reachable"] = p.reachable
    out["hasCheckSig"] = p.has_check_sig
    out["stackDepthAtEnd"] = p.stack_depth_at_end
    return out


def _summary_to_dict(s: Summary) -> "OrderedDict[str, Any]":
    out: "OrderedDict[str, Any]" = OrderedDict()
    out["totalPaths"] = s.total_paths
    out["reachablePaths"] = s.reachable_paths
    out["pathsWithCheckSig"] = s.paths_with_check_sig
    out["pathsWithoutCheckSig"] = s.paths_without_check_sig
    out["maxStackDepth"] = s.max_stack_depth
    out["scriptSizeBytes"] = s.script_size_bytes
    return out


def report_to_dict(report: AnalyzerReport) -> "OrderedDict[str, Any]":
    out: "OrderedDict[str, Any]" = OrderedDict()
    out["script"] = report.script
    out["scriptSize"] = report.script_size
    out["findings"] = [_finding_to_dict(f) for f in report.findings]
    out["paths"] = [_path_to_dict(p) for p in report.paths]
    out["summary"] = _summary_to_dict(report.summary) if report.summary else {}
    return out


def report_to_json(report: AnalyzerReport) -> str:
    """Serialize an AnalyzerReport to canonical JSON (with trailing newline)."""
    obj = report_to_dict(report)
    # json.dumps with indent=2 produces:
    #   key separator: ": "
    #   item separator: ",\n" between items, "\n" newline-indented per object/array
    # We want exactly that. Note: pass separators to ensure no trailing
    # space after commas (default with indent is (", ", ": "); but with
    # indent the commas come BEFORE newlines so the trailing space after
    # "," would never appear in pretty output anyway).
    # Use separators=(",", ": ") to guarantee no trailing whitespace.
    text = json.dumps(
        obj,
        ensure_ascii=False,
        indent=2,
        separators=(",", ": "),
        sort_keys=False,
    )
    return text + "\n"
