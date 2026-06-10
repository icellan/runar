"""Types for the Bitcoin Script static analyzer.

See spec/script-analyzer-format.md for the normative cross-tier contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


# --- Push encoding kinds (spec §6) -------------------------------------------

PUSH_ENCODING_DIRECT = "direct"
PUSH_ENCODING_PUSHDATA1 = "pushdata1"
PUSH_ENCODING_PUSHDATA2 = "pushdata2"
PUSH_ENCODING_PUSHDATA4 = "pushdata4"
PUSH_ENCODING_OPN = "opN"


@dataclass
class ParsedOpcode:
    """A single parsed opcode (or synthetic RAW_SPAN step)."""

    offset: int           # byte offset of the opcode in the script
    opcode: int           # the byte value (0..255), or -1 for synthetic RAW_SPAN
    name: str             # canonical name (§4)
    size: int             # total bytes consumed (opcode + length-prefix + data)
    # Push-specific fields (None for non-pushes):
    data_length: Optional[int] = None
    push_encoding: Optional[str] = None
    truncated: bool = False
    # Synthetic raw-span arity (only set on RAW_SPAN):
    raw_span_arity: Optional[tuple] = None


@dataclass
class RawScriptSpan:
    offset: int
    length: int
    in_arity: int
    out_arity: int


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    offset: Optional[int] = None
    opcode: Optional[str] = None
    path: Optional[str] = None


@dataclass
class ExecutionPath:
    id: int
    description: str
    branch_choices: List[bool]
    reachable: bool
    has_check_sig: bool
    stack_depth_at_end: int


@dataclass
class Summary:
    total_paths: int
    reachable_paths: int
    paths_with_check_sig: int
    paths_without_check_sig: int
    max_stack_depth: int
    script_size_bytes: int


@dataclass
class AnalyzerReport:
    script: str
    script_size: int
    findings: List[Finding] = field(default_factory=list)
    paths: List[ExecutionPath] = field(default_factory=list)
    summary: Optional[Summary] = None


@dataclass
class BranchFrame:
    if_index: int        # index into the parsed-opcode list
    else_index: int      # -1 if no ELSE seen yet
    is_notif: bool


@dataclass
class CompletedBranch:
    if_index: int
    else_index: int      # -1 if no ELSE
    endif_index: int
    is_notif: bool


@dataclass
class AnalyzeOptions:
    raw_script_spans: Optional[List[RawScriptSpan]] = None
