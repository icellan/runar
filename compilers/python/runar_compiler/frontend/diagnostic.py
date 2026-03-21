"""Structured compiler diagnostics."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from runar_compiler.frontend.ast_nodes import SourceLocation


class Severity:
    ERROR = "error"
    WARNING = "warning"


@dataclass
class Diagnostic:
    """A single compiler diagnostic (error or warning)."""
    message: str
    severity: str  # Severity.ERROR or Severity.WARNING
    loc: Optional[SourceLocation] = None

    def format_message(self) -> str:
        """Format with optional file:line:column prefix."""
        if self.loc and self.loc.file:
            if self.loc.column > 0:
                return f"{self.loc.file}:{self.loc.line}:{self.loc.column}: {self.message}"
            return f"{self.loc.file}:{self.loc.line}: {self.message}"
        return self.message

    def __str__(self) -> str:
        return self.format_message()
