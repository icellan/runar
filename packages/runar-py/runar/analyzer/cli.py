"""CLI entry: read a hex script from a file path (argv[1]) and write the
analyzer report as JSON to stdout.

Invoke via `python -m runar.analyzer <hex-file>`.
"""

from __future__ import annotations

import sys

from . import analyze_script
from .emit import report_to_json


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: python -m runar.analyzer <hex-file>\n")
        return 2
    hex_path = argv[1]
    with open(hex_path, "r", encoding="utf-8") as fh:
        hex_text = fh.read().strip()
    report = analyze_script(hex_text)
    sys.stdout.write(report_to_json(report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
