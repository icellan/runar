"""Allow `python -m runar.analyzer <hex-file>`."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv))
