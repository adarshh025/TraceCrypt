"""Entrypoint for python -m tracecrypt.cli."""

import sys
from tracecrypt.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
