"""
Direct module execution entry point for soc-analyzer.
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
