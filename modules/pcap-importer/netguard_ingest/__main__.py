"""Allow ``python -m netguard_ingest``."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
