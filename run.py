#!/usr/bin/env python
"""Convenience launcher, so `python run.py` works the same as `python -m avguard`."""

import sys

from avguard.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
