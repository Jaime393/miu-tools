#!/usr/bin/env python3
"""Compatibility CLI: the canonical implementation is audit_record_generator.py."""
from pathlib import Path
import runpy

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).with_name("audit_record_generator.py")), run_name="__main__")
