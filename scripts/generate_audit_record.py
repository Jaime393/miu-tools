#!/usr/bin/env python3
"""Compatibility CLI for the single canonical audit generator."""
from pathlib import Path
import runpy

if __name__ == "__main__":
    runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "tools" / "audit_record_generator.py"),
        run_name="__main__",
    )
