#!/usr/bin/env python3
"""Run backend unit tests with cwd=backend (safe from repo root)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"


def main() -> int:
    tests_dir = BACKEND / "tests"
    
    if not tests_dir.is_dir():
        print("Error: Expected backend/tests directory", file=sys.stderr)
        return 1
    
    # Check if actual test files exist
    test_files = list(tests_dir.glob("test_*.py"))
    if not test_files:
        print("Warning: No test_*.py files found in backend/tests/", file=sys.stderr)
        print("Note: Test discovery may still find tests with other naming patterns", file=sys.stderr)

    # Try pytest first (modern Python testing)
    try:
        cmd = [sys.executable, "-m", "pytest", "tests", "-v", "--tb=short"]
        proc = subprocess.run(cmd, cwd=str(BACKEND), check=False, timeout=300)
        if proc.returncode != 0:
            print(f"Test execution failed with return code {proc.returncode}.", file=sys.stderr)
        return proc.returncode
    except FileNotFoundError:
        # Fallback to unittest if pytest not available
        print("Note: pytest not found, falling back to unittest", file=sys.stderr)
        try:
            cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
            proc = subprocess.run(cmd, cwd=str(BACKEND), check=False, timeout=300)
            if proc.returncode != 0:
                print(f"Test execution failed with return code {proc.returncode}.", file=sys.stderr)
            return proc.returncode
        except subprocess.TimeoutExpired:
            print("Test execution timed out after 300 seconds", file=sys.stderr)
            return 1
        except subprocess.SubprocessError as e:
            print(f"Test execution failed due to subprocess error: {e}", file=sys.stderr)
            return 1
    except subprocess.TimeoutExpired:
        print("Test execution timed out after 300 seconds", file=sys.stderr)
        return 1
    except subprocess.SubprocessError as e:
        print(f"Test execution failed due to subprocess error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Test execution failed due to unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
