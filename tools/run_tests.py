"""Run the full VIGOR-DFA unit-test suite with stdlib unittest discovery.

The paper (Section VIII-F) reports 22 unit tests with 0 failures and 0
errors; ``tools/verify_counts.py`` checks that the archive contains
exactly 22 test functions and the claimed case counts before or after
running this entry point.

Usage (from the artifact root, or anywhere)::

    python tools/run_tests.py            # discover and run tests/
    python tools/run_tests.py -v         # verbose
    python tools/run_tests.py test_dpf   # a single module (path or name)
"""

import argparse
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
TESTS_DIR = REPO_ROOT / "tests"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("module", nargs="*",
                        help="optional test module(s) relative to tests/, "
                             "e.g. test_dpf")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="verbose output")
    args = parser.parse_args(argv)

    if not TESTS_DIR.is_dir():
        print(f"tests directory not found: {TESTS_DIR}", file=sys.stderr)
        return 1

    verbosity = 2 if args.verbose else 1
    if args.module:
        names = []
        for m in args.module:
            m = m.replace("\\", "/").rstrip("/")
            if m.endswith(".py"):
                m = m[:-3]
            if "/" in m:
                m = m.rsplit("/", 1)[1]
            names.append(m if m.startswith("test") else f"test_{m}")
        # loadTestsFromNames resolves the names as importable top-level modules, so the tests directory must be on sys.path; the test modules import vigor_dfa, so the artifact root must be too.
        sys.path.insert(0, str(REPO_ROOT))
        sys.path.insert(0, str(TESTS_DIR))
        suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    else:
        suite = unittest.defaultTestLoader.discover(
            start_dir=str(TESTS_DIR), pattern="test_*.py",
            top_level_dir=str(REPO_ROOT))

    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    print()
    print(f"Tests run: {result.testsRun}, failures: "
          f"{len(result.failures)}, errors: {len(result.errors)}, "
          f"skipped: {len(result.skipped)}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
