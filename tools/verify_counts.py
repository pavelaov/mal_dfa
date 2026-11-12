"""Verify the test-archive contract of the artifact against the paper's
research dossier (paper Section VIII-F, "Executed functional
validation").

Checks (all textual scans, no test execution)
---------------------------------------------
1. The total number of ``test_*`` functions in ``tests/`` equals 22
   (the paper states 22 unit tests, 0 failures, 0 errors).
2. The case-count constants claimed by the research dossier exist in
   ``tests/`` and equal the claimed values:

   ==================  =======  ==============================================
   Constant            Value    Paper claim (research dossier)
   ==================  =======  ==============================================
   DPF_CASES           21,840   exhaustive small-domain DPF target, query and
                                payload cases (thm:dpf-correct)
   GAC_CASES            2,728   party-local streaming GaC vs materialized
                                evaluation comparisons (thm:gac)
   DCF_CASES            1,364   DCF comparisons (thm:dcf)
   MERSENNE_CASES      20,004   CPU checks of the GPU Mersenne multiplication
                                formula vs arbitrary-precision arithmetic
                                (Sec. VI-E)
   TRUNC_CASES            124   signed-truncation cases (thm:cmp-trunc)
   ==================  =======  ==============================================

It prints the comparison table and exits 0 iff every check passes.

Usage::

    python tools/verify_counts.py            # scan tests/ only (default)
    python tools/verify_counts.py --run      # also execute the 22 tests
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
TESTS_DIR = REPO_ROOT / "tests"

# Constant name -> (claimed value, paper claim / research-dossier text)
CLAIMS = {
    "DPF_CASES": (21840,
                  "21,840 exhaustive small-domain DPF target/query/payload "
                  "cases (thm:dpf-correct)"),
    "GAC_CASES": (2728,
                  "2,728 party-local comparisons between streaming GaC and "
                  "materialized evaluation (thm:gac)"),
    "DCF_CASES": (1364,
                  "1,364 DCF comparisons (thm:dcf)"),
    "MERSENNE_CASES": (20004,
                       "20,004 CPU checks of the GPU Mersenne multiplication "
                       "formula against arbitrary-precision arithmetic, "
                       "including boundary operands (Sec. VI-E)"),
    "TRUNC_CASES": (124,
                    "124 signed-truncation cases (thm:cmp-trunc)"),
}

EXPECTED_TEST_COUNT = 22

# Matches ``NAME = <int>``, ``NAME: int = <int>`` and ``NAME: Final[int] = <int>`` assignments (digits may use ``_`` separators), optionally followed by a comment.
_CONST_RE = re.compile(r"^\s*(?P<name>[A-Z][A-Z0-9_]*)\s*"
                       r"(?::\s*(?:int|Final(?:\[int\])?))?\s*=\s*"
                       r"(?P<value>[0-9][0-9_]*)\s*(?:#.*)?$")
# Matches function definitions named test_* (including test methods of unittest.TestCase classes, which are indented).
_TESTFN_RE = re.compile(r"^\s*def\s+(test_[A-Za-z0-9_]*)\s*\(")


def scan_tests():
    """Return (test_files, per-file test counts, constant occurrences).

    Occurrences: dict name -> list of (file, line, value).  Every .py
    file under tests/ is scanned, so shared helper modules that define
    the case-count constants are found too.
    """
    if not TESTS_DIR.is_dir():
        raise SystemExit(f"tests directory not found: {TESTS_DIR}")
    files = sorted(TESTS_DIR.glob("**/*.py"))
    if not files:
        raise SystemExit(f"no .py files found under {TESTS_DIR}")
    counts = {}
    occurrences = {name: [] for name in CLAIMS}
    for path in files:
        rel = path.relative_to(REPO_ROOT)
        n = 0
        for line_no, line in enumerate(path.read_text(
                encoding="utf-8").splitlines(), start=1):
            if _TESTFN_RE.match(line):
                n += 1
            m = _CONST_RE.match(line)
            if m and m.group("name") in CLAIMS:
                occurrences[m.group("name")].append(
                    (str(rel), line_no,
                     int(m.group("value").replace("_", ""))))
        counts[str(rel)] = n
    return files, counts, occurrences


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify the test-archive contract against the paper's "
                    "research dossier.")
    parser.add_argument("--run", action="store_true",
                        help="also execute the unittest suite after the "
                             "scan passes")
    args = parser.parse_args(argv)

    files, counts, occurrences = scan_tests()
    ok = True

    print("Test files found under tests/:")
    for f in files:
        rel = str(f.relative_to(REPO_ROOT))
        print(f"  {rel}: {counts[rel]} test function(s)")
    total = sum(counts.values())
    print(f"Total test functions: {total} (paper claims "
          f"{EXPECTED_TEST_COUNT} unit tests)")
    if total != EXPECTED_TEST_COUNT:
        print(f"FAIL: expected exactly {EXPECTED_TEST_COUNT} test_ "
              f"functions, found {total}.")
        ok = False
    else:
        print("OK: test count matches the paper's 22 unit tests.")

    print()
    print("Case-count constants (research dossier):")
    hdr = f"{'Constant':<16} {'Claimed':>9} {'Found':>9}  Claim"
    print(hdr)
    print("-" * len(hdr))
    for name, (claimed, text) in CLAIMS.items():
        hits = occurrences[name]
        found = "missing" if not hits else str(hits[0][2])
        marker = "OK "
        if not hits:
            marker = "FAIL"
            ok = False
        elif hits[0][2] != claimed:
            marker = "FAIL"
            ok = False
        elif len(hits) > 1:
            values = {v for _, _, v in hits}
            if values != {claimed}:
                marker = "FAIL"
                ok = False
        print(f"{marker} {name:<13} {claimed:>9,} {found:>9}  {text}")
        for fname, line_no, value in hits:
            if value != claimed:
                print(f"     -> {fname}:{line_no} = {value} (claimed "
                      f"{claimed})")
            elif marker == "FAIL":
                print(f"     -> defined at {fname}:{line_no}")
        if not hits:
            print(f"     -> no assignment of {name} found in tests/; "
                  f"define {name} = {claimed}")

    print()
    if ok:
        print("All archive-contract checks passed.")
    else:
        print("Archive-contract checks FAILED; fix tests/ before "
              "submission.")
        return 1

    if args.run:
        print()
        print("Executing the unittest suite (python tools/run_tests.py)...")
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "run_tests.py")],
            cwd=str(REPO_ROOT))
        return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
