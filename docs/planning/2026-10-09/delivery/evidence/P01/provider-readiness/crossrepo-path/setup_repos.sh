#!/usr/bin/env bash
# Two throwaway repos the demo orchestrations work in, so agents never touch a real
# project. Idempotent: an existing repo is left alone unless --reset is given.
#   calc    a tiny Python library (the "provider" repo)
#   report  an app that consumes calc (the "consumer" repo) - cross-repo work
set -euo pipefail
BASE="${HUBDEMO_BASE:-$HOME/hubdemo}"
[ "${1:-}" = "--reset" ] && rm -rf "$BASE"
mkdir -p "$BASE"

mk() {
  local name="$1"; shift
  local d="$BASE/$name"
  [ -d "$d/.git" ] && { echo "exists: $d"; return; }
  mkdir -p "$d"
  ( cd "$d"
    "$@"
    printf '%s\n' '__pycache__/' '*.pyc' > .gitignore
    git init -q -b main
    git -c user.name=hubdemo -c user.email=hubdemo@localhost add -A
    git -c user.name=hubdemo -c user.email=hubdemo@localhost commit -qm "initial $name"
  )
  echo "created: $d"
}

calc_files() {
  mkdir -p calc tests
  cat > calc/__init__.py <<'PY'
"""calc - a tiny arithmetic library used by the report app."""


def add(a, b):
    return a + b


def mean(xs):
    xs = list(xs)
    if not xs:
        raise ValueError("mean of empty sequence")
    return sum(xs) / len(xs)
PY
  cat > tests/test_calc.py <<'PY'
import unittest

from calc import add, mean


class T(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_mean(self):
        self.assertEqual(mean([1, 2, 3]), 2)


if __name__ == "__main__":
    unittest.main()
PY
  printf '# calc\n\nRun tests: `python3 -m unittest discover -s tests`\n' > README.md
}

report_files() {
  mkdir -p report tests
  cat > report/__init__.py <<'PY'
"""report - formats summaries of numeric series. Depends on the calc repo."""
import os
import sys

sys.path.insert(0, os.environ.get("CALC_PATH", os.path.expanduser("~/hubdemo/calc")))
from calc import mean  # noqa: E402


def summary(name, xs):
    return f"{name}: n={len(xs)} mean={mean(xs):.2f}"
PY
  cat > tests/test_report.py <<'PY'
import unittest

from report import summary


class T(unittest.TestCase):
    def test_summary(self):
        self.assertEqual(summary("a", [1, 2, 3]), "a: n=3 mean=2.00")


if __name__ == "__main__":
    unittest.main()
PY
  printf '# report\n\nRun tests: `python3 -m unittest discover -s tests`\n' > README.md
}

mk calc calc_files
mk report report_files
