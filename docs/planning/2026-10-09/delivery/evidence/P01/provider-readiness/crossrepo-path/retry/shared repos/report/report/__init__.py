"""report - formats summaries of numeric series. Depends on the calc repo."""
import os
import sys

sys.path.insert(0, os.environ.get("CALC_PATH", os.path.expanduser("~/hubdemo/calc")))
from calc import mean  # noqa: E402


def summary(name, xs):
    return f"{name}: n={len(xs)} mean={mean(xs):.2f}"
