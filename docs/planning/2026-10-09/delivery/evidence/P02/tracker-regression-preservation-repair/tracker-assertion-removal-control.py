"""Check rejection when the reviewed tracker assertion is removed in memory."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path

root = Path.cwd()
base = root / 'docs/planning/2026-10-09/delivery'
spec = importlib.util.spec_from_file_location('regression_check', base / 'check_regressions.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
manifest = check.read_manifest()
rel = 'docs/planning/2026-10-09/delivery/test_track.py'
raw = (root / rel).read_bytes()
method = next(n for n in ast.walk(ast.parse(raw)) if isinstance(n, ast.FunctionDef) and n.name == 'test_predecessor_cannot_be_bypassed')
assertion = next(n for n in method.body if isinstance(n, ast.With))
assert isinstance(assertion.items[0].context_expr, ast.Call)
assert assertion.items[0].context_expr.func.attr == 'assertRaisesRegex'
lines = raw.decode().splitlines(keepends=True)
lines[assertion.lineno - 1:assertion.end_lineno] = [' ' * assertion.col_offset + 'pass  # removed predecessor rejection assertion\n']
mutated = ''.join(lines).encode()
ast.parse(mutated)
positive = check.verify(manifest)
negative = check.verify(manifest, {rel: mutated})
assert positive == []
assert negative == [rel + ': invalid or stale reviewed replacement']
print(json.dumps({'sourceSHA256': hashlib.sha256(raw).hexdigest(), 'mutationSHA256': hashlib.sha256(mutated).hexdigest(), 'removedMethod': method.name, 'removedAssertion': 'assertRaisesRegex', 'candidateErrors': positive, 'mutationErrors': negative, 'repositorySourceChanged': False}, indent=2))
