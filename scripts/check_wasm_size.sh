#!/usr/bin/env bash
set -euo pipefail

# Compares compiled release WASM artifact sizes against deployments/wasm-size-baseline.json
# and exits non-zero if any contract exceeds its baseline + maxRegressionPercent threshold.

WASM_DIR="${WASM_DIR:-target/wasm32v1-none/release}"
BASELINE_FILE="${BASELINE_FILE:-deployments/wasm-size-baseline.json}"

if [ ! -f "$BASELINE_FILE" ]; then
  echo "Baseline file not found: $BASELINE_FILE" >&2
  exit 1
fi

python3 - "$WASM_DIR" "$BASELINE_FILE" <<'PY'
import json
import os
import sys

wasm_dir, baseline_path = sys.argv[1], sys.argv[2]
with open(baseline_path, "r", encoding="utf-8") as f:
    baseline = json.load(f)

max_pct = float(baseline.get("maxRegressionPercent", 5.0))
contracts = baseline.get("contracts", {})

regressions = []
print("| Contract | Actual (bytes) | Baseline (bytes) | Delta (%) | Status |")
print("|---|---:|---:|---:|---|")

for name, limit in contracts.items():
    path = os.path.join(wasm_dir, name)
    if not os.path.exists(path):
        print(f"| `{name}` | missing | {limit} | - | SKIP |")
        continue
    size = os.path.getsize(path)
    delta_pct = ((size - limit) / limit) * 100.0 if limit > 0 else 0.0
    status = "OK"
    if delta_pct > max_pct:
        status = "REGRESSION"
        regressions.append((name, size, limit, delta_pct))
    print(f"| `{name}` | {size} | {limit} | {delta_pct:+.2f}% | {status} |")

if regressions:
    print("\nWASM size regression detected:", file=sys.stderr)
    for name, size, limit, pct in regressions:
        print(f"  - {name}: {size} bytes (baseline {limit}, {pct:+.2f}% > +{max_pct:.2f}%)", file=sys.stderr)
    sys.exit(1)
PY
