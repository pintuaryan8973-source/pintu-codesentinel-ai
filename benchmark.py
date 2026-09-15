#!/usr/bin/env python3
import json
import time
from pathlib import Path
from reviewer import scan_file

ROOT = Path(__file__).parent
CASES = ROOT / "benchmark_cases"

EXPECTED = {
    "case_python.py": {"PY001", "PY002", "PY007", "PY008"},
    "case_web.js": {"JS001", "JS002"},
}


def main():
    start = time.perf_counter()
    tp = fp = fn = 0
    per_file = []

    for filename, expected in EXPECTED.items():
        path = CASES / filename
        detected = {f.rule for f in scan_file(path)}

        local_tp = len(detected & expected)
        local_fp = len(detected - expected)
        local_fn = len(expected - detected)

        tp += local_tp
        fp += local_fp
        fn += local_fn

        per_file.append({
            "file": filename,
            "expected": sorted(expected),
            "detected": sorted(detected),
            "tp": local_tp,
            "fp": local_fp,
            "fn": local_fn,
        })

    elapsed = time.perf_counter() - start

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    result = {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "avg_time_seconds": elapsed / len(EXPECTED),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "cases": per_file,
    }

    print("\n" + "=" * 62)
    print("               LOCAL CODE REVIEW BENCHMARK")
    print("=" * 62)
    print(f"Precision : {precision * 100:.2f}%")
    print(f"Recall    : {recall * 100:.2f}%")
    print(f"F1 Score  : {f1 * 100:.2f}%")
    print(f"Avg Time  : {result['avg_time_seconds']:.6f}s")
    print(f"TP / FP / FN : {tp} / {fp} / {fn}")
    print("=" * 62)

    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
