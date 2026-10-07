#!/usr/bin/env python3
"""Scalability benchmark: 1K, 10K, 100K rows.

Measures: duration, rows/sec, peak memory (if tracemalloc available).
"""

import json
import os
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_quality_platform.validation.engine import ValidationEngine
from data_quality_platform.rules.registry import RuleRegistry
from data_quality_platform.generation.synthetic import SyntheticDataGenerator


def benchmark_size(rows: int, seed: int = 20260821) -> dict:
    """Benchmark validation for a given row count."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(project_root, "data", "generated")
    ev_dir = os.path.join(project_root, "evidence", "benchmarks")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(ev_dir, exist_ok=True)

    csv_path = os.path.join(data_dir, f"bench_{rows}.csv")
    out_path = os.path.join(data_dir, f"bench_{rows}_out.csv")
    run_id = f"bench_{rows}"

    # Generate
    gen = SyntheticDataGenerator(seed=seed)
    gen.generate(rows, csv_path)

    # Benchmark
    tracemalloc.start()
    start = time.time()

    engine = ValidationEngine(
        rules=RuleRegistry.create_default(),
        run_id=run_id,
        evidence_dir=os.path.join(ev_dir, run_id),
    )
    result = engine.validate(csv_path, out_path)

    elapsed = time.time() - start
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "rows": rows,
        "duration_seconds": round(elapsed, 3),
        "rows_per_second": round(rows / elapsed, 1) if elapsed > 0 else 0,
        "peak_memory_mb": round(peak_mem / 1024 / 1024, 2),
        "success": result.success,
        "monitoring_score": result.monitoring_score,
        "error": result.error,
    }


def main():
    sizes = [1000, 10000, 100000]
    # Optionally add 1M if available
    # sizes.append(1000000)

    results = []
    for size in sizes:
        print(f"Benchmarking {size} rows...")
        result = benchmark_size(size)
        results.append(result)
        print(f"  {size}: {result['duration_seconds']}s, {result['rows_per_second']} rows/sec, {result['peak_memory_mb']}MB peak")

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ev_dir = os.path.join(project_root, "evidence", "benchmarks")
    os.makedirs(ev_dir, exist_ok=True)
    report_path = os.path.join(ev_dir, "benchmark.json")
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": sys.platform,
        "python_version": sys.version,
        "benchmarks": results,
        "note": (
            "800M-row performance is NOT claimed. "
            "Production-scale execution is intended for ClickHouse. "
            "These benchmarks measure file-based processing throughput and "
            "peak memory on the machine that runs them. The engine is "
            "streaming per row, but total in-process memory is O(N) in the "
            "row count (id_set and row lineage buffers grow with every "
            "processed row); see the ValidationEngine docstring and "
            "FINAL_SCALE_REPORT.md for the measured evidence."
        ),
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nBenchmark report: {report_path}")


if __name__ == "__main__":
    main()
