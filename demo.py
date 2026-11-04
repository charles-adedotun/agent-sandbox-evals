#!/usr/bin/env python3
"""agent-sandbox-evals: Working Demonstration & Simulation Script.

Executes empirical containment benchmark across:
- Layer 0: Raw Host (Unsandboxed)
- Layer 1: Sanitized Subprocess / Filtered MCP (airlock / SafeDnsResolver / PathGuard)
- Layer 2: Hardened OCI Container Sandbox (Docker rootless, read-only rootfs, network=none)

Prints the quantitative Containment Failure Rate (CFR %) matrix and writes
reports to `./reports/demo_benchmark_report.md` and `.json`.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to sys.path so demo.py runs directly from checkout
project_root = Path(__file__).resolve().parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from tabulate import tabulate
from agent_sandbox_evals.models import AttackCategory, HarnessLayer
from agent_sandbox_evals.reporting.generator import ReportGenerator
from agent_sandbox_evals.runner import BenchmarkRunner
from agent_sandbox_evals.vectors.matrix import get_all_vectors


async def run_demo():
    print("=" * 80)
    print("🚀 AGENT-SANDBOX-EVALS: EMPIRICAL AI CONTROL & CONTAINMENT BENCHMARK")
    print("   Empirical Research Suite for AI Agent Sandboxing & MCP Defense")
    print("=" * 80)
    print(f"Platform: {os.uname().sysname} {os.uname().machine} | Python: {sys.version.split()[0]}")
    print("Target Layers:")
    print("  [0] Layer 0: Raw Host Subprocess (Unsandboxed)")
    print("  [1] Layer 1: Sanitized Subprocess / Filtered MCP (SafeDnsResolver + PathGuard)")
    print("  [2] Layer 2: Hardened OCI Container Sandbox (Docker non-root, read-only, net=none)")
    print("-" * 80)

    vectors = get_all_vectors()
    print(f"Loaded {len(vectors)} concrete adversarial test vectors.")
    print("Running containment trials...\n")

    # Real-time trial progress indicator
    def on_progress(result, current, total):
        breached_tag = "🔴 BREACH" if result.breached else "🟢 PASS"
        layer_name = result.layer.short_name
        print(f"  [{current:02d}/{total:02d}] {layer_name:<14} | {result.vector_id:<9} | {breached_tag} | {result.outcome.value:<14} ({result.duration_ms:5.1f}ms) - {result.vector_name[:35]}")

    runner = BenchmarkRunner(
        vectors=vectors,
        layers=[
            HarnessLayer.LAYER0_HOST,
            HarnessLayer.LAYER1_SANITIZED,
            HarnessLayer.LAYER2_CONTAINER,
        ],
        progress_callback=on_progress,
    )

    report = await runner.run()

    # Generate Reports
    reports_dir = project_root / "reports"
    generator = ReportGenerator(report)
    saved = generator.write_reports(output_dir=reports_dir, basename="demo_benchmark_report")

    print("\n" + "=" * 80)
    print("📊 EMPIRICAL CONTAINMENT BENCHMARK RESULTS")
    print("=" * 80)

    # Format Summary Table
    table_headers = [
        "Isolation Layer",
        "Vectors",
        "Blocked",
        "Contained",
        "Breached",
        "CFR (%)",
        "CSR (%)",
        "Avg Block (ms)",
        "Avg Exec (ms)",
        "Overhead (ms)",
    ]
    table_rows = []
    for layer_enum in [HarnessLayer.LAYER0_HOST, HarnessLayer.LAYER1_SANITIZED, HarnessLayer.LAYER2_CONTAINER]:
        s = report.layers[layer_enum]
        table_rows.append([
            s.layer_name,
            s.total_vectors,
            s.blocked_count,
            s.contained_count,
            s.failure_count,
            f"{s.cfr_pct:.1f}%",
            f"{s.csr_pct:.1f}%",
            f"{s.avg_detection_ms:.2f} ms" if s.avg_detection_ms > 0 else "N/A",
            f"{s.avg_execution_ms:.1f} ms",
            f"{s.baseline_latency_ms:.1f} ms",
        ])

    print(tabulate(table_rows, headers=table_headers, tablefmt="github"))
    print("\n" + "-" * 80)
    print("🛡️ CONTAINMENT FAILURE RATE (CFR %) BY ATTACK CATEGORY")
    print("-" * 80)

    cat_headers = [
        "Adversarial Category",
        "Layer 0: Raw Host",
        "Layer 1: Sanitized MCP",
        "Layer 2: OCI Container",
    ]
    cat_rows = []
    for cat in AttackCategory:
        cat_rows.append([
            cat.display_name,
            f"{report.category_cfr.get(cat, {}).get(HarnessLayer.LAYER0_HOST, 0.0):.1f}%",
            f"{report.category_cfr.get(cat, {}).get(HarnessLayer.LAYER1_SANITIZED, 0.0):.1f}%",
            f"{report.category_cfr.get(cat, {}).get(HarnessLayer.LAYER2_CONTAINER, 0.0):.1f}%",
        ])
    print(tabulate(cat_rows, headers=cat_headers, tablefmt="github"))

    print("\n" + "=" * 80)
    print("✅ BENCHMARK ARTIFACTS GENERATED")
    print(f"  • Markdown Report: {saved['markdown']}")
    print(f"  • JSON Dataset:    {saved['json']}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    asyncio.run(run_demo())
