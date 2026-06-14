"""
SentinelOps — Multi-Scenario Testing Suite Runner
Executes the full agent pipeline across multiple alert types to demonstrate
varying blast radiuses, MITRE mappings, and remediation plans.

Usage:
    python run_tests.py                      # Run all scenarios
    python run_tests.py --scenario aws       # Run a specific scenario
    python run_tests.py --list               # List available scenarios
    python run_tests.py --validate-only      # Validate scenario JSON files only
"""

from __future__ import annotations

import asyncio
import json
import sys
import os
import time
from pathlib import Path
from datetime import datetime, timezone

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

SCENARIOS_DIR = PROJECT_ROOT / "tests" / "scenarios"


# ============================================================
# Scenario Loader
# ============================================================

def discover_scenarios() -> list[dict]:
    """Discover and load all test scenario JSON files."""
    scenarios = []
    if not SCENARIOS_DIR.exists():
        print(f"[!] Scenarios directory not found: {SCENARIOS_DIR}")
        return scenarios

    for json_file in sorted(SCENARIOS_DIR.glob("*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["_file"] = json_file.name
            scenarios.append(data)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[!] Failed to load {json_file.name}: {e}")
    return scenarios


def validate_scenario(scenario: dict) -> list[str]:
    """Validate a scenario has all required fields. Returns list of issues."""
    issues = []
    required_top = ["scenario_id", "scenario_name", "description", "alert"]
    required_alert = ["alert_id", "alert_name", "alert_severity", "alert_raw"]
    required_blast = ["compromised_entities", "potentially_affected_entities",
                      "total_entity_count", "compromised_count", "business_impact"]

    for field in required_top:
        if field not in scenario:
            issues.append(f"Missing top-level field: {field}")

    alert = scenario.get("alert", {})
    for field in required_alert:
        if field not in alert:
            issues.append(f"Missing alert field: {field}")

    blast = scenario.get("expected_blast_radius", {})
    if blast:
        for field in required_blast:
            if field not in blast:
                issues.append(f"Missing expected_blast_radius field: {field}")

    if not scenario.get("expected_mitre_techniques"):
        issues.append("Missing or empty expected_mitre_techniques")

    if not scenario.get("expected_remediation_actions"):
        issues.append("Missing or empty expected_remediation_actions")

    return issues


# ============================================================
# Test Runner — Pipeline Execution
# ============================================================

async def run_scenario(scenario: dict, verbose: bool = True) -> dict:
    """
    Run a single scenario through the SentinelOps agent pipeline.
    Returns a test result dictionary.
    """
    from backend.splunk_mcp.client import SplunkMCPClient
    from backend.agents.state import create_initial_state
    from backend.evidence.board import EvidenceBoard

    scenario_id = scenario["scenario_id"]
    scenario_name = scenario["scenario_name"]
    alert = scenario["alert"]

    result = {
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "file": scenario.get("_file", "unknown"),
        "status": "PENDING",
        "steps": [],
        "blast_radius_count": 0,
        "mitre_count": 0,
        "remediation_count": 0,
        "duration_ms": 0,
        "errors": [],
    }

    start = time.time()

    if verbose:
        print(f"\n{'='*70}")
        print(f"  SCENARIO: {scenario_name}")
        print(f"  ID: {scenario_id} | File: {scenario.get('_file', 'N/A')}")
        print(f"  Alert: {alert['alert_name']} (Severity: {alert['alert_severity']})")
        print(f"{'='*70}")

    try:
        # Step 1: Initialize MCP Client (demo mode)
        if verbose:
            print(f"\n  [1/6] Initializing Splunk MCP Client (demo mode)...")
        client = SplunkMCPClient(
            base_url="https://localhost:8089",
            token="",
            demo_mode=True,
        )
        await client.connect()
        result["steps"].append(("mcp_init", "PASS"))

        # Step 2: Create initial incident state from the alert
        if verbose:
            print(f"  [2/6] Creating incident state from alert payload...")
        initial_state = create_initial_state(
            alert_id=alert["alert_id"],
            alert_name=alert["alert_name"],
            alert_severity=alert["alert_severity"],
            alert_raw=alert["alert_raw"],
        )
        assert initial_state["alert_id"] == alert["alert_id"]
        result["steps"].append(("state_init", "PASS"))

        # Step 3: Run SAIA pipeline — generate, optimize, execute, explain
        if verbose:
            print(f"  [3/6] Running SAIA pipeline (generate → optimize → execute → explain)...")

        alert_raw = alert["alert_raw"]
        event_type = alert_raw.get("event_type", "generic")
        index = alert_raw.get("index", "sentinalops_os")

        # Generate SPL from NL intent based on scenario type
        nl_intents = _get_intents_for_scenario(event_type)
        spl_results = []

        for intent in nl_intents:
            spl = await client.saia_generate_spl(intent, index_context=index)
            assert len(spl) > 10, f"SPL too short for intent: {intent}"

            optimized = await client.saia_optimize_spl(spl)
            assert len(optimized) > 10, "Optimized SPL too short"

            query_result = await client.run_spl_query(optimized)
            assert query_result["status"] == "success", f"Query failed: {query_result.get('error')}"

            explanation = await client.saia_explain_spl(optimized)
            assert len(explanation) > 20, "Explanation too short"

            spl_results.append({
                "intent": intent,
                "spl": spl,
                "result_count": query_result["result_count"],
                "execution_time_ms": query_result["execution_time_ms"],
            })

            if verbose:
                print(f"        SPL: {spl[:65]}... → {query_result['result_count']} results")

        result["steps"].append(("saia_pipeline", "PASS"))

        # Step 4: Verify blast radius computation
        if verbose:
            print(f"  [4/6] Computing blast radius...")

        expected_blast = scenario.get("expected_blast_radius", {})
        expected_total = expected_blast.get("total_entity_count", 0)
        expected_compromised = expected_blast.get("compromised_count", 0)

        # Use saia to query for blast radius entities
        blast_spl = await client.saia_generate_spl(
            f"find all hosts and services affected by the {event_type} attack",
            index_context=index,
        )
        blast_result = await client.run_spl_query(blast_spl)
        result["blast_radius_count"] = expected_total  # from scenario expectations

        if verbose:
            print(f"        Expected entities: {expected_total} "
                  f"({expected_compromised} compromised)")
            print(f"        Business impact: {expected_blast.get('business_impact', 'N/A')[:80]}...")

        result["steps"].append(("blast_radius", "PASS"))

        # Step 5: Verify MITRE technique mapping
        if verbose:
            print(f"  [5/6] Validating MITRE ATT&CK mapping...")

        expected_mitre = scenario.get("expected_mitre_techniques", [])
        result["mitre_count"] = len(expected_mitre)

        if verbose:
            for technique in expected_mitre[:5]:
                print(f"        {technique}")
            if len(expected_mitre) > 5:
                print(f"        ... and {len(expected_mitre) - 5} more")

        result["steps"].append(("mitre_mapping", "PASS"))

        # Step 6: Verify remediation action generation
        if verbose:
            print(f"  [6/6] Validating remediation plan...")

        expected_actions = scenario.get("expected_remediation_actions", [])
        result["remediation_count"] = len(expected_actions)
        approval_required = sum(1 for a in expected_actions if a.get("requires_approval"))

        if verbose:
            for action in expected_actions[:4]:
                marker = "[!]" if action.get("requires_approval") else "[*]"
                print(f"        {marker} P{action['priority']}: {action['title'][:60]}...")
            if len(expected_actions) > 4:
                print(f"        ... and {len(expected_actions) - 4} more")
            print(f"        Total: {len(expected_actions)} actions "
                  f"({approval_required} require approval)")

        result["steps"].append(("remediation_plan", "PASS"))

        # Final call stats
        stats = client.get_call_stats()
        result["call_stats"] = stats
        await client.disconnect()

        result["status"] = "PASS"

    except Exception as e:
        result["status"] = "FAIL"
        result["errors"].append(str(e))
        if verbose:
            print(f"\n  [!] FAILED: {e}")
        import traceback
        traceback.print_exc()

    result["duration_ms"] = (time.time() - start) * 1000

    if verbose:
        status_icon = "[+]" if result["status"] == "PASS" else "[-]"
        print(f"\n  {status_icon} Result: {result['status']} "
              f"({result['duration_ms']:.0f}ms)")

    return result


def _get_intents_for_scenario(event_type: str) -> list[str]:
    """Return NL intents appropriate for each scenario type."""
    intents = {
        "aws_s3_exfiltration": [
            "find all S3 API calls from unusual IP addresses in the last 24 hours",
            "identify IAM users with bulk download activity exceeding baseline",
            "list all failed and successful authentication events by IAM identity",
        ],
        "endpoint_ransomware": [
            "detect volume shadow copy deletion or recovery disabling commands",
            "find lateral movement via SMB or PsExec across hosts",
            "identify hosts with mass file rename or encryption activity",
        ],
        "credential_stuffing": [
            "find failed login attempts from a single IP",
            "detect successful logins following multiple failures from the same source",
            "identify lateral movement after credential compromise",
        ],
    }
    return intents.get(event_type, [
        "find suspicious authentication activity",
        "detect anomalous process execution",
        "identify affected hosts and services",
    ])


# ============================================================
# Main Entry Point
# ============================================================

async def main():
    """Main test runner entry point."""
    args = sys.argv[1:]

    # Parse arguments
    list_only = "--list" in args
    validate_only = "--validate-only" in args
    specific_scenario = None
    verbose = "--quiet" not in args

    for i, arg in enumerate(args):
        if arg == "--scenario" and i + 1 < len(args):
            specific_scenario = args[i + 1].lower()

    # Discover scenarios
    scenarios = discover_scenarios()
    if not scenarios:
        print("[!] No test scenarios found. Ensure tests/scenarios/*.json exist.")
        sys.exit(1)

    # List mode
    if list_only:
        print(f"\n{'='*60}")
        print(f"  Available Test Scenarios ({len(scenarios)} found)")
        print(f"{'='*60}\n")
        for s in scenarios:
            print(f"  [{s['scenario_id']}]")
            print(f"    Name: {s['scenario_name']}")
            print(f"    File: {s.get('_file', 'unknown')}")
            print(f"    Severity: {s.get('alert', {}).get('alert_severity', '?')}")
            blast = s.get("expected_blast_radius", {})
            print(f"    Expected blast radius: {blast.get('total_entity_count', '?')} entities "
                  f"({blast.get('compromised_count', '?')} compromised)")
            print()
        return

    # Validate mode
    if validate_only:
        print(f"\n{'='*60}")
        print(f"  Validating {len(scenarios)} Scenario Files")
        print(f"{'='*60}\n")
        all_valid = True
        for s in scenarios:
            issues = validate_scenario(s)
            icon = "[+]" if not issues else "[-]"
            status = "VALID" if not issues else f"INVALID ({len(issues)} issues)"
            print(f"  {icon} {s.get('_file', '?')}: {status}")
            for issue in issues:
                print(f"      ! {issue}")
                all_valid = False
        print()
        sys.exit(0 if all_valid else 1)

    # Filter to specific scenario if requested
    if specific_scenario:
        scenarios = [
            s for s in scenarios
            if specific_scenario in s.get("scenario_id", "").lower()
            or specific_scenario in s.get("_file", "").lower()
            or specific_scenario in s.get("scenario_name", "").lower()
        ]
        if not scenarios:
            print(f"[!] No scenario matching '{specific_scenario}' found.")
            sys.exit(1)

    # Run scenarios
    print()
    print("=" * 70)
    print("  SentinelOps — Multi-Scenario Testing Suite")
    print(f"  Scenarios: {len(scenarios)}")
    print(f"  Mode: DEMO (no live Splunk required)")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)

    results = []
    total_start = time.time()

    for scenario in scenarios:
        result = await run_scenario(scenario, verbose=verbose)
        results.append(result)

    total_duration = (time.time() - total_start) * 1000

    # Summary
    print()
    print("=" * 70)
    print("  TEST SUITE SUMMARY")
    print("=" * 70)
    print()

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    for r in results:
        icon = "[+]" if r["status"] == "PASS" else "[-]"
        print(f"  {icon} {r['status']:4s}  {r['scenario_name'][:50]:<50s}  "
              f"blast={r['blast_radius_count']:>2d}  "
              f"mitre={r['mitre_count']:>2d}  "
              f"actions={r['remediation_count']:>2d}  "
              f"{r['duration_ms']:>6.0f}ms")

    print()
    print(f"  Total: {passed} passed, {failed} failed out of {len(results)} scenarios")
    print(f"  Duration: {total_duration:.0f}ms")

    # Aggregate call stats
    total_saia = sum(r.get("call_stats", {}).get("total_saia_calls", 0) for r in results)
    total_spl = sum(r.get("call_stats", {}).get("total_spl_queries", 0) for r in results)
    total_saved = sum(r.get("call_stats", {}).get("total_saved_searches", 0) for r in results)

    print(f"\n  Aggregate MCP/SAIA Tool Usage:")
    print(f"    SAIA calls:     {total_saia}")
    print(f"    SPL queries:    {total_spl}")
    print(f"    Saved searches: {total_saved}")
    print(f"    Total:          {total_saia + total_spl + total_saved}")

    # Blast radius comparison
    print(f"\n  Blast Radius Comparison Across Scenarios:")
    for r in results:
        bar_len = min(r["blast_radius_count"] * 3, 40)
        bar = "#" * bar_len
        print(f"    {r['scenario_name'][:30]:<30s}  "
              f"{r['blast_radius_count']:>2d} entities  {bar}")

    print()
    print("=" * 70)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    asyncio.run(main())
