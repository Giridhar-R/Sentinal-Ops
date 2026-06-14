"""
SentinelOps - MCP Tool Test Script
Verifies all 9 mandated Splunk AI tools work correctly in both demo and live modes.

Usage:
    python test_mcp_tools.py          # Tests in demo mode (default)
    python test_mcp_tools.py --live   # Tests against live Splunk instance
"""

from __future__ import annotations

import asyncio
import sys
import os
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


async def test_all_tools(live_mode: bool = False):
    """Test all mandated Splunk AI tools."""
    from backend.splunk_mcp.client import SplunkMCPClient

    print("=" * 60)
    print("  SentinelOps - MCP Tool Verification")
    print(f"  Mode: {'LIVE' if live_mode else 'DEMO'}")
    print("=" * 60)
    print()

    client = SplunkMCPClient(
        base_url=os.getenv("SPLUNK_BASE_URL", "https://localhost:8089"),
        token=os.getenv("SPLUNK_TOKEN", ""),
        demo_mode=not live_mode,
    )
    await client.connect()

    results = []

    # Test 1: splunk_get_indexes
    print("[1/9] Testing splunk_get_indexes...")
    try:
        indexes = await client.get_indexes()
        assert len(indexes) > 0, "No indexes returned"
        print(f"   PASS - {len(indexes)} indexes found")
        results.append(("splunk_get_indexes", True))
    except Exception as e:
        print(f"   FAIL - {e}")
        results.append(("splunk_get_indexes", False))

    # Test 2: splunk_get_metadata
    print("[2/9] Testing splunk_get_metadata...")
    try:
        metadata = await client.get_metadata("sentinalops_os", "sourcetypes")
        assert len(metadata) > 0, "No sourcetypes returned"
        print(f"   PASS - {len(metadata)} sourcetypes for sentinalops_os")
        results.append(("splunk_get_metadata", True))
    except Exception as e:
        print(f"   FAIL - {e}")
        results.append(("splunk_get_metadata", False))

    # Test 3: splunk_run_query
    print("[3/9] Testing splunk_run_query...")
    try:
        result = await client.run_spl_query(
            'index=sentinalops_os sourcetype=linux_secure "Failed password" | stats count by src_ip'
        )
        assert result["status"] == "success", f"Query failed: {result.get('error')}"
        assert result["result_count"] > 0, "No results returned"
        print(f"   PASS - {result['result_count']} results in {result['execution_time_ms']:.0f}ms")
        results.append(("splunk_run_query", True))
    except Exception as e:
        print(f"   FAIL - {e}")
        results.append(("splunk_run_query", False))

    # Test 4: splunk_get_knowledge_objects
    print("[4/9] Testing splunk_get_knowledge_objects...")
    try:
        searches = await client.get_saved_searches()
        assert len(searches) > 0, "No saved searches returned"
        print(f"   PASS - {len(searches)} saved searches")
        results.append(("splunk_get_knowledge_objects", True))
    except Exception as e:
        print(f"   FAIL - {e}")
        results.append(("splunk_get_knowledge_objects", False))

    # Test 5: splunk_run_saved_search
    print("[5/9] Testing splunk_run_saved_search...")
    try:
        saved_results = await client.run_saved_search("Failed Login Spike Detector")
        assert len(saved_results) > 0, "No results from saved search"
        print(f"   PASS - {len(saved_results)} results")
        results.append(("splunk_run_saved_search", True))
    except Exception as e:
        print(f"   FAIL - {e}")
        results.append(("splunk_run_saved_search", False))

    # Test 6: saia_generate_spl
    print("[6/9] Testing saia_generate_spl...")
    try:
        spl = await client.saia_generate_spl("find failed login attempts from a single IP")
        assert len(spl) > 10, f"SPL too short: '{spl}'"
        assert "index=" in spl.lower() or "stats" in spl.lower(), "Doesn't look like SPL"
        print(f"   PASS - Generated: {spl[:80]}...")
        results.append(("saia_generate_spl", True))
    except Exception as e:
        print(f"   FAIL - {e}")
        results.append(("saia_generate_spl", False))

    # Test 7: saia_explain_spl
    print("[7/9] Testing saia_explain_spl...")
    try:
        explanation = await client.saia_explain_spl(
            'index=sentinalops_os sourcetype=linux_secure "Failed password" | stats count by src_ip'
        )
        assert len(explanation) > 20, f"Explanation too short: '{explanation}'"
        print(f"   PASS - {explanation[:80]}...")
        results.append(("saia_explain_spl", True))
    except Exception as e:
        print(f"   FAIL - {e}")
        results.append(("saia_explain_spl", False))

    # Test 8: saia_optimize_spl
    print("[8/9] Testing saia_optimize_spl...")
    try:
        optimized = await client.saia_optimize_spl(
            'index=* sourcetype=linux_secure | search "Failed password" | stats count by src_ip'
        )
        assert len(optimized) > 10, f"Optimized SPL too short: '{optimized}'"
        print(f"   PASS - {optimized[:80]}...")
        results.append(("saia_optimize_spl", True))
    except Exception as e:
        print(f"   FAIL - {e}")
        results.append(("saia_optimize_spl", False))

    # Test 9: saia_ask_splunk_question
    print("[9/9] Testing saia_ask_splunk_question...")
    try:
        answer = await client.saia_ask_question(
            "What are the recommended containment steps for credential stuffing?"
        )
        assert len(answer) > 20, f"Answer too short: '{answer}'"
        print(f"   PASS - {answer[:80]}...")
        results.append(("saia_ask_splunk_question", True))
    except Exception as e:
        print(f"   FAIL - {e}")
        results.append(("saia_ask_splunk_question", False))

    # Summary
    print()
    print("=" * 60)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"  RESULTS: {passed}/{total} tools PASSED")
    print()
    for tool, ok in results:
        status = "PASS" if ok else "FAIL"
        marker = "[+]" if ok else "[-]"
        print(f"    {marker} {status}  {tool}")
    print()

    # Call statistics
    stats = client.get_call_stats()
    print(f"  Call Statistics:")
    print(f"    SAIA calls:     {stats['total_saia_calls']}")
    print(f"    SPL queries:    {stats['total_spl_queries']}")
    print(f"    Saved searches: {stats['total_saved_searches']}")
    print(f"    Total:          {stats['total_calls']}")
    print("=" * 60)

    await client.disconnect()

    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    live = "--live" in sys.argv
    asyncio.run(test_all_tools(live_mode=live))
