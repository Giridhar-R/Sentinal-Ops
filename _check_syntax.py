"""Quick syntax check for all Python files."""
import ast
import sys

files = [
    "backend/agents/state.py",
    "backend/agents/graph.py",
    "backend/agents/orchestrator.py",
    "backend/agents/threat_hunter.py",
    "backend/agents/rca_agent.py",
    "backend/agents/blast_radius.py",
    "backend/agents/remediation.py",
    "backend/evidence/board.py",
    "backend/splunk_mcp/client.py",
    "backend/splunk_mcp/kv_store.py",
    "backend/splunk_mcp/spl_library.py",
    "backend/postmortem/generator.py",
    "backend/config.py",
    "backend/main.py",
    "backend/demo/scenario.py",
    "backend/demo/sample_data.py",
]

ok = 0
fail = 0

for f in files:
    try:
        with open(f, encoding="utf-8") as fh:
            ast.parse(fh.read())
        print(f"  OK: {f}")
        ok += 1
    except Exception as e:
        print(f"  FAIL: {f} -> {e}")
        fail += 1

print(f"\n{ok} OK, {fail} FAIL")
if fail > 0:
    sys.exit(1)
