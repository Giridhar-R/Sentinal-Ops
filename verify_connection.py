"""
SentinelOps — Splunk MCP Live Connection Verifier
Loads configuration from .env and verifies active connectivity to live Splunk MCP server.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from backend.config import get_settings
    from backend.splunk_mcp.client import SplunkMCPClient
except ImportError as e:
    print(f"[!] ERROR: Failed to import backend modules: {e}")
    print("    Ensure you are running this from the repository root directory.")
    sys.exit(1)

async def main():
    print("=" * 65)
    print("🛡️  SentinelOps — Splunk MCP Live Connection Verifier")
    print("=" * 65)

    # Check for .env file
    env_file = PROJECT_ROOT / ".env"
    if not env_file.exists():
        print("[!] ERROR: .env file not found in the project root!")
        print("    Please copy .env.example to .env and configure it:")
        print("    cp .env.example .env")
        sys.exit(1)

    # Load settings
    try:
        settings = get_settings()
    except Exception as e:
        print(f"[!] ERROR: Failed to load configuration from .env: {e}")
        sys.exit(1)

    print(f"[*] Configuration Loaded:")
    print(f"    - DEMO_MODE    : {settings.demo_mode}")
    print(f"    - SPLUNK_HOST  : {settings.splunk.host}")
    print(f"    - SPLUNK_PORT  : {settings.splunk.port}")
    token_display = "configured" if settings.splunk.token and settings.splunk.token != "changeme" else "NOT CONFIGURED"
    print(f"    - SPLUNK_TOKEN : {token_display}")
    print(f"    - SPLUNK_INDEX : {settings.splunk.index}")
    print(f"    - VERIFY_SSL   : {settings.splunk.verify_ssl}")
    print("-" * 65)

    if settings.demo_mode:
        print("[!] WARNING: DEMO_MODE is set to 'true' in your .env file.")
        print("    To test a live connection, set DEMO_MODE=false in .env.")
        print("=" * 65)
        sys.exit(0)

    print("[*] Initiating live connection to Splunk MCP Server...")
    client = SplunkMCPClient(
        base_url=settings.splunk.base_url,
        token=settings.splunk.token,
        mode=settings.splunk.mcp_mode,
        index=settings.splunk.index,
        verify_ssl=settings.splunk.verify_ssl,
        demo_mode=False,
    )

    try:
        # Connect & fetch server info
        await client.connect()
        print("[+] SUCCESS: Connected to the live Splunk instance!")
        
        # Check health
        health = await client.health_check()
        print(f"[+] Health Check: {'PASSED ✅' if health else 'FAILED ❌'}")
        
        # Test basic MCP queries
        print("[*] Discovery: Discovering Splunk indexes...")
        indexes = await client.get_indexes()
        if indexes:
            print(f"[+] Found {len(indexes)} indexes:")
            for idx in indexes[:5]:
                print(f"    - {idx.get('name')} ({idx.get('totalEventCount')} events)")
            if len(indexes) > 5:
                print("    - ...")
        else:
            print("[-] No indexes discovered (or empty list returned).")

        # Test index presence
        target_index = settings.splunk.index
        index_names = [idx.get('name') for idx in indexes]
        if target_index in index_names:
            print(f"[+] Target index '{target_index}' is present in Splunk.")
        else:
            print(f"[!] WARNING: Target index '{target_index}' not found in the list of indexes!")

        print("-" * 65)
        print("✅ Live Splunk MCP connection is fully functional and ready for demo!")
        print("=" * 65)

    except Exception as e:
        print(f"\n[!] CONNECTION FAILED ❌")
        print(f"    Error: {e}")
        print("\n    Please verify:")
        print("    1. Is Splunk running locally or on the target host?")
        print("    2. Is the Splunk MCP Server installed and running?")
        print("    3. Are the SPLUNK_HOST, SPLUNK_PORT, and SPLUNK_TOKEN set correctly in .env?")
        print("    4. If using self-signed certs, is SPLUNK_VERIFY_SSL set to false?")
        print("=" * 65)
        sys.exit(1)
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
