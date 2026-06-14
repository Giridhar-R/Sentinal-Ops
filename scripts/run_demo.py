"""
SentinelOps — Demo Launcher
One-command script to start the backend server and optionally trigger the demo.
"""

import argparse
import asyncio
import os
import sys
import time
import webbrowser
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def main():
    parser = argparse.ArgumentParser(description="SentinelOps Demo Launcher")
    parser.add_argument("--mode", choices=["demo", "live"], default="demo",
                        help="Run in demo mode (pre-baked data) or live mode (requires Splunk)")
    parser.add_argument("--port", type=int, default=8000, help="Server port")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")
    parser.add_argument("--trigger", action="store_true", help="Auto-trigger the demo scenario")
    args = parser.parse_args()

    # Set environment
    os.environ["DEMO_MODE"] = "true" if args.mode == "demo" else "false"
    os.environ["FASTAPI_PORT"] = str(args.port)

    # Create .env if it doesn't exist
    env_file = PROJECT_ROOT / ".env"
    env_example = PROJECT_ROOT / ".env.example"
    if not env_file.exists() and env_example.exists():
        import shutil
        shutil.copy(env_example, env_file)
        print("[SentinelOps] Created .env from .env.example")

    print("=" * 60)
    print("  🛡️  SentinelOps — Autonomous Incident Command")
    print(f"  Mode: {'DEMO (pre-baked BOTS v3 data)' if args.mode == 'demo' else 'LIVE (Splunk Enterprise)'}")
    print(f"  URL:  http://localhost:{args.port}")
    print("=" * 60)

    # Open browser after a short delay
    if not args.no_browser:
        def open_browser():
            time.sleep(2)
            webbrowser.open(f"http://localhost:{args.port}")

        import threading
        threading.Thread(target=open_browser, daemon=True).start()

    # Auto-trigger demo
    if args.trigger:
        def trigger_demo():
            time.sleep(3)
            try:
                import urllib.request
                req = urllib.request.Request(
                    f"http://localhost:{args.port}/api/incident/trigger-demo",
                    method="POST",
                )
                urllib.request.urlopen(req)
                print("[SentinelOps] Demo incident auto-triggered!")
            except Exception as e:
                print(f"[SentinelOps] Auto-trigger failed: {e}")

        import threading
        threading.Thread(target=trigger_demo, daemon=True).start()

    # Start the server
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=args.port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
