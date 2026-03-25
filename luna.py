#!/usr/bin/env python3
import asyncio
import sys
from medusa.engine.modules.ai.chat import LunaChat

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Interactive AI Agent")
    parser.add_argument("--session", help="Session UUID for context")
    args = parser.parse_args()

    try:
        chat = LunaChat()
        asyncio.run(chat.start(session_id=args.session))
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
