#!/usr/bin/env python3
import asyncio
import sys
from medusa.engine.modules.ai.chat import LunaChat

def main():
    import argparse
    parser = argparse.ArgumentParser(description="LUNA STATE OPERATIVE v5.0")
    parser.add_argument("--session", help="Session UUID for context grounding")
    args = parser.parse_args()

    try:
        chat = LunaChat(user_name="David")
        asyncio.run(chat.start(session_id=args.session))
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
