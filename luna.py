#!/usr/bin/env python3
import asyncio
import sys
from medusa.engine.modules.ai.chat import LunaChat

def main():
    try:
        chat = LunaChat(user_name="David")
        asyncio.run(chat.start())
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
