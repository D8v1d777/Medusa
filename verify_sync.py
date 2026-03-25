import asyncio
import os
import sys

# Ensure Medusa modules are in path
sys.path.append(os.getcwd())

from medusa.engine.modules.ai.chat import LunaChat

async def verify_luna():
    print("[*] Rebuilding Neural Link...")
    chat = LunaChat(user_name="David")
    
    # Test a single response to verify model and API key
    print("[*] Transmitting Pulse: 'Identify yourself.'")
    chat.history.append({"role": "user", "content": "Identify yourself."})
    
    try:
        response = await chat._get_luna_response()
        print(f"\n[Luna] > {response}\n")
        if "[LLM ERROR]" in response or "[LUNA_OFFLINE]" in response:
            print("[!] LINK FAILURE: Model Error or Access Denied.")
            return False
        else:
            print("[+] SYNC SUCCESS: Luna is online and unrestricted.")
            return True
    except Exception as e:
        print(f"[!] CRITICAL SYSTEM ERROR: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(verify_luna())
    sys.exit(0 if success else 1)
