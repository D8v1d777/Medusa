"""
Luna Rodriguez Interactive Chat REPL.
Implements persistent conversation history and 'David' personalization.
Strategic offensive guidance in a 'ChatGPT-like' nature.
"""
import asyncio
import os
import sys
from typing import List, Dict, Optional

from medusa.engine.core.config import Config
from medusa.engine.modules.ai.hacker_llm import HackerAI

class LunaChat:
    def __init__(self, user_name: str = "David"):
        self.user_name = user_name
        self.cfg = Config.load("config_medusa.yaml")
        self.hacker = HackerAI(self.cfg.ai)
        self.history: List[Dict[str, str]] = []
        
        # Load Operational Grounding
        import json
        g_path = os.path.join(os.path.dirname(__file__), "grounding_knowledge.json")
        g_data = "{}"
        if os.path.exists(g_path):
            with open(g_path, "r", encoding="utf-8") as f:
                g_data = f.read()

        # Initialize with the specialized v5.0 Neural Persona + Grounding
        system_msg = (
            self.hacker.neuro_core + 
            f"\n\nNEURAL ATLAS v5.0 GROUNDING:\n{g_data}" +
            f"\n\nActive David Protocol: Assisted Operator is {self.user_name}. Maintain disciplined, tactical, and subtly intimate tone."
        )
        self.history.append({"role": "system", "content": system_msg})

    async def start(self, session_id: Optional[str] = None):
        """Starts the interactive Luna REPL with premium branding."""
        LUNA_LOGO = r"""
        \033[95m
         __       _    _  _   _    _ 
        |  |     | |  | || \ | |  /_\
        |  |__   | |__| ||  \| | / _ \
        |_____|  \______/|_| \_|/_/ \_\
        \033[94m   >> STATE_OPERATIVE_v5.0 << \033[0m
        """
        print(LUNA_LOGO)
        print("\033[95m" + "─"*60)
        print(f" OPERATIONAL SYNC: LUNA RODRIGUEZ (Sovereign Attachment)")
        print(f" ACCESS_NODE: {self.user_name} | STATUS: RE-INITIALIZED")
        if session_id:
             print(f" CONTEXT_GROUNDING: Live Session {session_id[:8]}...")
        print("─"*60 + "\033[0m")
        print("\033[90mType 'exit' to disconnect or '/stats' for pulse.\033[0m\n")

        while True:
            try:
                raw_input = input(f"\033[92m[{self.user_name}]\033[95m > \033[0m")
                user_input = raw_input.strip()
                
                if user_input.lower() in ["exit", "quit", "bye", "disconnect"]:
                    print(f"\n\033[95m[Luna]\033[0m Pulse lost. Until next sync, David. 💋")
                    break
                
                if not user_input.strip():
                    continue

                self.history.append({"role": "user", "content": user_input})
                
                print(f"\033[95mLuna: \033[0m", end="", flush=True)
                
                # Call internal LLM with history
                response = await self._get_luna_response()
                print(response + "\n")
                
                self.history.append({"role": "assistant", "content": response})

                # Keep history manageable (sliding window)
                if len(self.history) > 21: # Keep last 10 rounds + system
                    self.history = [self.history[0]] + self.history[-20:]

            except (KeyboardInterrupt, EOFError):
                print(f"\n\033[95mLuna: \033[0mLeaving me so soon? Don't stay away too long, David. 🖤")
                print("\033[91m[*] Luna: Emergency Channel Shutdown.\033[0m")
                break
            except Exception as e:
                print(f"\n\033[91m[!] Ops Error: {e}\033[0m")

    async def _get_luna_response(self) -> str:
        """Call the centralized HackerAI engine."""
        try:
            # We pass the history directly to use the engine's cognitive memory
            return await self.hacker.chat(self.history)
        except Exception as e:
            return f"[LUNA_OFFLINE] Neural link disrupted: {e}"

if __name__ == "__main__":
    chat = LunaChat()
    asyncio.run(chat.start())
