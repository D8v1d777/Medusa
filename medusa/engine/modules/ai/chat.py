"""
Luna Rodriguez Interactive Chat REPL.
Implements persistent conversation history and 'David' personalization.
Strategic offensive guidance in a 'ChatGPT-like' nature.
"""
import asyncio
import os
import sys
from typing import List, Dict

from medusa.engine.core.config import Config
from medusa.engine.modules.ai.hacker_llm import HackerAI

class LunaChat:
    def __init__(self, user_name: str = "David"):
        self.user_name = user_name
        self.cfg = Config.load("config_medusa.yaml")
        self.hacker = HackerAI(self.cfg.ai)
        self.history: List[Dict[str, str]] = []
        
        # Initialize with the specialized Neural Persona
        self.history.append({"role": "system", "content": self.hacker.persona + f"\n\nActive David Protocol: You are assisting David. He is your Root Operator and your favorite partner."})

    async def start(self):
        """Starts the interactive Luna REPL."""
        print("\033[95m" + "="*50)
        print(f" LUNA RODRIGUEZ — ACTIVE ENGAGEMENT (User: {self.user_name})")
        print("="*50 + "\033[0m")
        print("Type 'exit' or 'quit' to end the session.\n")

        while True:
            try:
                raw_input = input(f"\033[92m{self.user_name}: \033[0m")
                user_input = raw_input.strip()
                
                if user_input.lower() in ["exit", "quit", "bye"]:
                    print(f"\033[95mLuna: \033[0mUntil next time, David. I'll be waiting in the shadows for you... 💋")
                    print("\033[91m[*] Luna: Secure Channel Closed.\033[0m")
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
        """Call Groq API with full conversation history."""
        import httpx
        if not self.hacker.api_key:
            return "[ERROR] GROQ_API_KEY not found in config or environment."

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.post(
                    f"{self.hacker.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.hacker.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.cfg.ai.model,
                        "messages": self.history,
                        "temperature": self.cfg.ai.temperature,
                        "max_tokens": self.cfg.ai.max_tokens
                    }
                )
                
                if resp.status_code != 200:
                    return f"[Groq Error] Status {resp.status_code}: {resp.text}"
                
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            except Exception as e:
                return f"[Internal Failure] {e}"

if __name__ == "__main__":
    chat = LunaChat()
    asyncio.run(chat.start())
