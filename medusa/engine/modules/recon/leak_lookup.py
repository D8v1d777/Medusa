import httpx
import logging
import asyncio
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

class LeakLookup:
    """
    Leak-Lookup OSINT Module for Medusa.
    Searches for compromised credentials and data leaks.
    """
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://leak-lookup.com/api/search"
        self.client = httpx.AsyncClient(timeout=30.0, verify=False)  # Bypassing SSL cert issues if they persist

    async def search(self, query: str, search_type: str = "email_address") -> Dict[str, Any]:
        """
        Perform a search against Leak-Lookup.com.
        
        Types: email_address, username, ipaddress, phone, domain, password, fullname
        """
        valid_types = [
            "email_address", "username", "ipaddress", "phone", 
            "domain", "password", "fullname"
        ]
        
        if search_type not in valid_types:
            return {"error": f"Invalid search type. Must be one of: {', '.join(valid_types)}"}

        data = {
            "key": self.api_key,
            "type": search_type,
            "query": query
        }

        try:
            resp = await self.client.post(self.base_url, data=data)
            if resp.status_code == 200:
                result = resp.json()
                if result.get("error") == "false":
                    # The response body usually has a 'message' field with the results
                    return result
                return {"error": result.get("message", "Unknown error from Leak-Lookup")}
            return {"error": f"HTTP Error {resp.status_code}: {resp.text}"}
        except Exception as e:
            logger.error(f"[!] Leak-Lookup Request Failed: {e}")
            return {"error": str(e)}

    async def aclose(self):
        await self.client.aclose()

    def __del__(self):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.aclose())
            else:
                asyncio.run(self.aclose())
        except:
            pass
