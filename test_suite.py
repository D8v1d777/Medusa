import os
import sys
import unittest
import json
import logging

# Set up logging for the test
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MEDUSA-TEST")

# Import Medusa modules
try:
    from medusa.engine.core.config import AIConfig
    from medusa.engine.modules.ai.hacker_llm import HackerAI
    import medusa.engine.cli as cli
    import medusa.engine.modules.network.dark_crawler as dark_crawler
    SUCCESSFUL_IMPORTS = True
except ImportError as e:
    logger.error(f"[!] Import Failure: {e}")
    SUCCESSFUL_IMPORTS = False

class TestMedusaCore(unittest.TestCase):
    
    def test_imports(self):
        """Verify all critical modules are available."""
        self.assertTrue(SUCCESSFUL_IMPORTS, "Not all Medusa modules could be imported.")

    def test_luna_persona_integrity(self):
        """Does Luna load her weaponized persona?"""
        cfg = AIConfig(provider="groq", model="llama3-70b-8192", api_key="dummy")
        ai = HackerAI(cfg)
        self.assertIn("LUNA Neuro-Interface", ai.neuro_core)
        self.assertIn("EXPLOIT_LIBRARY_INDEX", ai.neuro_core)
        logger.info("[+] Verified: Luna Persona Loaded with Exploit Index.")

    def test_exploit_library_access(self):
        """Can Luna query her knowledge library?"""
        cfg = AIConfig(provider="groq", model="llama3-70b-8192", api_key="dummy")
        ai = HackerAI(cfg)
        results = ai.query_library("Exploit-DB")
        self.assertIn("Exploit-DB", results)
        self.assertIn("https://www.exploit-db.com", results)
        logger.info("[+] Verified: Exploit Library Query Bridge is functional.")

    def test_dark_crawler_branding(self):
        """Ensure DarkCrawler's brand integrity."""
        from medusa.engine.modules.network.dark_crawler import Colors
        self.assertEqual(Colors.RED, '\033[1;31m')
        logger.info("[+] Verified: DarkCrawler Branded UI integrity.")

    def test_exploit_db_ingestion(self):
        """Check if the 45k exploit metadata index is present."""
        path = "exploit_db_metadata.csv"
        self.assertTrue(os.path.exists(path), f"{path} is missing from the workspace.")
        logger.info(f"[+] Verified: Exploit-DB metadata index identified at {path}.")

if __name__ == "__main__":
    unittest.main()
