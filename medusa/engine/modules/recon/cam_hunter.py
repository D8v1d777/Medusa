import asyncio
import httpx
import re
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class CamHunter:
    """
    Tactical Reconnaissance Module: CamHunter
    Targets: worldcams.tv, hdontap.com, iplivecams.com, earthcam.com
    Objective: Extract live stream URLs and snapshots.
    """

    def __init__(self, proxy=None):
        self.proxy = proxy
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        self.targets = {
            "worldcams": "https://worldcams.tv/",
            "hdontap": "https://hdontap.com/index.php/video",
            "iplivecams": "https://iplivecams.com/",
            "earthcam": "https://www.earthcam.com/"
        }

    async def hunt(self, limit=10):
        """Main entry point for the hunt."""
        results = []
        tasks = [
            self.hunt_worldcams(limit),
            self.hunt_hdontap(limit),
            self.hunt_iplivecams(limit),
            self.hunt_earthcam(limit)
        ]
        
        # Run all hunts in parallel
        hunt_results = await asyncio.gather(*tasks)
        for res in hunt_results:
            results.extend(res)
            
        return results

    async def hunt_worldcams(self, limit):
        """Scrapes worldcams.tv for YouTube embeds."""
        logger.info("[*] CamHunter: Engaging WorldCams...")
        results = []
        try:
            async with httpx.AsyncClient(headers=self.headers, proxy=self.proxy, verify=False, timeout=15) as client:
                resp = await client.get(self.targets["worldcams"])
                soup = BeautifulSoup(resp.text, "html.parser")
                
                # Links to individual cam pages
                links = soup.select("a.cam-link")[:limit]
                for link in links:
                    url = urljoin(self.targets["worldcams"], link["href"])
                    cam_resp = await client.get(url)
                    
                    # Extract YouTube ID
                    yt_match = re.search(r'youtube\.com/embed/([a-zA-Z0-9_-]{11})', cam_resp.text)
                    if yt_match:
                        yt_id = yt_match.group(1)
                        results.append({
                            "site": "WorldCams",
                            "name": link.get_text(strip=True),
                            "url": url,
                            "stream": f"https://www.youtube.com/watch?v={yt_id}",
                            "type": "YouTube"
                        })
        except Exception as e:
            logger.error(f"[!] WorldCams hunt failed: {e}")
        return results

    async def hunt_hdontap(self, limit):
        """Scrapes hdontap.com for HLS streams."""
        logger.info("[*] CamHunter: Engaging HDonTAP...")
        results = []
        try:
            async with httpx.AsyncClient(headers=self.headers, proxy=self.proxy, verify=False, timeout=15) as client:
                resp = await client.get(self.targets["hdontap"])
                soup = BeautifulSoup(resp.text, "html.parser")
                
                # Thumbnails/Links
                cams = soup.select(".video-item")[:limit]
                for cam in cams:
                    link = cam.select_one("a")
                    if not link: continue
                    
                    name = cam.select_one(".video-title").get_text(strip=True) if cam.select_one(".video-title") else "Unknown"
                    url = urljoin("https://hdontap.com/", link["href"])
                    
                    # HDonTAP uses Wowza for snapshots
                    stream_name = url.split("/")[-1]
                    snapshot = f"https://storage.hdontap.com/wowza_stream_thumbnails/snapshot_{stream_name}.jpg"
                    
                    results.append({
                        "site": "HDonTAP",
                        "name": name,
                        "url": url,
                        "snapshot": snapshot,
                        "type": "HLS/Wowza"
                    })
        except Exception as e:
            logger.error(f"[!] HDonTAP hunt failed: {e}")
        return results

    async def hunt_iplivecams(self, limit):
        """Scrapes iplivecams.com for YouTube embeds."""
        logger.info("[*] CamHunter: Engaging IpLiveCams...")
        results = []
        try:
            async with httpx.AsyncClient(headers=self.headers, proxy=self.proxy, verify=False, timeout=15) as client:
                resp = await client.get(self.targets["iplivecams"])
                soup = BeautifulSoup(resp.text, "html.parser")
                
                links = soup.select(".cam-title a")[:limit]
                for link in links:
                    name = link.get_text(strip=True)
                    url = urljoin(self.targets["iplivecams"], link["href"])
                    
                    cam_resp = await client.get(url)
                    yt_match = re.search(r'youtube\.com/embed/([a-zA-Z0-9_-]{11})', cam_resp.text)
                    if yt_match:
                        yt_id = yt_match.group(1)
                        results.append({
                            "site": "IpLiveCams",
                            "name": name,
                            "url": url,
                            "stream": f"https://www.youtube.com/watch?v={yt_id}",
                            "type": "YouTube"
                        })
        except Exception as e:
            logger.error(f"[!] IpLiveCams hunt failed: {e}")
        return results

    async def hunt_earthcam(self, limit):
        """Scrapes earthcam.com for stream metadata."""
        logger.info("[*] CamHunter: Engaging EarthCam...")
        results = []
        try:
            async with httpx.AsyncClient(headers=self.headers, proxy=self.proxy, verify=False, timeout=15) as client:
                resp = await client.get(self.targets["earthcam"])
                # EarthCam is JS heavy, we look for JSON objects in scripts
                matches = re.findall(r'\"title\":\"([^\"]+)\",\"url\":\"([^\"]+)\"', resp.text)
                for i, (title, url) in enumerate(matches):
                    if i >= limit: break
                    results.append({
                        "site": "EarthCam",
                        "name": title,
                        "url": f"https://www.earthcam.com{url}",
                        "type": "HLS/Web"
                    })
        except Exception as e:
            logger.error(f"[!] EarthCam hunt failed: {e}")
        return results

if __name__ == "__main__":
    import json
    async def test():
        hunter = CamHunter()
        res = await hunter.hunt(limit=5)
        print(json.dumps(res, indent=4))
    asyncio.run(test())
