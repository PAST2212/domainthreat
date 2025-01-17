import asyncio
import aiohttp
import json


class ScanerThreatCrowd:
    def __init__(self) -> None:
        self.results: set[tuple[str, str]] = set()

    @staticmethod
    async def _scrape_subdomains(session: aiohttp.ClientSession, domain: str) -> set[tuple[str, str]]:
        url = "http://ci-www.threatcrowd.org/searchApi/v2/domain/report/"
        params = {"domain": domain}
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        try:
            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('response_code') == '1':  # Success code
                        subdomains = set()
                        for subdomain in data.get('subdomains', []):
                            if domain in subdomain:
                                subdomains.add((domain, subdomain.lower()))
                        return subdomains
                else:
                    print(f"ThreatCrowd returned status {response.status} for {domain}")

        except asyncio.TimeoutError:
            print(f"Timeout scanning {domain} on ThreatCrowd")
        except json.JSONDecodeError:
            print(f"Invalid JSON response from ThreatCrowd for {domain}")
        except (aiohttp.ClientError, aiohttp.ServerConnectionError) as e:
            print(f"Connection error scanning {domain} on ThreatCrowd: {str(e)}")
        except Exception as e:
            print(f"Unexpected error scanning {domain} on ThreatCrowd: {str(e)}")

        return set()

    async def get_results(self, domains, session: aiohttp.ClientSession):
        for domain in domains:
            try:
                subdomains = await self._scrape_subdomains(session, domain)
                self.results.update(subdomains)
            except Exception as e:
                print(f"Failed to scan {domain} on ThreatCrowd: {str(e)}")
        return self.results
