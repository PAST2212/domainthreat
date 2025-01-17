import asyncio
import aiohttp
import json


class ScanerCertSpotter:
    def __init__(self) -> None:
        self.results: set[tuple[str, str]] = set()

    @staticmethod
    async def _scrape_subdomains(session: aiohttp.ClientSession, domain: str) -> set[tuple[str, str]]:
        url = f"https://api.certspotter.com/v1/issuances"
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names"
        }

        try:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = set()
                    for cert in data:
                        for dns_name in cert.get('dns_names', []):
                            if domain in dns_name:
                                subdomains.add((domain, dns_name.lower()))
                    return subdomains
                else:
                    print(f"CertSpotter returned status {response.status} for {domain}")

        except asyncio.TimeoutError:
            print(f"Timeout scanning {domain} on CertSpotter")
        except json.JSONDecodeError:
            print(f"Invalid JSON response from CertSpotter for {domain}")
        except (aiohttp.ClientError, aiohttp.ServerConnectionError) as e:
            print(f"Connection error scanning {domain} on CertSpotter: {str(e)}")
        except Exception as e:
            print(f"Unexpected error scanning {domain} on CertSpotter: {str(e)}")

        return set()

    async def get_results(self, domains, session: aiohttp.ClientSession):
        for domain in domains:
            try:
                subdomains = await self._scrape_subdomains(session, domain)
                self.results.update(subdomains)
            except Exception as e:
                print(f"Failed to scan {domain} on CertSpotter: {str(e)}")
        return self.results
