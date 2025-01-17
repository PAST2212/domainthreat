#!/usr/bin/env python3

import asyncio
from bs4 import BeautifulSoup
import aiohttp


class ScanerRapidDns:
    def __init__(self) -> None:
        self.results: set[tuple[str, str]] = set()

    @staticmethod
    async def _scrape_subdomains(session: aiohttp.ClientSession, domain: str) -> set[tuple[str, str]]:
        url = f"https://rapiddns.io/s/{domain}?full=1#result"
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "lxml")

                    if table := soup.find("table", id="table"):
                        subdomains = set()
                        rows = table.findAll("tr")
                        for row in rows:
                            passive_dns = row.findAll("td")
                            # passive DNS Data
                            # [value.text.strip() for value in passive_dns]
                            for cell in passive_dns:
                                subdomain = cell.get_text().strip()
                                if domain in subdomain and subdomain:
                                    subdomains.add((domain, subdomain))

                        return subdomains

                else:
                    print(f"RapidDNS returned status {response.status} for {domain}")

        except asyncio.TimeoutError:
            print(f"Timeout scanning {domain} on RapidDNS")
        except (aiohttp.ClientError, aiohttp.ServerConnectionError) as e:
            print(f"Connection error scanning {domain} on RapidDNS: {str(e)}")
        except Exception as e:
            print(f"Unexpected error scanning {domain} on RapidDNS: {str(e)}")

        return set()

    async def get_results(self, domains, session: aiohttp.ClientSession):
        for domain in domains:
            try:
                subdomains = await self._scrape_subdomains(session, domain)
                self.results.update(subdomains)
            except Exception as e:
                print(f"Failed to scan {domain} on RapidDNS: {str(e)}")
        return self.results
