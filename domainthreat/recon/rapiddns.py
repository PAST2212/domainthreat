#!/usr/bin/env python3

import asyncio
import json
from bs4 import BeautifulSoup
import aiohttp
from aiolimiter import AsyncLimiter
from domainthreat.core.webscraper import HtmlContent


class ScanerRapidDns:
    def __init__(self) -> None:
        self.results: set = set()

    async def rapiddns(self, session: aiohttp.ClientSession, domain, rate_limit):
        try:
            async with rate_limit:
                response = await session.get(f"https://rapiddns.io/s/{domain}?full=1#result", headers=HtmlContent.get_header())
                if response.status == 200:
                    data1 = await response.text()
                    soup = BeautifulSoup(data1, "lxml")
                    table = soup.find("table", id="table")
                    rows = table.findAll("tr")
                    for row in rows:
                        passive_dns = row.findAll("td")
                        # passive DNS Data
                        # [value.text.strip() for value in passive_dns]
                        for subdomain in passive_dns:
                            subdomain_trans = subdomain.get_text().strip()
                            if domain in subdomain_trans:
                                if subdomain_trans != '':
                                    self.results.add((domain, subdomain_trans))

        except (asyncio.TimeoutError, TypeError, json.decoder.JSONDecodeError) as e:
            print(f'Rapiddns Error via Subdomainscan for: {domain}', e)

        except (aiohttp.ClientConnectorError, aiohttp.ServerConnectionError) as e:
            print(f'Rapiddns Connection Error via Subdomainscan for: {domain}', e)

        except Exception as e:
            print(f'Rapiddns Unusual Error via Subdomainscan for: {domain}', e)

    async def tasks_rapiddns(self, fuzzy_results: list, session: aiohttp.ClientSession):
        rate_limit = AsyncLimiter(1, 5)
        tasks = [self.rapiddns(session, y, rate_limit) for y in fuzzy_results]
        await asyncio.gather(*tasks)

    async def get_results(self, fuzzy_results, session: aiohttp.ClientSession):
        await self.tasks_rapiddns(fuzzy_results, session)
        return self.results
