#!/usr/bin/env python3

import aiohttp
from aiolimiter import AsyncLimiter
import asyncio
from bs4 import BeautifulSoup
import json
import re
from domainthreat.core.webscraper import HtmlContent

class ScanerSubdomainCenter:
    def __init__(self) -> None:
        self.results: set = set()

    async def subdomaincenter(self, session: aiohttp.ClientSession, domain, rate_limit):
        try:
            async with rate_limit:
                response = await session.get(f"https://api.subdomain.center/?domain={domain}", headers=HtmlContent.get_header())
                if response.status == 200:
                    data1 = await response.text()
                    soup = BeautifulSoup(data1, 'lxml')
                    subdomain_trans = re.sub(r'[\[\]"]', "", soup.find('p').get_text()).split(",")
                    for subdomain in subdomain_trans:
                        if subdomain != '':
                            self.results.add((domain, subdomain))

        except (asyncio.TimeoutError, TypeError, json.decoder.JSONDecodeError) as e:
            print(f'Subdomaincenter Error via Subdomainscan for: {domain}', e)

        except (aiohttp.ClientConnectorError, aiohttp.ServerConnectionError) as e:
            print(f'Subdomaincenter Connection Error via Subdomainscan for: {domain}', e)

        except Exception as e:
            print(f'Subdomaincenter Unusual Error via Subdomainscan for: {domain}', e)

    async def tasks_subdomaincenter(self, fuzzy_results:list, session: aiohttp.ClientSession):
        rate_limit = AsyncLimiter(1, 5)  # no burst requests, make request every 1.5 seconds
        tasks = [self.subdomaincenter(session, y, rate_limit) for y in fuzzy_results]
        await asyncio.gather(*tasks)

    async def get_results(self, fuzzy_results, session: aiohttp.ClientSession):
        await self.tasks_subdomaincenter(fuzzy_results, session)
        return self.results




