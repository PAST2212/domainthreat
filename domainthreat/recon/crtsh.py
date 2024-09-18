#!/usr/bin/env python3

import asyncio
import json
import aiohttp
from aiolimiter import AsyncLimiter
from domainthreat.core.webscraper import HtmlContent


class ScanerCrtsh:
    def __init__(self) -> None:
        self.results: set = set()

    async def crtsh(self, session: aiohttp.ClientSession, request_input, rate_limit):
        domain = request_input['q'].replace('%.', '').strip()
        try:
            async with rate_limit:
                response = await session.get('https://crt.sh/?', params=request_input, headers=HtmlContent.get_header())
                if response.status == 200:
                    data1 = await response.text()
                    data = json.loads(data1)
                    for crt in data:
                        for domains in crt['name_value'].split('\n'):
                            if '@' in domains:
                                continue

                            if domains not in self.results:
                                domains_trans = domains.lower().replace('*.', '')
                                self.results.add((domain, domains_trans))

        except (asyncio.TimeoutError, TypeError, json.decoder.JSONDecodeError) as e:
            print(f'Crt.sh Error via Subdomainscan for: {domain}', e)

        except (aiohttp.ClientConnectorError, aiohttp.ServerConnectionError) as e:
            print(f'Crt.sh Connection Error via Subdomainscan for: {domain}', e)

        except Exception as e:
            print(f'Crt.sh Unusual Error via Subdomainscan for: {domain}', e)

    async def tasks_subdomains_crtsh(self, fuzzy_results: list, session: aiohttp.ClientSession):
        parameters = [{'q': '%.{}'.format(y), 'output': 'json'} for y in fuzzy_results]
        rate_limit = AsyncLimiter(1, 5)
        tasks = [self.crtsh(session, symbol, rate_limit) for symbol in parameters]
        await asyncio.gather(*tasks)

    async def get_results(self, fuzzy_results: list, session: aiohttp.ClientSession):
        await self.tasks_subdomains_crtsh(fuzzy_results, session)
        return self.results
