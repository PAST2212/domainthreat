#!/usr/bin/env python3

import asyncio
import aiohttp
from domainthreat.recon.crtsh import ScanerCrtsh
from domainthreat.recon.rapiddns import ScanerRapidDns
from domainthreat.recon.dnsdumpster import ScanerDnsDumpster


class ScanerSubdomains:
    def __init__(self):
        self.subdomains = set()

    async def tasks_subdomains(self, iterables: list) -> None:
        async with aiohttp.ClientSession() as session1, aiohttp.ClientSession() as session2, aiohttp.ClientSession() as session3:
            subs = await asyncio.gather(ScanerCrtsh().get_results(iterables, session1),
                                        ScanerRapidDns().get_results(iterables, session2),
                                        ScanerDnsDumpster().get_results(iterables, session3)
                                        )
            for sub in subs:
                self.subdomains.update(sub)

    def get_results(self, iterables: list) -> set:
        asyncio.run(self.tasks_subdomains(iterables))

        return self.subdomains
