#!/usr/bin/env python3

import aiohttp
import asyncio
from recon.crtsh import ScanerCrtsh
from recon.subdomaincenter import ScanerSubdomainCenter
from recon.rapiddns import ScanerRapidDns
from recon.dnsdumpster import ScanerDnsDumpster

class ScanerSubdomains:
    def __init__(self):
        self.subdomains = set()

    async def tasks_subdomains(self, iterables: list) -> None:
        # One client Session per function, https://docs.aiohttp.org/en/stable/client_quickstart.html#make-a-request
        async with aiohttp.ClientSession() as session1, aiohttp.ClientSession() as session2, aiohttp.ClientSession() as session3, aiohttp.ClientSession() as session4:
            subs = await asyncio.gather(ScanerCrtsh().get_results(iterables, session1),
                                        ScanerRapidDns().get_results(iterables, session2),
                                        ScanerSubdomainCenter().get_results(iterables, session3),
                                        ScanerDnsDumpster().get_results(iterables, session4)
                                        )
            for sub in subs:
                self.subdomains.update(sub)

    def get_results(self, iterables: list) -> set:
        asyncio.run(self.tasks_subdomains(iterables))

        return self.subdomains