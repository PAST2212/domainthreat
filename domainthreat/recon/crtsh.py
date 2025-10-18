#!/usr/bin/env python3

import asyncio
import json
import aiohttp


class ScanerCrtsh:
    def __init__(self) -> None:
        self.results: set[tuple[str, str]] = set()

    @staticmethod
    async def _scrape_subdomains(session: aiohttp.ClientSession, domain: str):
        params = {
            'q': f"%.{domain}",
            'output': 'json'
        }

        try:
            async with session.get('https://crt.sh/', params=params) as response:
                if response.status == 200:
                    data = await response.text()
                    certificates = json.loads(data)

                    subdomains = set()
                    for cert in certificates:
                        for subdomain in cert['name_value'].split('\n'):
                            # Skip email addresses
                            if '@' in subdomain:
                                continue

                            subdomain = subdomain.lower().replace('*.', '')
                            if subdomain:
                                subdomains.add((domain, subdomain))

                    return subdomains
                else:
                    print(f"Crt.sh returned status {response.status} for {domain}")

        except asyncio.TimeoutError:
            print(f"Timeout scanning {domain} on crt.sh")
        except json.JSONDecodeError:
            print(f"Invalid JSON response from crt.sh for {domain}")
        except (aiohttp.ClientError, aiohttp.ServerConnectionError) as e:
            print(f"Connection error scanning {domain} on crt.sh: {str(e)}")
        except Exception as e:
            print(f"Unexpected error scanning {domain} on crt.sh: {str(e)}")

        return set()

    async def get_results(self, domains: list, session: aiohttp.ClientSession):
        for domain in domains:
            try:
                subdomains = await self._scrape_subdomains(session, domain)
                self.results.update(subdomains)
            except Exception as e:
                print(f"Failed to scan {domain} on crt.sh: {str(e)}")
        return self.results
