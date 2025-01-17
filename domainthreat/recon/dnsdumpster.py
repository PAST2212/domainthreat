#!/usr/bin/env python3


import asyncio
import aiohttp
import json
from bs4 import BeautifulSoup


class ScanerDnsDumpster:
    def __init__(self) -> None:
        self.results: set[tuple[str, str]] = set()

    @staticmethod
    async def _scrape_subdomains(session: aiohttp.ClientSession, domain: str) -> set[tuple[str, str]]:
        url = "https://dnsdumpster.com/"
        try:
            async with session.get(url=url) as response:
                if response.status != 200:
                    print(f"DNSDumpster initial request failed with status {response.status} for {domain}")
                    return set()

                html = await response.text()
                soup = BeautifulSoup(html, 'lxml')
                csrfmiddlewaretoken = soup.find("input", {"name": "csrfmiddlewaretoken"})
                if not csrfmiddlewaretoken or not csrfmiddlewaretoken.get("value"):
                    print(f"Could not find CSRF token for {domain}")
                    return set()

                if 'csrftoken' not in response.cookies:
                    print(f"No CSRF cookie found for {domain}")
                    return set()

                csrftoken = str(response.cookies['csrftoken'])

                data = {
                    'csrfmiddlewaretoken': csrfmiddlewaretoken["value"],
                    'targetip': domain,
                    'user': 'free'
                }

                headers = {
                    'Referer': url,
                    'Origin': 'https://dnsdumpster.com',
                    'Cookie': f'csrftoken={csrftoken}'
                }

                async with session.post(url, data=data, headers=headers) as scan_response:
                    if scan_response.status != 200:
                        print(f"DNSDumpster scan failed with status {scan_response.status} for {domain}")
                        return set()

                    scan_html = await scan_response.text()
                    result_soup = BeautifulSoup(scan_html, 'lxml')

                    subdomains = set()
                    for subdomain_elem in result_soup.findAll('td', {"class": "col-md-4"}):
                        if subdomain := subdomain_elem.get_text().split()[0]:
                            if domain in subdomain and subdomain:
                                subdomains.add((domain, subdomain))

                    return subdomains

        except asyncio.TimeoutError:
            print(f"Timeout scanning {domain} on DNSDumpster")
        except json.JSONDecodeError:
            print(f"Invalid JSON response from DNSDumpster for {domain}")
        except (aiohttp.ClientError, aiohttp.ServerConnectionError) as e:
            print(f"Connection error scanning {domain} on DNSDumpster: {str(e)}")
        except Exception as e:
            print(f"Unexpected error scanning {domain} on DNSDumpster: {str(e)}")

        return set()

    async def get_results(self, domains: list, session: aiohttp.ClientSession):
        for domain in domains:
            try:
                subdomains = await self._scrape_subdomains(session, domain)
                self.results.update(subdomains)
            except Exception as e:
                print(f"Failed to scan {domain} on DNSDumpster: {str(e)}")
        return self.results
