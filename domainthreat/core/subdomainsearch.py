#!/usr/bin/env python3

import asyncio
import time
import math
from dataclasses import dataclass
from tqdm import tqdm
import aiohttp
from domainthreat.recon.crtsh import ScanerCrtsh
from domainthreat.recon.rapiddns import ScanerRapidDns
from domainthreat.recon.threatcrowd import ScanerThreatCrowd


@dataclass
class RateLimitConfig:
    name: str
    requests_per_minute: int
    burst_limit: int = 10


SUBDOMAIN_SERVICES = {
    'crtsh': {
        'scanner': ScanerCrtsh,
        'rate_limit': 10
    },
    'rapiddns': {
        'scanner': ScanerRapidDns,
        'rate_limit': 10
    },
    # 'certspotter': {
    #     'scanner': ScanerCertSpotter,
    #     'rate_limit': 15
    # },
    'threatcrowd': {
        'scanner': ScanerThreatCrowd,
        'rate_limit': 10
    }
}


class RateLimiter:
    def __init__(self, requests_per_minute: int, burst_limit: int):
        self.requests_per_minute = requests_per_minute
        self.burst_limit = burst_limit
        self.tokens = burst_limit
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.monotonic()
            time_passed = now - self.last_update

            # Add tokens based on time passed
            self.tokens = min(
                self.burst_limit,
                int(self.tokens + time_passed * (self.requests_per_minute / 60.0))
            )

            if self.tokens < 1:
                wait_time = (1 - self.tokens) * (60.0 / self.requests_per_minute)
                print(f"Rate limit hit, waiting {wait_time:.2f} seconds")
                await asyncio.sleep(wait_time)
                self.tokens = 1

            self.tokens -= 1
            self.last_update = now


class SubdomainScanner:
    def __init__(self):
        self.services = {name: RateLimitConfig(name, requests_per_minute=config['rate_limit']) for name, config in SUBDOMAIN_SERVICES.items()}
        self._session = None
        self.subdomains = set()
        self.progress_bar = None

        self.rate_limiters = {
            name: RateLimiter(config.requests_per_minute, config.burst_limit)
            for name, config in self.services.items()
        }

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    @property
    async def session(self):
        if self._session is None:
            connector = aiohttp.TCPConnector(
                limit=50,
                ttl_dns_cache=300,
                enable_cleanup_closed=True
            )

            timeout = aiohttp.ClientTimeout(total=30, connect=10)

            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
        return self._session

    async def scan_with_rate_limit(self, scanner, iterables, service_name):
        await self.rate_limiters[service_name].acquire()
        result = await scanner.get_results(iterables, await self.session)
        if self.progress_bar:
            self.progress_bar.update(len(iterables))
            self.progress_bar.set_postfix({'service': service_name})
        return result

        # for attempt in range(max_retries):
        #     try:
        #         result = await scanner.get_results(iterables, await self.session)
        #         if self.progress_bar:
        #             self.progress_bar.update(len(iterables))
        #             self.progress_bar.set_postfix({
        #                 'service': service_name,
        #                 'attempt': attempt + 1 if attempt > 0 else ''
        #             })
        #         return result
        #
        #     except Exception as e:
        #         if attempt < max_retries - 1:
        #             wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
        #             if self.progress_bar:
        #                 self.progress_bar.set_postfix({
        #                     'service': service_name,
        #                     'status': f'retrying in {wait_time}s'
        #                 })
        #             await asyncio.sleep(wait_time)
        #         else:
        #             print(f"Final failure for {service_name} after {max_retries} attempts: {str(e)}")
        #             return set()

    async def tasks_subdomains(self, iterables: list) -> None:
        scanner_pairs = [
            (name, config['scanner']())
            for name, config in SUBDOMAIN_SERVICES.items()
        ]

        self.progress_bar = tqdm(
            total=len(iterables) * len(scanner_pairs),
            desc="Scanning domains",
            unit="scan"
        )

        try:
            tasks = []
            for current_service, scanner_instance in scanner_pairs:
                task = self.scan_with_rate_limit(
                    scanner_instance,
                    iterables,
                    current_service
                )
                tasks.append(task)

            scan_results = await asyncio.gather(*tasks)
            for result_set in scan_results:
                self.subdomains.update(result_set)
        except Exception as e:
            print(f"Error during Subdomain scanning: {str(e)}")
        finally:
            if self.progress_bar:
                self.progress_bar.close()
                self.progress_bar = None

    def calculate_time_range(self, total_domains: int) -> tuple[int, int]:
        # Best case: Perfect parallel execution
        fastest_rate = max(config.requests_per_minute for config in self.services.values())
        best_case = math.ceil((total_domains * 60) / fastest_rate)

        # Worst case: Rate limits become bottleneck
        slowest_rate = min(config.requests_per_minute for config in self.services.values())
        worst_case = math.ceil((total_domains * len(self.services) * 60) / slowest_rate)

        return best_case, worst_case

    async def get_results(self, iterables: list) -> set:
        total_domains = len(iterables)
        best_case, worst_case = self.calculate_time_range(total_domains)

        services = ', '.join(f"{name}" for name in self.services.keys())

        print(
            f"Starting scan of {total_domains} domains using {len(self.services)} services: {services}.\n"
            f"Estimated time range: {best_case}-{worst_case} seconds "
            f"({best_case / 60:.1f}-{worst_case / 60:.1f} minutes)"
        )

        start_time = time.time()
        await self.tasks_subdomains(iterables)

        elapsed = time.time() - start_time
        print(
            f"Scan completed in {elapsed:.2f} seconds. "
            f"Found {len(self.subdomains)} subdomains. "
            f"Average: {elapsed / total_domains:.2f} seconds per domain"
        )

        return self.subdomains

    async def close(self):
        if self._session is not None:
            await self._session.close()
            self._session = None


async def async_scan_subdomains(domains: list[str]) -> set[str]:
    """Async function to scan subdomains"""
    async with SubdomainScanner() as scanner:
        return await scanner.get_results(domains)


def scan_subdomains(domains: list[str]) -> set[str]:
    """Synchronous wrapper for the async scanner"""
    return asyncio.run(async_scan_subdomains(domains))
