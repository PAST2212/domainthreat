#!/usr/bin/env python3

from typing import Optional
from dataclasses import dataclass
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from enum import Enum


class RecordStatus(str, Enum):
    PRESENT = "Yes"
    ABSENT = "No"


@dataclass
class DNSConfig:
    resolver_timeout: int = 5
    resolver_lifetime: int = 5
    resolver_nameservers: list[str] = None

    def __post_init__(self):
        if self.resolver_nameservers is None:
            self.resolver_nameservers = ['8.8.8.8']     # Google resolver per default


class ScanerEmailReady:
    def __init__(self, config: Optional[DNSConfig] = None):
        self.config = config or DNSConfig()

    def _get_resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.resolver_timeout
        resolver.lifetime = self.config.resolver_lifetime
        resolver.nameservers = self.config.resolver_nameservers
        return resolver

    def check_mx_record(self, domain: str) -> tuple[str, RecordStatus]:
        resolver = self._get_resolver()
        try:
            answers = resolver.resolve(domain, 'MX')
            if any(ans.exchange for ans in answers):
                return domain, RecordStatus.PRESENT
            return domain, RecordStatus.ABSENT
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            return domain, RecordStatus.ABSENT

    def check_spf_record(self, domain: str) -> tuple[str, RecordStatus]:
        resolver = self._get_resolver()
        try:
            answers = resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_string = "".join(str(txt) for txt in rdata.strings)
                if txt_string.startswith("v=spf1"):
                    if txt_string != 'v=spf1 -all':
                        return domain, RecordStatus.PRESENT
            return domain, RecordStatus.ABSENT
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            return domain, RecordStatus.ABSENT

    def check_dmarc_record(self, domain: str) -> tuple[str, RecordStatus]:
        resolver = self._get_resolver()
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_string = "".join(str(txt) for txt in rdata.strings)
                if txt_string.startswith("v=DMARC1"):
                    return domain, RecordStatus.PRESENT
            return domain, RecordStatus.ABSENT
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            return domain, RecordStatus.ABSENT

    @staticmethod
    def _parallel_check(check_func, domains: list[str], num_workers: list) -> list[tuple[str, RecordStatus]]:
        with ThreadPoolExecutor(max_workers=num_workers[0]) as executor:
            results = list(executor.map(check_func, domains))
        return [r for r in results if r is not None]

    def get_results(self, iterables: list[str], number_workers) -> list:
        mx_results = self._parallel_check(self.check_mx_record, iterables, number_workers)
        spf_results = self._parallel_check(self.check_spf_record, iterables, number_workers)
        dmarc_results = self._parallel_check(self.check_dmarc_record, iterables, number_workers)
        email_ready = mx_results + dmarc_results + spf_results

        return email_ready
