#!/usr/bin/env python3

import dns.resolver
from concurrent.futures import ThreadPoolExecutor


class ScanerEmailReady:
    def __init__(self):
        self.resolver_timeout = 5
        self.resolver_lifetime = 5
        self.resolver_nameservers = ['8.8.8.8']

    def _mx_record(self, domain: str) -> tuple:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.resolver_timeout
        resolver.lifetime = self.resolver_lifetime
        resolver.nameservers = self.resolver_nameservers
        mx = []
        try:
            MX = resolver.resolve(domain, 'MX')
            for answer in MX:
                mx.append(answer.exchange.to_text())
                if answer is not None:
                    return domain, 'Yes'
                else:
                    return domain, 'No'


        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            return domain, 'No'


    def _spf_record(self, domain: str) -> tuple:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.resolver_timeout
        resolver.lifetime = self.resolver_lifetime
        resolver.nameservers = self.resolver_nameservers
        try:
            SPF = resolver.resolve(domain, 'TXT')
            for answer in SPF:
                answer = str(answer).replace('"', '').rstrip(".")
                answer_1 = answer.startswith("v=spf1")
                if answer_1 and answer_1 is not None and answer != 'v=spf1 -all':
                    return domain, 'Yes'
                else:
                    return domain, 'No'

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            return domain, 'No'

    def _dmarc_record(self, domain: str) -> tuple:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.resolver_timeout
        resolver.lifetime = self.resolver_lifetime
        resolver.nameservers = self.resolver_nameservers
        dmarc_domain = "_dmarc." + str(domain)
        try:
            DMARC = resolver.resolve(dmarc_domain, 'TXT')
            for answer in DMARC:
                new_string_dmarc = str(answer).replace("; ", " ").replace(";", " ").replace('"', '').rstrip(".")
                if new_string_dmarc and new_string_dmarc is not None:
                    return domain, 'Yes'
                else:
                    return domain, 'No'

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            return domain, 'No'


    def _multithreading_spf(self, numberthreads: list, iterables: list) -> list:
        iterables_output = []
        with ThreadPoolExecutor(numberthreads[0]) as executor:
            results = executor.map(self._spf_record, iterables)
            for result in results:
                iterables_output.append(result)
        return iterables_output

    def _multithreading_dmarc(self, numberthreads: list, iterables: list) -> list:
        iterables_output = []
        with ThreadPoolExecutor(numberthreads[0]) as executor:
            results = executor.map(self._dmarc_record, iterables)
            for result in results:
                iterables_output.append(result)
        return iterables_output

    def _multithreading_mx(self, numberthreads: list, iterables: list) -> list:
        iterables_output = []
        with ThreadPoolExecutor(numberthreads[0]) as executor:
            results = executor.map(self._mx_record, iterables)
            for result in results:
                iterables_output.append(result)
        return iterables_output

    def get_results(self, number_workers: list, iterables: list) -> list:
        mx = self._multithreading_mx(number_workers, iterables)
        dmarc = self._multithreading_dmarc(number_workers, iterables)
        spf = self._multithreading_spf(number_workers, iterables)

        email_ready = mx + dmarc + spf

        return list(filter(lambda item: item is not None, email_ready))
