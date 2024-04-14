#!/usr/bin/env python3

import tldextract
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from .webscraper import HtmlContent

class ScanerParkedState:
    def __init__(self):
        self.resolver_timeout = 5
        self.resolver_lifetime = 5
        self.resolver_nameservers = ['8.8.8.8']

    @staticmethod
    def _parked(domain) -> tuple:
        domains = 'http://' + domain
        parked_keywords = ['parkingcrew.net', 'sedoparking',
                           'img1.wsimg.com/parking-lander/static/js/main.2de80224.chunk.js',
                           'This domain name is parked for FREE by',
                           'This domain has been registered via IONOS and is not yet connected to a website',
                           'Parked Domain name on Hostinger DNS system']
        try:
            response = requests.get(domains, headers=HtmlContent().get_header(), allow_redirects=True, timeout=(5, 30))
            if response.raise_for_status() is None:
                soup = BeautifulSoup(response.text, 'lxml')
                try:
                    hidden_redirect_1 = soup.find("meta")["content"]
                    hidden_redirect_2 = soup.find("meta")["http-equiv"]
                    # Find instant client redirects https://www.w3.org/TR/WCAG20-TECHS/H76.html
                    if '0;url=' in hidden_redirect_1.lower().replace(" ", "") and 'refresh' in hidden_redirect_2.lower().strip():
                        redirect_url = hidden_redirect_1.split("=")[-1]
                        if tldextract.extract(redirect_url).registered_domain == '':
                            transformed_url = domains + "/" + hidden_redirect_1.split("=")[-1]
                            transformed_response = requests.get(transformed_url, headers=HtmlContent().get_header(), allow_redirects=True,
                                                                timeout=(5, 30))
                            hidden_redirect_soup = BeautifulSoup(transformed_response.text, 'lxml')
                            for k in parked_keywords:
                                if k.lower() in str(hidden_redirect_soup.html).lower():
                                    return domain, 'Yes'
                                else:
                                    return domain, 'No'
                        else:
                            transformed_url = hidden_redirect_1.split("=")[-1]
                            transformed_response = requests.get(transformed_url, headers=HtmlContent().get_header(), allow_redirects=True,
                                                                timeout=(5, 30))
                            hidden_redirect_soup = BeautifulSoup(transformed_response.text, 'lxml')
                            for k in parked_keywords:
                                if k.lower() in str(hidden_redirect_soup.html).lower():
                                    return domain, 'Yes'
                                else:
                                    return domain, 'No'

                    else:
                        for k in parked_keywords:
                            if k.lower() in str(soup.html).lower():
                                return domain, 'Yes'
                            else:
                                return domain, 'No'

                except:
                    for k in parked_keywords:
                        if k.lower() in str(soup.html).lower():
                            return domain, 'Yes'
                        else:
                            return domain, 'No'
        except:
            pass

    def _multithreading_parked(self, numberthreads: list, iterables: list) -> list:
        iterables_output = []
        with ThreadPoolExecutor(numberthreads[0]) as executor:
            results = executor.map(self._parked, iterables)
            for result in results:
                iterables_output.append(result)
        return iterables_output


    def get_results(self, number_workers: list, iterables: list) -> list:
        parked = self._multithreading_parked(number_workers, iterables)
        return list(filter(None, parked))
