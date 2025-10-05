#!/usr/bin/env python3

import tldextract
import datetime
import textdistance
from colorama import Fore, Style
from domainthreat.core.punycoder import normalize_domain, decode_domain, unconfuse


class ScanerDomains:
    def __init__(self, keyword, domain):
        self.keyword = keyword
        self.domain = domain

    def damerau(self, similarity_value: list[int], domain_extract: tldextract.tldextract.TLDExtract) -> str:
        domain_name = domain_extract(self.domain).domain
        len_s1 = len(self.keyword)
        len_s2 = len(domain_name)
        d = [[0] * (len_s2 + 1) for _ in range(len_s1 + 1)]

        for i in range(len_s1 + 1):
            d[i][0] = i
        for j in range(len_s2 + 1):
            d[0][j] = j

        for i in range(1, len_s1 + 1):
            for j in range(1, len_s2 + 1):
                cost = 0 if self.keyword[i - 1] == domain_name[j - 1] else 1
                d[i][j] = min(
                    d[i - 1][j] + 1,
                    d[i][j - 1] + 1,
                    d[i - 1][j - 1] + cost,
                )
                if i > 1 and j > 1 and self.keyword[i - 1] == domain_name[j - 2] and self.keyword[i - 2] == domain_name[j - 1]:
                    d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)

        damerau_distance = d[len_s1][len_s2]

        if similarity_value[0] <= len(self.keyword) <= similarity_value[1]:
            if damerau_distance <= similarity_value[2]:
                return self.domain

        elif similarity_value[3] < len(self.keyword) <= similarity_value[4]:
            if damerau_distance <= similarity_value[5]:
                return self.domain

        elif len(self.keyword) >= similarity_value[6]:
            if damerau_distance <= similarity_value[7]:
                return self.domain

    def jaccard(self, n_gram: int, similarity_value: float, domain_extract: tldextract.tldextract.TLDExtract) -> str:
        domain_letter_weight = domain_extract(self.domain).domain
        keyword_letter_weight = self.keyword
        ngram_keyword = [keyword_letter_weight[i:i + n_gram] for i in range(len(keyword_letter_weight) - n_gram + 1)]
        ngram_domain_name = [domain_letter_weight[i:i + n_gram] for i in range(len(domain_letter_weight) - n_gram + 1)]
        intersection = set(ngram_keyword).intersection(ngram_domain_name)
        union = set(ngram_keyword).union(ngram_domain_name)
        similarity = len(intersection) / len(union) if len(union) > 0 else 0
        if similarity >= similarity_value:
            return self.domain

    def jaro_winkler(self, similarity_value: float, domain_extract: tldextract.tldextract.TLDExtract) -> str:
        domain_name = domain_extract(self.domain).domain
        winkler = textdistance.jaro_winkler.normalized_similarity(self.keyword, domain_name)
        if winkler >= similarity_value:
            return self.domain

    @staticmethod
    def get_results(chunk, container, blacklist, similarity_range, domain_extract):
        FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

        index = chunk[0]
        value = chunk[1]
        today = str(datetime.date.today())
        results_temp = []
        print(FR + f'Processor Job {index} for domain monitoring is starting\n' + S)
        for domain, keyword in value:
            if keyword in domain and all(black_keyword not in domain for black_keyword in blacklist):
                results_temp.append((decode_domain(domain), keyword, today, 'Full Word Match'))

            elif ScanerDomains(keyword, domain).jaccard(n_gram=2, similarity_value=similarity_range['jaccard'], domain_extract=domain_extract) is not None and all(black_keyword not in domain for black_keyword in blacklist):
                results_temp.append((decode_domain(domain), keyword, today, 'Similarity Jaccard'))

            elif ScanerDomains(keyword, domain).damerau(similarity_value=similarity_range['damerau'], domain_extract=domain_extract) is not None and all(black_keyword not in domain for black_keyword in blacklist):
                results_temp.append((decode_domain(domain), keyword, today, 'Similarity Damerau-Levenshtein'))

            elif ScanerDomains(keyword, domain).jaro_winkler(similarity_value=similarity_range['jaro_winkler'], domain_extract=domain_extract) is not None and all(black_keyword not in domain for black_keyword in blacklist):
                results_temp.append((decode_domain(domain), keyword, today, 'Similarity Jaro-Winkler'))

            elif unconfuse(domain) is not domain:
                ascii_domain = normalize_domain(domain)
                if keyword in ascii_domain and all(black_keyword not in ascii_domain for black_keyword in blacklist):
                    results_temp.append((decode_domain(domain), keyword, today, 'IDN Full Word Match'))

                elif ScanerDomains(keyword, ascii_domain).damerau(similarity_value=similarity_range['damerau'], domain_extract=domain_extract) is not None and all(black_keyword not in ascii_domain for black_keyword in blacklist):
                    results_temp.append((decode_domain(domain), keyword, today, 'IDN Similarity Damerau-Levenshtein'))

                elif ScanerDomains(keyword, ascii_domain).jaccard(n_gram=2, similarity_value=similarity_range['jaccard'], domain_extract=domain_extract) is not None and all(black_keyword not in ascii_domain for black_keyword in blacklist):
                    results_temp.append((decode_domain(domain), keyword, today, 'IDN Similarity Jaccard'))

                elif ScanerDomains(keyword, ascii_domain).jaro_winkler(similarity_value=similarity_range['jaro_winkler'], domain_extract=domain_extract) is not None and all(black_keyword not in ascii_domain for black_keyword in blacklist):
                    results_temp.append((decode_domain(domain), keyword, today, 'IDN Similarity Jaro-Winkler'))

        container.put(results_temp)
        print(FG + f'Processor Job {index} for domain monitoring is finishing\n' + S)