#!/usr/bin/env python3

import tldextract
import textdistance
from colorama import Fore, Style
from domainthreat.core.utilities import Helper
from domainthreat.core.punycoder import unconfuse
from domainthreat.core.punycoder import normalize_domain
from domainthreat.core.files import ManageFiles


class ScanerDomains:
    def __init__(self, keyword, domain):
        self.keyword = keyword
        self.domain = domain

    def damerau(self, similarity_value: list[int], domain_extract: tldextract.tldextract.TLDExtract) -> str:
        # Based on / Inspired by (c) Everton Gomede, PhD
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

    # LCS only starts to work for brand names or strings with length greater than 8
    # Not activated by default
    def lcs(self, keywordthreshold, domain_extract: tldextract.tldextract.TLDExtract) -> str:
        domain_name = domain_extract(self.domain).domain
        if len(self.keyword) > 8:
            longest_common_substring = ""
            max_length = 0
            for i in range(len(self.keyword)):
                if self.keyword[i] in domain_name:
                    for j in range(len(self.keyword), i, -1):
                        if self.keyword[i:j] in domain_name:
                            if len(self.keyword[i:j]) > max_length:
                                max_length = len(self.keyword[i:j])
                                longest_common_substring = self.keyword[i:j]
            if (len(longest_common_substring) / len(self.keyword)) > keywordthreshold and len(
                    longest_common_substring) is not len(
                    self.keyword) and all(black_keyword_lcs not in self.keyword for black_keyword_lcs in ManageFiles().get_blacklist_lcs()):
                return self.domain

    # X as sublist Input by cpu number separated sublists to make big input list more processable
    # container1, container2 as container for getting domain monitoring results
    @staticmethod
    def get_results(x, container1, container2, blacklist, similarity_range, domain_extract):
        FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

        index = x[0]  # index of sub list
        value = x[1]  # content of sub list
        results_temp = []
        print(FR + f'Processor Job {index} for domain monitoring is starting\n' + S)

        for domain in value:
            if domain[1] in domain[0] and all(black_keyword not in domain[0] for black_keyword in blacklist):
                results_temp.append((domain[0], domain[1], Helper.get_today(), 'Full Word Match'))

            elif ScanerDomains(domain[1], domain[0]).jaccard(n_gram=2, similarity_value=similarity_range[
                'jaccard'], domain_extract=domain_extract) is not None and all(black_keyword not in domain[0] for black_keyword in blacklist):
                results_temp.append((domain[0], domain[1], Helper.get_today(), 'Similarity Jaccard'))

            elif ScanerDomains(domain[1], domain[0]).damerau(
                    similarity_value=similarity_range['damerau'], domain_extract=domain_extract) is not None and all(
                    black_keyword not in domain[0] for black_keyword in blacklist):
                results_temp.append((domain[0], domain[1], Helper.get_today(), 'Similarity Damerau-Levenshtein'))

            elif ScanerDomains(domain[1], domain[0]).jaro_winkler(
                    similarity_value=similarity_range['jaro_winkler'], domain_extract=domain_extract) is not None and all(
                    black_keyword not in domain[0] for black_keyword in blacklist):
                results_temp.append((domain[0], domain[1], Helper.get_today(), 'Similarity Jaro-Winkler'))

            elif unconfuse(domain[0]) is not domain[0]:
                ascii_domain = normalize_domain(domain[0])
                if domain[1] in ascii_domain and all(black_keyword not in ascii_domain for black_keyword in blacklist):
                    results_temp.append((domain[0], domain[1], Helper.get_today(), 'IDN Full Word Match'))

                elif ScanerDomains(domain[1], ascii_domain).damerau(
                        similarity_value=similarity_range['damerau'], domain_extract=domain_extract) is not None and all(
                        black_keyword not in ascii_domain for black_keyword in blacklist):
                    results_temp.append(
                        (domain[0], domain[1], Helper.get_today(), 'IDN Similarity Damerau-Levenshtein'))

                elif ScanerDomains(domain[1], ascii_domain).jaccard(n_gram=2, similarity_value=similarity_range[
                    'jaccard'], domain_extract=domain_extract) is not None and all(black_keyword not in ascii_domain for black_keyword in blacklist):
                    results_temp.append((domain[0], domain[1], Helper.get_today(), 'IDN Similarity Jaccard'))

                elif ScanerDomains(domain[1], ascii_domain).jaro_winkler(
                        similarity_value=similarity_range['jaro_winkler'], domain_extract=domain_extract) is not None and all(
                        black_keyword not in ascii_domain for black_keyword in blacklist):
                    results_temp.append((domain[0], domain[1], Helper.get_today(), 'IDN Similarity Jaro-Winkler'))

        container1.put(results_temp)
        container2.put(index)
        print(FG + f'Processor Job {index} for domain monitoring is finishing\n' + S)
