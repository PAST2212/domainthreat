#!/usr/bin/env python3

import unicodedata
import re
from concurrent.futures import ThreadPoolExecutor
from deep_translator import MyMemoryTranslator
import translators as ts
from domainthreat.core.utilities import SmoothingResults
from domainthreat.core.files import ManageFiles
from domainthreat.core.webscraper import HtmlContent
from domainthreat.core.utilities import Helper


class BasicMonitoring:

    @staticmethod
    def _translator(transl: str) -> str:
        transle = re.sub(r"\.", "", transl)
        try:
            bing = ts.translate_text(transle, 'bing')
            return unicodedata.normalize("NFKD", bing).lower()

        except:
            try:
                alibaba = ts.translate_text(transle, 'alibaba')
                return unicodedata.normalize("NFKD", alibaba).lower()

            except:
                try:
                    google = ts.translate_text(transle, 'google')
                    return unicodedata.normalize("NFKD", google).lower()

                except:
                    pass

    # Check if Topic Keyword is in Page Source
    def _filter(self, tag: str) -> str:
        for value in ManageFiles().get_topic_keywords():
            if value in tag:
                return value
            try:
                if value in self._translator(tag):
                    return value

            except Exception as e:
                print(f'Something went wrong at Translation at HTML Tag: {tag}', e)

    # Return Topic Match if matched - Create and Merge Lists per scrapped HTML Tag
    def _matcher(self, domain: str) -> tuple:
        fetch_status_content = HtmlContent().fetch_items(domain)
        matches_content = [self._filter(k) for k in fetch_status_content[0][1:] if self._filter(k) is not None and k != '']
        http_status = fetch_status_content[1]
        if len(matches_content) > 0:
            return domain, list(set(matches_content)), http_status
        else:
            return domain, 'No Matches', http_status

    def _multithreading_basic(self, numberthreads: list, iterables: list) -> list:
        iterables_output = []
        with ThreadPoolExecutor(numberthreads[0]) as executor:
            results = executor.map(self._matcher, iterables)
            for result in results:
                if result is not None and len(result) > 1:
                    iterables_output.append(result)
        return iterables_output

    def get_results(self, number_workers: list, iterables: list) -> list:
        topics_matches_domains = self._multithreading_basic(number_workers, iterables)

        return list(filter(lambda item: item is not None, topics_matches_domains))


class AdvancedMonitoring:

    @staticmethod
    def _multithreading_advanced(numberthreads: list, iterables: list) -> list:
        iterables_output = []
        with ThreadPoolExecutor(numberthreads[0]) as executor:
            results = executor.map(HtmlContent().fetch_items, iterables)
            for result in results:
                if result is not None and len(result[0]) > 1:
                    iterables_output.append(result[0])

        return list(filter(lambda item: item is not None, iterables_output))

    def _matcher(self, nthreads: list) -> list:
        languages = ManageFiles().get_languages()
        list_topics = ManageFiles().get_topic_keywords()
        uniquebrands = ManageFiles().get_unique_brands()
        list_file_domains = ManageFiles().get_domainfile()
        blacklist_keywords = ManageFiles().get_blacklist_keywords()

        try:
            translate_topics = [MyMemoryTranslator('english', lang).translate_batch(list_topics) for lang in languages]
            flatten_languages = SmoothingResults().get_flatten_list(translate_topics)
            latin_syntax = [(unicodedata.normalize('NFKD', lang).encode('latin-1', 'ignore').decode('latin-1'), lang) for lang in flatten_languages]
            latin_translated = list(filter(lambda item: item is not None, [re.sub(r"[^a-z]", "", i[1].lower()) for i in latin_syntax if i[0] == i[1]]))
            latin_translated_deduplicated = list(set(latin_translated))
            print('Translated Keywords: ', latin_translated_deduplicated)
            joined_topic_keywords = latin_translated_deduplicated + list_topics

        except Exception as e:
            print('Something went wrong with Translation of topic keywords: ', e)
            joined_topic_keywords = []

        if len(uniquebrands) > 0 and len(list_topics) > 0:
            if len(joined_topic_keywords) > len(list_topics):
                thread_ex_list = [y for x in joined_topic_keywords for y in list_file_domains if x in y.split('.')[0]]
                print(len(thread_ex_list),
                      f'Newly registered domains detected with topic and translated topic keywords based on file topic_keywords.txt in domain name')

            else:
                thread_ex_list = [y for x in list_topics for y in list_file_domains if x in y.split('.')[0]]
                print(len(thread_ex_list),
                      f'Newly registered domains detected with topic keywords based on file topic_keywords.txt in domain name')

            thread_ex_list = list(set(thread_ex_list))
            print('Example Domains: ', thread_ex_list[1:8], '\n')

            html_content_temp = self._multithreading_advanced(numberthreads=nthreads, iterables=thread_ex_list)

            html_content = list(filter(lambda item: item is not None, html_content_temp))

            topic_in_domainname_results = [(x[0], y, Helper.get_today()) for y in uniquebrands for x in html_content for z in x[1:] if len(x) > 1 and y in z and all(black_keyword not in z for black_keyword in blacklist_keywords)]

            return list(set(topic_in_domainname_results))

        else:
            print('Please check unique_brand_names.txt and topic_keywords.txt for input')

    def get_results(self, number_workers: list) -> None:
        results = self._matcher(number_workers)
        if results is not None and len(results) > 0:
            print(f'\n{len(results)} Matches detected: ', results)
            print(*results, sep='\n')
            ManageFiles().create_csv_advanced_monitoring()
            ManageFiles().write_csv_advanced_monitoring(iterables=results)
            ManageFiles().postprocessing_advanced_monitoring()
        else:
            print('\nNo Matches detected: ', results)
