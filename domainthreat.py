#!/usr/bin/env python3

import asyncio
import datetime
import sys
import time
import os
from colorama import Fore, Style
import argparse
import tldextract
import multiprocessing
from domainthreat.core.domainsearch import ScanerDomains
from domainthreat.core.files import ManageFiles
from domainthreat.core.sourcecodesearch import BasicMonitoring
from domainthreat.core.sourcecodesearch import AdvancedMonitoring
from domainthreat.core.utilities import SmoothingResults
from domainthreat.core.utilities import Helper
from domainthreat.core.version import VERSION
from domainthreat.core.emailready import ScanerEmailReady
from domainthreat.core.parked import ScanerParkedState
from domainthreat.core.subdomainsearch import ScanerSubdomains


if __name__ == '__main__':

    # initialize once, otherwise tld suffix list will be requested in every multiprocessor
    domain_extract = tldextract.TLDExtract(include_psl_private_domains=True)
    domain_extract('google.com')

    FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    number_threads = []
    status_codes = []
    topics_matches_domains = []
    thresholds = {}

    print(FG + f"""
    -------------------------------------------------------
    #              Domainthreat {VERSION}                     #
    #            (c) Patrick Steinhoff                    #
    #   https://github.com/PAST2212/domainthreat.git      #
    -------------------------------------------------------
    """ + S)

    threads_standard = min(16, os.cpu_count() + 2)
    parser = argparse.ArgumentParser(usage='domainthreat.py [OPTIONS]', formatter_class=lambda prog: argparse.HelpFormatter(prog, width=150, max_help_position=100))

    parser.add_argument('-s', '--similarity', type=str, default='close', metavar='SIMILARITY MODE', choices=['close', 'medium', 'wide'], help='Similarity range of homograph, typosquatting detection algorithms with SIMILARITY MODE options "close" OR "wide" OR "medium" threshold range. Mode "close" is running per default.')
    parser.add_argument('-t', '--threads', type=int, metavar='NUMBER THREADS', default=threads_standard, help=f'Default threads number is CPU based and per default: {threads_standard}')

    if len(sys.argv[1:]) == 0:
        parser.print_help()

    args = parser.parse_args()

    def arg_threads():
        if args.threads > threads_standard:
            number_threads.append(args.threads)
        else:
            number_threads.append(threads_standard)

    def arg_thresholds():
        if args.similarity.lower() == 'medium':
            thresholds['damerau'] = [4, 6, 1, 6, 9, 2, 10, 2]
            thresholds['jaccard'] = 0.50
            thresholds['jaro_winkler'] = 0.85

        elif args.similarity.lower() == 'close':
            thresholds['damerau'] = [4, 6, 1, 6, 9, 1, 10, 2]
            thresholds['jaccard'] = 0.60
            thresholds['jaro_winkler'] = 0.9

        elif args.similarity.lower() == 'wide':
            thresholds['damerau'] = [4, 6, 1, 6, 9, 2, 10, 3]
            thresholds['jaccard'] = 0.45
            thresholds['jaro_winkler'] = 0.80

        else:
            parser.error('Similarity Argument is not supported. Please use "-s close" OR "-s wide" OR "-s medium" as input argument.\n'
                         'In case of leaving this similarity input argument blank: "close" mode is running per default')

    arg_threads()
    arg_thresholds()

    print('\nNumber of Threads: ', FG + str(number_threads[0]) + S)
    print('Selected Similarity Mode: ', FG + args.similarity + S)
    time.sleep(4)

    print(FR + '\nStart Downloading & Processing Domain Data Feeds' + S)
    file_manager = ManageFiles()
    file_manager.download_whoisds_domains()
    file_manager.download_github_domains()

    whoisds_domains = file_manager.get_whoisds_domainfile()
    github_domains = file_manager.get_github_domainfile()

    list_file_domains = list(set(whoisds_domains + github_domains))

    brandnames = file_manager.get_keywords()
    uniquebrands = file_manager.get_unique_brands()
    blacklist_keywords = file_manager.get_blacklist_keywords()
    list_topics = file_manager.get_topic_keywords()
    languages = file_manager.get_languages()
    file_manager.create_csv_basic_monitoring()
    file_manager.create_domain_output_file()

    print(FR + '\nStart Basic Domain Monitoring and Feature Scans' + S)
    print('Quantity of Newly Registered or Updated Domains from', (datetime.datetime.today() - datetime.timedelta(days=1)).strftime('%d.%m.%y') + ':', len(list_file_domains), 'Domains\n')

    domaindata_transform = [(x, y) for y in brandnames for x in list_file_domains]

    sub_list = Helper().split_into_chunks(domaindata_transform, multiprocessing.cpu_count())
    print(multiprocessing.cpu_count(), 'CPU Units detected.')

    que_1 = multiprocessing.Queue()
    que_2 = multiprocessing.Queue()

    processes = [multiprocessing.Process(target=ScanerDomains.get_results, args=(sub, que_1, que_2, blacklist_keywords, thresholds, domain_extract)) for sub
                 in sub_list]

    for p in processes:
        p.start()

    fuzzy_results_temp = [[que_1.get(), que_2.get()] for p in processes]

    for p in processes:
        p.join()
        p.close()

    fuzzy_results = SmoothingResults().get_flatten_list(fuzzy_results_temp)
    domain_results = [y[0] for y in fuzzy_results if isinstance(y, tuple)]
    file_manager.write_domain_output_file(fuzzy_results)
    print('Please check:', FY + f'domain_results_{datetime.datetime.today().strftime('20%y_%m_%d')}.csv' + S, ' file for only domain data results\n')
    file_manager.write_csv_basic_monitoring(fuzzy_results)
    print(*domain_results, sep="\n")
    print(FY + f'{len(domain_results)} Newly registered domains detected\n' + S)
    print(FR + '\nStart E-Mail Ready & Parked State Scan' + S)
    e_mail_ready = ScanerEmailReady().get_results(number_workers=number_threads, iterables=domain_results)
    parked_domains = ScanerParkedState().get_results(number_workers=number_threads, iterables=domain_results)
    print(FG + 'End E-Mail Ready & Parked State Scan\n' + S)
    print(FR + f'\nStart Subdomain Scan: This can take some time {FY}-at least {len(domain_results)*5} Seconds- {FR}to not exceed IP based rate limits' + S)
    subdomains = ScanerSubdomains().get_results(iterables=domain_results)
    print(FG + 'End Subdomain Scan\n' + S)
    print(FG + 'End Basic Domain Monitoring Scan\n' + S)

    print(FR + 'Start Search task for topic keywords in source codes of domain monitoring results' + S)
    source_code_basic = BasicMonitoring().get_results(number_workers=number_threads, iterables=domain_results)
    for values in source_code_basic:
        status_codes.append((values[0], values[2]))
        topics_matches_domains.append((values[0], values[1]))

    file_manager.postprocessing_basic_monitoring(iterables=domain_results, source=topics_matches_domains, website_status=status_codes, park_domain=parked_domains, subdomain=subdomains, email_info=e_mail_ready)
    print(FG + 'End Search task for topic keywords in source codes of domain monitoring results\n' + S)
    print('Please check:', FY + f'Newly_Registered_Domains_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv' + S, ' file for results\n')

    print(FR + f'Start Advanced Domain Monitoring for brand keywords {uniquebrands}\n' + S)
    AdvancedMonitoring().get_results(number_workers=number_threads)
    print(FG + f'\nEnd Advanced Domain Monitoring for brand keywords {uniquebrands}' + S)
