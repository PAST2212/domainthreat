import os
import base64
import datetime
import sys
import zipfile
from io import BytesIO
import textdistance
import tldextract
import csv
from confusables import unconfuse
import dns.resolver
import requests
from bs4 import BeautifulSoup
import unicodedata
import translators as ts
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import pandas as pd
from colorama import Fore, Style
import re
from requests.exceptions import HTTPError

FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

# Daterange of Newly Registered Domains Input from Source whoisds.com.
# Paramater "days=1" means newest feed from today up to maximum oldest feed of newly registered domains "days=4" with free access
daterange = datetime.datetime.today() - datetime.timedelta(days=1)

previous_date = daterange.strftime('20%y-%m-%d')

# Generic Header for making Page Source Requests
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36', 'Pragma': 'no-cache', 'Cache-Control': 'no-cache'}

# List unique brand names from unique_brand_names file
uniquebrands = []

# Results of Domainmonitoring Operations
fuzzy_results = []

# Set Standard Path for CSV file Output and TXT file Input
desktop = os.path.join(os.path.expanduser('~'), 'domainthreat')

# Print Out Date of Domains in CSV file
today = datetime.date.today()

# Daily Domain Input File as List
list_file_domains = []

# Strings or brand names to monitor
# e.g. brands or mailing domain names that your company is using for sending mails
# Keyword File as List
brandnames = []

# Important if there are common word collisions between brand names and other words to reduce false positives
# e.g. blacklist "lotto" if you monitor brand "otto"
# Blacklist File as List
blacklist_keywords = []


# Important if generic words are in brand names list to reduce false positives
# e.g. blacklist "group" if you monitor mailing domain string for your company "companygroup"
# Blacklist LCS File as List
list_file_blacklist_lcs = []

# Topic Keywords to look for in page source as Input
# e.g. product brands or words that are describing your industry or products
# e.g. Keyword "fashion" for a fashion company
list_topics = []

# List for finding Results of Topics in Page Source of fuzzy domains results
topics_matches_domains = []

# Website Status
status_codes = []


# Using Edit-based Textdistance Damerau-Levenshtein for finding look-a-like Domains
# Lenght of brand name or string decides threshold
def damerau(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    damerau = textdistance.damerau_levenshtein(keyword, domain_name)

    if 4 <= len(keyword) <= 6:
        if damerau <= 1:
            return domain

    elif 6 <= len(keyword) <= 9:
        if damerau <= 2:
            return domain

    elif len(keyword) >= 10:
        if damerau <= 3:
            return domain


# Using Token-based Textdistance Jaccard for finding look-a-like Domains
def jaccard(keyword, domain, n_gram):
    domain_letter_weight = '#' + tldextract.extract(domain).domain + '#'
    keyword_letter_weight = '#' + keyword + '#'
    ngram_keyword = [keyword_letter_weight[i:i+n_gram] for i in range(len(keyword_letter_weight)-n_gram+1)]
    ngram_domain_name = [domain_letter_weight[i:i+n_gram] for i in range(len(domain_letter_weight)-n_gram+1)]
    intersection = set(ngram_keyword).intersection(ngram_domain_name)
    union = set(ngram_keyword).union(ngram_domain_name)
    similarity = len(intersection) / len(union) if len(union) > 0 else 0

    if similarity > 0.5:
        return domain


# Using Edit-based Textdistance Jaro Winkler for finding look-a-like Domains
def jaro_winkler(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    winkler = textdistance.jaro_winkler.normalized_similarity(keyword, domain_name)
    if winkler >= 0.9:
        return domain


# Using Sequence-based Textdistance Longest Common Substring (LCS) for finding look-a-like Domains
# LCS only starts to work for brand names or strings with lenght greater than 8
def LCS(keyword, domain, keywordthreshold):
    domain_name = tldextract.extract(domain).domain
    if len(keyword) > 8:
        longestcommonsubstring = ""
        max_lenght = 0
        for i in range(len(keyword)):
            if keyword[i] in domain_name:
                for j in range(len(keyword), i, -1):
                    if keyword[i:j] in domain_name:
                        if len(keyword[i:j]) > max_lenght:
                            max_lenght = len(keyword[i:j])
                            longestcommonsubstring = keyword[i:j]
        if (len(longestcommonsubstring) / len(keyword)) > keywordthreshold and len(longestcommonsubstring) is not len(
                keyword) and all(
                black_keyword_lcs not in keyword for black_keyword_lcs in list_file_blacklist_lcs) is True:
            return domain


# Make DNS MX-Record lookup.
# Not activated per default
def mx_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8']
    try:
        MX = resolver.resolve(domain, 'MX')
        for answer in MX:
            return answer.exchange.to_text()[-1]
    except:
        pass


# Make DNS A-Record lookup.
# Not activated per default
def a_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8']
    try:
        A = resolver.resolve(domain, 'A')
        for answer in A:
            return answer.address
    except:
        pass


#Check for website status
def website_status(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8']
    try:
        resolver.resolve(domain, 'NS')

    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return (domain, 'ServerError')

    except (dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        return (domain, 'Status unknown')

    except:
        return (domain, 'Status unknown')


# Normalize String and translate HTML Title and HTML Description and HTML Description via Google API
def normalize_caseless_tag(transl):
    transle = re.sub("\.", "", transl)

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

            except Exception as e:
                print(f'Webpage Translation Error: {transl}', e)


# Check if Topic Keyword is in Page Source
def topics_filter(tag):
    for value in list_topics:
        try:
            if value in tag or value in normalize_caseless_tag(tag):
                return value

        except Exception as e:
            print(f'Webpage Translation Error: {tag}', e)


# Return Topic Match if matched - Create and Merge Lists per scrapped HTML Tag
def topic_match(domain):
    new = [topics_filter(k) for k in html_tags(domain)[1:] if topics_filter(k) is not None and k != '']
    if len(new) > 0:
        return (domain, list(set(new)))


# Get HTML Title as String
def html_tags(domain):
    hey = []
    domains = 'http://' + domain
    request_session = requests.Session()
    request_session.keep_alive = False
    try:
        response = request_session.get(domains, headers=headers, allow_redirects=True, timeout=(5, 30))
        if response.raise_for_status() is None:
            status_codes.append((domain, 'Online'))
            soup = BeautifulSoup(response.text, 'lxml')
            hey.append(domain)
            title = soup.find('title')
            description = soup.find('meta', attrs={'name': 'description'})
            keywords = soup.find('meta', attrs={'name': 'keywords'})
            if title is not None:
                hey.append(title.get_text().replace('\n', '').lower().strip())
            if description is not None:
                hey.append(description['content'].replace('\n', '').lower().strip())
            if keywords is not None:
                hey.append(keywords['content'].replace('\n', '').lower().strip())

    except (TypeError, AttributeError, requests.exceptions.ReadTimeout, KeyError):
        print('Parsing Webpage Error. Something went wrong at scraping: ', domain)
        status_codes.append((domain, 'Status unknown'))

    except (HTTPError, requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout, requests.exceptions.TooManyRedirects):
        status_codes.append((domain, 'ServerError'))

    except Exception as e:
        print('Other Error occured: ', e)
        status_codes.append((domain, 'Status unknown'))

    return list(filter(None, hey))


def download_input_domains():
    if os.path.isfile(f'{desktop}/domain-names.txt'):
        os.remove(f'{desktop}/domain-names.txt')

    previous_date_formated = previous_date + '.zip'
    new = base64.b64encode(previous_date_formated.encode('ascii'))
    domain_file = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(new.decode('ascii'))

    try:
        request = requests.get(domain_file)
        zipfiles = zipfile.ZipFile(BytesIO(request.content))
        zipfiles.extractall(desktop)

    except Exception:
        print(f'Something went wrong with downloading domain .zip file. Please check download link {domain_file}')
        sys.exit()


def create_new_csv_file_domainresults():
    console_file_path = f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv'
    if not os.path.exists(console_file_path):
        print('Create Monitoring with Newly Registered Domains')
        header = ['Domains', 'Keyword Found', 'Date', 'Detected by', 'Topic found in Source Code', 'Website Status']
        with open(console_file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)


def write_domain_monitoring_results_to_csv():
    with open(f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', mode='a', newline='') as f:
        writer = csv.writer(f, delimiter=',')
        for k in fuzzy_results:
            if isinstance(k, tuple):
                writer.writerow([k[0], k[1], k[2], k[3]])


def create_new_csv_file_topicresults():
    console_file_path = f'{desktop}/Newly_Registered_Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv'
    if not os.path.exists(console_file_path):
        print('Create Monitoring with Newly Registered Topic Domains')
        header = ['Domains', 'Brand in Page Source Code', 'Date']
        with open(console_file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)


def write_topic_monitoring_results_to_csv(listo):
    with open(f'{desktop}/Newly_Registered_Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', mode='a', newline='') as f:
        writer = csv.writer(f, delimiter=',')
        for k in listo:
            writer.writerow([k[0], k[1], k[2]])


# Read Domain Input TXT File as List
def read_input_file():
    if os.path.isfile(f'{desktop}/{previous_date}.txt'):
        os.rename(f'{desktop}/{previous_date}.txt', f'{desktop}/domain-names.txt')
    try:
        file_domains = open(f'{desktop}/domain-names.txt', 'r', encoding='utf-8-sig')
        for my_domains in file_domains:
            domain = my_domains.replace("\n", "").lower().strip()
            list_file_domains.append(domain)
        file_domains.close()

    except Exception as e:
        print('Something went wrong with reading domain-names.txt Input File. Please check file name', e)
        sys.exit()


# Read Keywords TXT File as List
def read_input_keywords_file():
    file_keywords = open(desktop + '/User Input/keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_keywords:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            brandnames.append(domain)
    file_keywords.close()


def read_input_uniquebrands_file():
    file_keywords = open(desktop + '/User Input/unique_brand_names.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_keywords:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            uniquebrands.append(domain)
    file_keywords.close()


# Read Blacklist for Keywords TXT File as List
def read_input_blacklist_file():
    file_blacklist = open(desktop + '/User Input/blacklist_keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_blacklist:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            blacklist_keywords.append(domain)
    file_blacklist.close()


# Read Blacklist Keywords for Longest Common Substring Method as List
def read_input_blacklist_lcs_file():
    file_blacklist = open(desktop + '/User Input/blacklist_lcs.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_blacklist:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            list_file_blacklist_lcs.append(domain)
    file_blacklist.close()


# Read Topic Keywords for Page Source Code Keyword Searches as List
def read_input_topic_file():
    file_topic = open(desktop + '/User Input/topic_keywords.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_topic:
        domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
        if domain is not None and domain != '':
            list_topics.append(domain)
    file_topic.close()


def flatten(sublist):
    for i in sublist:
        if type(i) != type([1]):
            fuzzy_results.append(i)
        else:
            flatten(i)


def topics_to_csv(input_data):
    for y in topics_matches_domains:
        if y[0] == input_data:
            return y[1]


def website_status_to_csv(input_data):
    for y in status_codes:
        if y[0] == input_data:
            return y[1]


def postprocessing_domain_results_outputfile():
    df = pd.read_csv(f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', delimiter=',')
    df['Topic found in Source Code'] = df.apply(lambda x: topics_to_csv(x['Domains']), axis=1)
    df['Website Status'] = df.apply(lambda x: website_status_to_csv(x['Domains']), axis=1)
    df.to_csv(f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', index=False)


def postprocessing_topic_results_outputfile():
    df = pd.read_csv(f'{desktop}/Newly_Registered_Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', delimiter=',')
    df.drop_duplicates(inplace=True, subset=['Domains'])
    df.to_csv(f'{desktop}/Newly_Registered_Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', index=False)


# X as sublist Input by cpu number separated sublists to make big input list more processable
# container1, container2 as container for getting domain monitoring results
def fuzzy_operations(x, container1, container2, blacklist):
    index = x[0]   # index of sub list
    value = x[1]   # content of sub list
    results_temp = []
    print(FR + f'Processor Job {index} for domain monitoring is starting\n' + S)

    for domain in value:
        if domain[1] in domain[0] and all(black_keyword not in domain[0] for black_keyword in blacklist):
            results_temp.append((domain[0], domain[1], today, 'Full Word Match'))

        elif jaccard(domain[1], domain[0], 2) is not None:
            results_temp.append((domain[0], domain[1], today, 'Similarity Jaccard'))

        elif damerau(domain[1], domain[0]) is not None:
            results_temp.append((domain[0], domain[1], today, 'Similarity Damerau-Levenshtein'))

        elif jaro_winkler(domain[1], domain[0]) is not None:
            results_temp.append((domain[0], domain[1], today, 'Similarity Jaro-Winkler'))

       # elif LCS(domain[1], domain[0], 0.5) is not None:
       #     results_temp.append((domain[0], domain[1], today, 'Similarity Longest Common Substring'))

        elif unconfuse(domain[0]) is not domain[0]:
            latin_domain = unicodedata.normalize('NFKD', unconfuse(domain[0])).encode('latin-1', 'ignore').decode('latin-1')
            if domain[1] in latin_domain and all(black_keyword not in latin_domain for black_keyword in blacklist):
                results_temp.append((domain[0], domain[1], today, 'IDN Full Word Match'))

            elif damerau(domain[1], latin_domain) is not None:
                results_temp.append((domain[0], domain[1], today, 'IDN Similarity Damerau-Levenshtein'))

            elif jaccard(domain[1], latin_domain, 2) is not None:
                results_temp.append((domain[0], domain[1], today, 'IDN Similarity Jaccard'))

            elif jaro_winkler(domain[1], latin_domain) is not None:
                results_temp.append((domain[0], domain[1], today, 'IDN Similarity Jaro-Winkler'))

    container1.put(results_temp)
    container2.put(index)
    print(FG + f'Processor Job {index} for domain monitoring is finishing\n' + S)


def page_source_search_in_brand_keyword_results(n):
    thread_ex_list = [y[0] for y in fuzzy_results if isinstance(y, tuple)]

    with ThreadPoolExecutor(n) as executor:
        results = executor.map(topic_match, thread_ex_list)
        for result in results:
            if result is not None and len(result) > 1:
                topics_matches_domains.append(result)

    return topics_matches_domains


def website_status_threading(n):
    thread_ex_list = [y[0] for y in fuzzy_results if isinstance(y, tuple)]
    print(len(thread_ex_list), 'Newly registered domains detected')
    print(*thread_ex_list, sep="\n")

    with ThreadPoolExecutor(n) as executor:
        results = executor.map(website_status, thread_ex_list)
        for result in results:
            if result is not None:
                status_codes.append(result)

    return status_codes


def page_source_search_in_topic_keyword_results(n):
    if len(uniquebrands) > 0:
        thread_ex_list = [y for x in list_topics for y in list_file_domains if x in y]
        print(len(thread_ex_list), 'Newly registered domains detected with topic keywords from file topic_keywords.txt in domain name')
        print('Topic Domain Names Examples: ', thread_ex_list[1:5])

        dummy_u = []

        with ThreadPoolExecutor(n) as executor:
            results = executor.map(html_tags, thread_ex_list)
            for result in results:
                dummy_u.append(result)

        dummy_u2 = list(filter(None, dummy_u))

        topic_in_domainnames_results = [(x[0], y, today) for y in uniquebrands for x in dummy_u2 for z in x[1:] if len(x) > 1 and y in z and all(black_keyword not in z for black_keyword in blacklist_keywords)]

        if len(topic_in_domainnames_results) > 0:
            print('\nMatches detected: ', topic_in_domainnames_results)
            postprocessing_topic_results_outputfile()
            write_topic_monitoring_results_to_csv(topic_in_domainnames_results)
            print('Please check:', FY + f'{desktop}/Newly_Registered_Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv' + S, 'file for results\n')

        else:
            print('\nNo Matches detected: ', topic_in_domainnames_results)
    else:
        print('No brand names provided in unique_brand_names.txt')


if __name__=='__main__':
    download_input_domains()
    read_input_file()
    read_input_keywords_file()
    read_input_uniquebrands_file()
    read_input_blacklist_file()
    #read_input_blacklist_lcs_file()
    read_input_topic_file()
    create_new_csv_file_domainresults()
    create_new_csv_file_topicresults()


if __name__ == '__main__':
    print(FR + '\nStart Domain Monitoring' + S)
    print('Quantity of Newly Registered or Updated Domains from', daterange.strftime('%d-%m-%y') + ':', len(list_file_domains), 'Domains\n')

    new = [(x, y) for y in brandnames for x in list_file_domains]

    def split(domain_input_list, n):
        a, b = divmod(len(domain_input_list), n)
        split_domaininput = [domain_input_list[i * a + min(i, b):(i + 1) * a + min(i + 1, b)] for i in range(n)]
        split_domaininput_order = [[i, v] for i, v in enumerate(split_domaininput)]
        return split_domaininput_order


    sub_list = split(new, multiprocessing.cpu_count())
    print(multiprocessing.cpu_count(), 'CPU Units detected.')

    que_1 = multiprocessing.Queue()
    que_2 = multiprocessing.Queue()

    processes = [multiprocessing.Process(target=fuzzy_operations, args=(sub, que_1, que_2, blacklist_keywords)) for sub in sub_list]

    for p in processes:
        p.daemon = True
        p.start()

    fuzzy_results_temp = [[que_1.get(), que_2.get()] for p in processes]

    for p in processes:
        p.join()
        p.close()

    flatten(fuzzy_results_temp)
    write_domain_monitoring_results_to_csv()
    website_status_threading(50)
    print(FG + 'End Domain Monitoring\n' + S)


if __name__ == '__main__':
    print(FR + 'Start Search task for Topic keywords in source codes of domain monitoring results\n' + S)
    page_source_search_in_brand_keyword_results(50)
    postprocessing_domain_results_outputfile()
    print(FG + '\nEnd Search task for Topic keywords in source codes of domain monitoring results\n' + S)
    print('Please check:', FY + f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv' + S, ' file for results\n')


if __name__=='__main__':
    print(FR + f'Start Advanced Domain Monitoring for brand keywords {uniquebrands} in topic domain names\n' + S)
    page_source_search_in_topic_keyword_results(50)
    print(FG + f'\nEnd Advanced Domain Monitoring for brand keywords {uniquebrands} in topic domain names\n' + S)
