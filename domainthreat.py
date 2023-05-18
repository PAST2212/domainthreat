import os
import base64
import datetime
import zipfile
from io import BytesIO
import textdistance
import tldextract
import csv
import whois
from confusables import unconfuse
import whoisit
import re
import dns.resolver
import requests
from bs4 import BeautifulSoup
import unicodedata
from googletrans import Translator
import time
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import pandas as pd
from colorama import Fore, Style

FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

# Daterange of Newly Registered Domains Input from Source whoisds.com.
# Paramater "days=1" means newest feed from today up to maximum oldest feed of newly registered domains "days=4" with free access
daterange = datetime.datetime.today() - datetime.timedelta(days=1)

whoisit.bootstrap(overrides=True)

# Generic Header for making Page Source Requests
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36', 'Pragma': 'no-cache', 'Cache-Control': 'no-cache'}

# Unique brands
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
Blacklist = []

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


# Using Edit-based Textdistance Damerau-Levenshtein for finding look-a-like Domains
# Lenght of brand name or string decides threshold
def damerau(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    damerau = textdistance.damerau_levenshtein(keyword, domain_name)
    if len(keyword) <= 3:
        pass

    elif 4 <= len(keyword) <= 6:
        if damerau <= 1:
            return domain
        else:
            pass

    elif 6 <= len(keyword) <= 9:
        if damerau <= 2:
            return domain
        else:
            pass

    elif len(keyword) >= 10:
        if damerau <= 3:
            return domain
        else:
            pass


# Using Token-based Textdistance Jaccard for finding look-a-like Domains
# Threshold is independent from brand name or string lenght
def jaccard(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    jaccard = textdistance.jaccard.normalized_similarity(keyword, domain_name)
    if jaccard >= 0.8:
        return domain
    else:
        pass


# Using Edit-based Textdistance Jaro Winkler for finding look-a-like Domains
# Threshold is independent from brand name or string lenght
def jaro_winkler(keyword, domain):
    domain_name = tldextract.extract(domain).domain
    Jaro_Winkler = textdistance.jaro_winkler.normalized_similarity(keyword, domain_name)
    if Jaro_Winkler >= 0.9:
        return domain
    else:
        pass


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


# Make Domain creation date lookup via WHOIS or RDAP protocol.
# Not activated per default
def whois_creation_date(domain):
    import time
    try:
        registered = whoisit.domain(domain, allow_insecure_ssl=True)['registration_date']
        creation_date = registered.strftime('%d-%m-%y')
        return creation_date

    except (whoisit.errors.UnsupportedError, KeyError, AttributeError, whoisit.errors.QueryError):
        try:
            registered = whois.whois(domain)
            creation_date = registered.creation_date
            return creation_date[0].strftime('%d-%m-%y')

        except (TypeError, AttributeError):
            if creation_date is not None:
                return creation_date.strftime('%d-%m-%y')
            else:
                pass

        except Exception:
            pass
        except whois.parser.PywhoisError:
            pass

    except whoisit.errors.ResourceDoesNotExist:
        pass
    time.sleep(2)


# Make Domain registrar lookup via WHOIS or RDAP protocol.
# Not activated per default
def whois_registrar(domain):
    import time
    try:
        registered = whoisit.domain(domain, allow_insecure_ssl=True)['entities']['registrar']
        registered_temp = list([registered[0].get('name')])
        registered_temp_2 = str(registered_temp).encode('utf-8-sig').decode('ascii', 'ignore')
        domain_registrar = re.sub(r"[\[,'\]]", "", str(registered_temp_2))
        return domain_registrar

    except (whoisit.errors.UnsupportedError, KeyError, AttributeError, whoisit.errors.QueryError, UnicodeError,
            UnicodeEncodeError, UnicodeDecodeError):
        try:
            registered = whois.whois(domain)
            domain_registrar = str(registered.registrar).replace(',', '')
            return domain_registrar

        except TypeError:
            pass
        except AttributeError:
            pass
        except Exception:
            pass
        except whois.parser.PywhoisError:
            pass

    except whoisit.errors.ResourceDoesNotExist:
        return 'NXDOMAIN'
        pass
    time.sleep(2)


# Make DNS MX-Record lookup.
# Not activated per default
def MX_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    try:
        MX = resolver.resolve(domain, 'MX')
        for answer in MX:
            return answer.exchange.to_text()[:-1]
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        return 'MX Record Not Found'
        pass
    except dns.name.EmptyLabel:
        pass
    except dns.resolver.Timeout:
        return 'Connection Timeout'
        pass
    except dns.exception.DNSException:
        pass


# Make DNS A-Record lookup.
# Not activated per default
def A_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    try:
        A = resolver.resolve(domain, 'A')
        for answer in A:
            return answer.address
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        return 'A Record Not Found'
        pass
    except dns.name.EmptyLabel:
        pass
    except dns.resolver.Timeout:
        return 'Connection Timeout'
        pass
    except dns.exception.DNSException:
        pass


# Normalize String and translate HTML Title and HTML Description and HTML Description via Google API
def normalize_caseless_tag(transl):
    translator = Translator()
    try:
        result = translator.translate(transl, dest='en').text
        return unicodedata.normalize("NFKD", result).lower()

    except:
        pass


# Check if Topic Keyword is in Page Source
def topics_filter(tag):
    for value in list_topics:
        try:
            if value in tag or value in normalize_caseless_tag(tag):
                return value
        except TypeError:
            continue

        except:
            pass


# Return Topic Match if matched - Create and Merge Lists per scrapped HTML Tag
def Topic_Match(domain):
    new = [topics_filter(k) for k in html_tags(domain)[1:] if topics_filter(k) is not None and k != '']
    if len(new) > 0:
        return (domain, list(set(new)))


# Get HTML Title as String
def html_tags(domain):
    hey = []
    domains = 'http://' + domain
    try:
        response = requests.get(domains, headers=headers, allow_redirects=True)
        #response = session.get(domains, headers=headers, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'lxml')
        hey.append(domain)
        hey.append(soup.find('title').get_text().replace('\n', '').lower().strip())
        hey.append(soup.find('meta', attrs={'name': 'description'})['content'].replace('\n', '').lower().strip())
        hey.append(soup.find('meta', attrs={'name': 'keywords'})['content'].replace('\n', '').lower().strip())
    except:
        pass

    return list(filter(None, hey))


def download_Inut_Domains():
    if os.path.isfile(desktop+'/domain-names.txt'):
        os.remove(desktop+'/domain-names.txt')

    previous_Date = daterange
    previous_date_formated = previous_Date.strftime('20%y-%m-%d')+'.zip'
    new = base64.b64encode(previous_date_formated.encode('ascii'))
    domain_file = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(new.decode('ascii'))

    request = requests.get(domain_file)

    zipfiles = zipfile.ZipFile(BytesIO(request.content))
    zipfiles.extractall(desktop)


def create_new_csv_file_domainresults():
    console_file_path = f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv'
    if not os.path.exists(console_file_path):
        print('Create Monitoring with Newly Registered Domains')
        header = ['Domains', 'Keyword Found', 'Date', 'Detected by', 'Topic found in Source Code']
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
    console_file_path = f'{desktop}/Newly-Registered-Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv'
    if not os.path.exists(console_file_path):
        print('Create Monitoring with Newly Registered Topic Domains')
        header = ['Domains', 'Brand in Page Source Code', 'Date']
        with open(console_file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)


def write_topic_monitoring_results_to_csv(listo):
    with open(f'{desktop}/Newly-Registered-Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', mode='a', newline='') as f:
        writer = csv.writer(f, delimiter=',')
        for k in listo:
            writer.writerow([k[0], k[1], k[2]])


# Read Domain Input TXT File as List
def read_input_file():
    file_domains = open(desktop + '/domain-names.txt', 'r', encoding='utf-8-sig')
    for my_domains in file_domains:
        domain = my_domains.replace("\n", "").lower().strip()
        list_file_domains.append(domain)
    file_domains.close()


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
            Blacklist.append(domain)
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


def postprocessing_domain_results_outputfile():
    df = pd.read_csv(f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', delimiter=',')
    df['Topic found in Source Code'] = df.apply(lambda x: topics_to_csv(x['Domains']), axis=1)
    df.to_csv(f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', index=False)


def postprocessing_topic_results_outputfile():
    df = pd.read_csv(f'{desktop}/Newly-Registered-Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', delimiter=',')
    df.drop_duplicates(inplace=True, subset=['Domains'])
    df.to_csv(f'{desktop}/Newly-Registered-Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', index=False)


# X as sublist Input by cpu number separated sublists to make big input list more processable
# container1, container2 as container for getting domain monitoring results
def fuzzyoperations(x, container1, container2):
   index = x[0]   # index of sub list
   value = x[1]   # content of sub list
   results_temp = []
   print(FR + f'Processor Job {index} for domain monitoring is starting\n' + S)
   for domain in value:
       if domain[1] in domain[0] and all(black_keyword not in domain[0] for black_keyword in Blacklist):
           results_temp.append((domain[0], domain[1], today, 'Full Word Match'))

       elif jaccard(domain[1], domain[0]) is not None:
           results_temp.append((domain[0], domain[1], today, 'Similarity Jaccard'))

       elif damerau(domain[1], domain[0]) is not None:
           results_temp.append((domain[0], domain[1], today, 'Similarity Damerau-Levenshtein'))

       elif jaro_winkler(domain[1], domain[0]) is not None:
           results_temp.append((domain[0], domain[1], today, 'Similarity Jaro-Winkler'))

       # elif LCS(domain[1], domain[0], 0.5) is not None:
       #     results_temp.append((domain[0], domain[1], today, 'Similarity Longest Common Substring'))

       elif unconfuse(domain[0]) is not domain[0]:
           latin_domain = unicodedata.normalize('NFKD', unconfuse(domain[0])).encode('latin-1', 'ignore').decode('latin-1')
           if domain[1] in latin_domain and all(black_keyword not in latin_domain for black_keyword in Blacklist):
               results_temp.append((domain[0], domain[1], today, 'IDN Full Word Match'))

           elif damerau(domain[1], latin_domain) is not None:
               results_temp.append((domain[0], domain[1], today, 'IDN Similarity Damerau-Levenshtein'))

           elif jaccard(domain[1], latin_domain) is not None:
               results_temp.append((domain[0], domain[1], today, 'IDN Similarity Jaccard'))

           elif jaro_winkler(domain[1], latin_domain) is not None:
               results_temp.append((domain[0], domain[1], today, 'IDN Similarity Jaro-Winkler'))

   container1.put(results_temp)
   container2.put(index)
   print(FG + f'Processor Job {index} for domain monitoring is finishing\n' + S)


def Page_Source_Search_in_brand_keyword_results(n):
    thread_ex_list = [y[0] for y in fuzzy_results if isinstance(y, tuple)]
    print(len(thread_ex_list), 'Domain registrations detected with keywords from file keywords.txt in domain name or are similar registered\n')

    with ThreadPoolExecutor(n) as executor:
        results = executor.map(Topic_Match, thread_ex_list)
        for result in results:
            if result is not None and len(result) > 1:
                topics_matches_domains.append(result)

    return topics_matches_domains


def Page_Source_Search_in_topic_keyword_results(n):
    thread_ex_list = [y for x in list_topics for y in list_file_domains if x in y]
    print(len(thread_ex_list), 'Domain registrations detected with topic keywords from file topic_keywords.txt in domain name\n')

    dummy_u = []

    with ThreadPoolExecutor(n) as executor:
        results = executor.map(html_tags, thread_ex_list)
        for result in results:
            dummy_u.append(result)

    dummy_u2 = list(filter(None, dummy_u))

    topic_in_domainnames_results = [(x[0], y, today) for y in uniquebrands for x in dummy_u2 for z in x[1:] if len(x) > 1 and y in z and all(black_keyword not in z for black_keyword in Blacklist)]
    print(topic_in_domainnames_results, 'Domain registrations with brand keyword from file unique_brand_names.txt in Source Code\n')
    write_topic_monitoring_results_to_csv(topic_in_domainnames_results)


if __name__=='__main__':
    download_Inut_Domains()
    read_input_file()
    read_input_keywords_file()
    read_input_uniquebrands_file()
    read_input_blacklist_file()
    #read_input_blacklist_lcs_file()
    read_input_topic_file()
    create_new_csv_file_domainresults()
    create_new_csv_file_topicresults()


if __name__=='__main__':
    print(FR + 'Start Domain Monitoring\n' + S)
    print('Quantity of Newly Registered or Updated Domains from', daterange.strftime('%d-%m-%y') + ':', len(list_file_domains), 'Domains')

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

    processes = [multiprocessing.Process(target=fuzzyoperations, args=(sub, que_1, que_2)) for sub in sub_list]

    for p in processes:
        p.daemon = True
        p.start()

    fuzzy_results_temp = [[que_1.get(), que_2.get()] for p in processes]

    for p in processes:
        p.join()
        p.close()

    flatten(fuzzy_results_temp)
    write_domain_monitoring_results_to_csv()
    print(FG + 'End Domain Monitoring\n' + S)


if __name__=='__main__':
    print(FR + 'Start Page Source Searching for Topic keywords in domain monitoring results\n' + S)
    Page_Source_Search_in_brand_keyword_results(50)
    postprocessing_domain_results_outputfile()
    print(FG + 'End Page Source Searching for Topic keywords in domain monitoring results\n' + S)
    print('Please check:', FY + f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv' + S, ' file for results\n')


if __name__=='__main__':
    print(FR + 'Start Page Source Searching for brand keywords in topic keyword results\n'+ S)
    Page_Source_Search_in_topic_keyword_results(50)
    postprocessing_topic_results_outputfile()
    print(FG + 'End Page Source Searching for brand keywords in topic keyword results\n' + S)
    print('Please check:', FY + f'{desktop}/Newly-Registered-Topic_Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv' + S, 'file for results\n')

