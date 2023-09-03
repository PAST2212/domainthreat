import os
import base64
import datetime
import sys
import zipfile
from io import BytesIO
import textdistance
import tldextract
import csv
from detectidna import unconfuse
import dns.resolver
import requests
from bs4 import BeautifulSoup
import unicodedata
import translators as ts
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing
import pandas as pd
from colorama import Fore, Style
import re
import json

FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

# Daterange of Newly Registered Domains Input from Source whoisds.com.
# Paramater "days=1" means newest feed from today up to maximum oldest feed of newly registered domains "days=4" with free access
daterange = datetime.datetime.today() - datetime.timedelta(days=1)

previous_date = daterange.strftime('20%y-%m-%d')

# Generic Header for making Page Source Requests
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    'Pragma': 'no-cache', 'Cache-Control': 'no-cache'}

header_subdomain_services = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'}

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

# Subdomains
subdomains = set()

# Domain mail sending or receiving able
e_mail_ready = []

# Parked Domains
parked_domains = []


def flatten(sublist):
    for i in sublist:
        if type(i) != type([1]):
            fuzzy_results.append(i)
        else:
            flatten(i)


def group_tuples_first_value(klaus):
    out = {}
    for elem in klaus:
        try:
            out[elem[0]].extend(elem[1:])
        except KeyError:
            out[elem[0]] = list(elem)

    return [tuple(values) for values in out.values()]


class StringMatching:
    def __init__(self, keyword, domain):
        self.keyword = keyword
        self.domain = domain

    def damerau(self):
        domain_name = tldextract.extract(self.domain).domain
        damerau = textdistance.damerau_levenshtein(self.keyword, domain_name)

        if 4 <= len(self.keyword) <= 6:
            if damerau <= 1:
                return self.domain

        elif 6 <= len(self.keyword) <= 9:
            if damerau <= 2:
                return self.domain

        elif len(self.keyword) >= 10:
            if damerau <= 3:
                return self.domain

    def jaccard(self, n_gram):
        domain_letter_weight = '#' + tldextract.extract(self.domain).domain + '#'
        keyword_letter_weight = '#' + self.keyword + '#'
        ngram_keyword = [keyword_letter_weight[i:i + n_gram] for i in range(len(keyword_letter_weight) - n_gram + 1)]
        ngram_domain_name = [domain_letter_weight[i:i + n_gram] for i in range(len(domain_letter_weight) - n_gram + 1)]
        intersection = set(ngram_keyword).intersection(ngram_domain_name)
        union = set(ngram_keyword).union(ngram_domain_name)
        similarity = len(intersection) / len(union) if len(union) > 0 else 0

        if similarity > 0.5:
            return self.domain

    def jaro_winkler(self):
        domain_name = tldextract.extract(self.domain).domain
        winkler = textdistance.jaro_winkler.normalized_similarity(self.keyword, domain_name)
        if winkler >= 0.9:
            return self.domain

    # LCS only starts to work for brand names or strings with length greater than 8
    def lcs(self, keywordthreshold):
        domain_name = tldextract.extract(self.domain).domain
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
                    self.keyword) and all(black_keyword_lcs not in self.keyword for black_keyword_lcs in list_file_blacklist_lcs):
                return self.domain


class FeatureProcessing:
    def __init__(self, domain):
        self.domain = domain
        self.resolver_timeout = 5
        self.resolver_lifetime = 5
        self.resolver_nameservers = ['8.8.8.8']

    def mx_record(self):
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.resolver_timeout
        resolver.lifetime = self.resolver_lifetime
        resolver.nameservers = self.resolver_nameservers
        mx = []
        try:
            MX = resolver.resolve(self.domain, 'MX')
            for answer in MX:
                mx.append(answer.exchange.to_text())
                if answer is not None:
                    return e_mail_ready.append((self.domain, 'Yes'))
                else:
                    return e_mail_ready.append((self.domain, 'No'))


        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            e_mail_ready.append((self.domain, 'No'))

    def spf_record(self):
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.resolver_timeout
        resolver.lifetime = self.resolver_lifetime
        resolver.nameservers = self.resolver_nameservers
        try:
            SPF = resolver.resolve(self.domain, 'TXT')
            for answer in SPF:
                answer = str(answer).replace('"', '').rstrip(".")
                answer_1 = answer.startswith("v=spf1")
                if answer_1 and answer_1 is not None and answer != 'v=spf1 -all':
                    return e_mail_ready.append((self.domain, 'Yes'))
                else:
                    return e_mail_ready.append((self.domain, 'No'))

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            e_mail_ready.append((self.domain, 'No'))

    def dmarc_record(self):
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.resolver_timeout
        resolver.lifetime = self.resolver_lifetime
        resolver.nameservers = self.resolver_nameservers
        dmarc_domain = "_dmarc." + str(self.domain)
        try:
            DMARC = resolver.resolve(dmarc_domain, 'TXT')
            for answer in DMARC:
                new_string_dmarc = str(answer).replace("; ", " ").replace(";", " ").replace('"', '').rstrip(".")
                if new_string_dmarc and new_string_dmarc is not None:
                    return e_mail_ready.append((self.domain, 'Yes'))
                else:
                    return e_mail_ready.append((self.domain, 'No'))

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            e_mail_ready.append((self.domain, 'No'))

    def subdomains_by_crt(self):
        parameters = {'q': '%.{}'.format(self.domain), 'output': 'json'}
        try:
            response = requests.get("https://crt.sh/?", params=parameters, headers=header_subdomain_services)
            if response.raise_for_status() is None:
                content = response.content.decode('utf-8')
                data = json.loads(content)
                for crt in data:
                    for domains in crt['name_value'].split('\n'):
                        if '@' in domains:
                            continue

                        if domains not in subdomains:
                            domains_trans = domains.lower().replace('*.', '')
                            subdomains.add((self.domain, domains_trans))

        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout,
                requests.exceptions.TooManyRedirects, requests.exceptions.Timeout, requests.exceptions.SSLError):
            pass

        except Exception as e:
            print('Other Error occured: ', e)

        return list(filter(None, subdomains))

    def subdomains_by_hackertarget(self):
        session = requests.Session()
        try:
            response = session.get('https://dnsdumpster.com/', headers=header_subdomain_services)
            cookies = {}
            data = {}
            if response.raise_for_status() is None:
                if 'csrftoken' in response.cookies.keys():
                    cookies['csrftoken'] = response.cookies['csrftoken']
                    data['csrfmiddlewaretoken'] = cookies['csrftoken']
                    data['targetip'] = self.domain
                    data['user'] = 'free'
                    header_subdomain_services["Referer"] = 'https://dnsdumpster.com/'
                    data_response = session.post("https://dnsdumpster.com/", data=data, cookies=cookies,
                                                 headers=header_subdomain_services)
                    soup = BeautifulSoup(data_response.text, 'lxml')
                    subdomains_new = soup.findAll('td', {"class": "col-md-4"})
                    for subdomain in subdomains_new:
                        subdomain_trans = subdomain.get_text().split()[0]
                        if self.domain in subdomain_trans:
                            if subdomain_trans != '':
                                subdomains.add((self.domain, subdomain_trans))

        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout,
                requests.exceptions.TooManyRedirects, requests.exceptions.Timeout, requests.exceptions.SSLError):
            pass

        except Exception as e:
            print('Subdomain Scan Error occured in dnsdumpster: ', e)

        return list(filter(None, subdomains))

    def subdomains_by_subdomaincenter(self):
        session = requests.Session()
        try:
            response = session.get(f"https://api.subdomain.center/?domain={self.domain}", headers=header_subdomain_services)
            if response.raise_for_status() is None:
                soup = BeautifulSoup(response.text, 'lxml')
                subdomain_trans = re.sub(r'[\[\]"]', "", soup.find('p').get_text()).split(",")
                for subdomain in subdomain_trans:
                    if subdomain != '':
                        subdomains.add((self.domain, subdomain))

        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout,
                requests.exceptions.TooManyRedirects, requests.exceptions.Timeout, requests.exceptions.SSLError):
            pass

        except Exception as e:
            print('Subdomain Scan Error occured in subdomaincenter: ', e)

        return list(filter(None, subdomains))

    def parked(self):
        domains = 'http://' + self.domain
        parked_keywords = ['parkingcrew.net', 'sedoparking',
                           'img1.wsimg.com/parking-lander/static/js/main.2de80224.chunk.js',
                           'This domain name is parked for FREE by',
                           'This domain has been registered via IONOS and is not yet connected to a website',
                           'Parked Domain name on Hostinger DNS system']

        try:
            response = requests.get(domains, headers=headers, allow_redirects=True, timeout=(5, 30))
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
                            transformed_response = requests.get(transformed_url, headers=headers, allow_redirects=True,
                                                                timeout=(5, 30))
                            hidden_redirect_soup = BeautifulSoup(transformed_response.text, 'lxml')
                            for k in parked_keywords:
                                if k.lower() in str(hidden_redirect_soup.html).lower():
                                    parked_domains.append((self.domain, 'Yes'))
                                else:
                                    parked_domains.append((self.domain, 'No'))
                        else:
                            transformed_url = hidden_redirect_1.split("=")[-1]
                            transformed_response = requests.get(transformed_url, headers=headers, allow_redirects=True,
                                                                timeout=(5, 30))
                            hidden_redirect_soup = BeautifulSoup(transformed_response.text, 'lxml')
                            for k in parked_keywords:
                                if k.lower() in str(hidden_redirect_soup.html).lower():
                                    parked_domains.append((self.domain, 'Yes'))
                                else:
                                    parked_domains.append((self.domain, 'No'))

                    else:
                        for k in parked_keywords:
                            if k.lower() in str(soup.html).lower():
                                parked_domains.append((self.domain, 'Yes'))
                            else:
                                parked_domains.append((self.domain, 'No'))
                except:
                    for k in parked_keywords:
                        if k.lower() in str(soup.html).lower():
                            parked_domains.append((self.domain, 'Yes'))
                        else:
                            parked_domains.append((self.domain, 'No'))

        except:
            pass

        return list(filter(None, parked_domains))


class TopicMatching:
    def __init__(self, domain):
        self.domain = domain

    @staticmethod
    def translator(transl):
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

                except Exception as e:
                    print(f'Webpage Translation Error: {transl}', e)

    # Check if Topic Keyword is in Page Source
    def filter(self, tag):
        for value in list_topics:
            try:
                if value in tag or value in self.translator(tag):
                    return value

            except Exception as e:
                print(f'Webpage Translation Error: {tag}', e)

    # Return Topic Match if matched - Create and Merge Lists per scrapped HTML Tag
    def matcher(self):
        matches = [self.filter(k) for k in html_tags(self.domain)[1:] if self.filter(k) is not None and k != '']
        if len(matches) > 0:
            return self.domain, list(set(matches))
        else:
            return self.domain, 'No Matches'


def html_tags(domain):
    hey = []
    domains = 'http://' + domain
    request_session = requests.Session()
    try:
        response = request_session.get(domains, headers=headers, allow_redirects=True, timeout=(5, 30))
        if response.raise_for_status() is None:
            status_codes.append((domain, 'Online'))
            hey.append(domain)
            soup = BeautifulSoup(response.text, 'lxml')
            try:
                hidden_redirect_1 = soup.find("meta")["content"]
                hidden_redirect_2 = soup.find("meta")["http-equiv"]
                # Find instant client redirects https://www.w3.org/TR/WCAG20-TECHS/H76.html
                if '0;url=' in hidden_redirect_1.lower().replace(" ", "") and 'refresh' in hidden_redirect_2.lower().strip():
                    redirect_url = hidden_redirect_1.split("=")[-1]
                    if tldextract.extract(redirect_url).registered_domain == '':
                        transformed_url = domains + "/" + hidden_redirect_1.split("=")[-1]
                        transformed_response = requests.get(transformed_url, headers=headers, allow_redirects=True,
                                                            timeout=(5, 30))
                        hidden_redirect_soup = BeautifulSoup(transformed_response.text, 'lxml')
                        title = hidden_redirect_soup.find('title')
                        description = hidden_redirect_soup.find('meta', attrs={'name': 'description'})
                        keywords = hidden_redirect_soup.find('meta', attrs={'name': 'keywords'})
                        if title is not None:
                            hey.append(title.get_text().replace('\n', '').lower().strip())
                        if description is not None:
                            hey.append(description['content'].replace('\n', '').lower().strip())
                        if keywords is not None:
                            hey.append(keywords['content'].replace('\n', '').lower().strip())

                    else:
                        transformed_url = hidden_redirect_1.split("=")[-1]
                        transformed_response = requests.get(transformed_url, headers=headers, allow_redirects=True,
                                                            timeout=(5, 30))
                        hidden_redirect_soup = BeautifulSoup(transformed_response.text, 'lxml')
                        title = hidden_redirect_soup.find('title')
                        description = hidden_redirect_soup.find('meta', attrs={'name': 'description'})
                        keywords = hidden_redirect_soup.find('meta', attrs={'name': 'keywords'})
                        if title is not None:
                            hey.append(title.get_text().replace('\n', '').lower().strip())
                        if description is not None:
                            hey.append(description['content'].replace('\n', '').lower().strip())
                        if keywords is not None:
                            hey.append(keywords['content'].replace('\n', '').lower().strip())

                else:
                    title = soup.find('title')
                    description = soup.find('meta', attrs={'name': 'description'})
                    keywords = soup.find('meta', attrs={'name': 'keywords'})
                    if title is not None:
                        hey.append(title.get_text().replace('\n', '').lower().strip())
                    if description is not None:
                        hey.append(description['content'].replace('\n', '').lower().strip())
                    if keywords is not None:
                        hey.append(keywords['content'].replace('\n', '').lower().strip())

            except:
                title = soup.find('title')
                description = soup.find('meta', attrs={'name': 'description'})
                keywords = soup.find('meta', attrs={'name': 'keywords'})
                if title is not None:
                    hey.append(title.get_text().replace('\n', '').lower().strip())
                if description is not None:
                    hey.append(description['content'].replace('\n', '').lower().strip())
                if keywords is not None:
                    hey.append(keywords['content'].replace('\n', '').lower().strip())

    except (TypeError, AttributeError, KeyError) as e:
        status_codes.append((domain, 'WebpageError'))
        print('Parsing Webpage Error. Something went wrong at scraping: ', e)

    except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout, requests.exceptions.Timeout):
        status_codes.append((domain, 'TimeoutError'))

    except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.TooManyRedirects, requests.exceptions.SSLError):
        status_codes.append((domain, 'HTTPError'))

    except Exception as e:
        status_codes.append((domain, 'Unknown'))
        print('Unknown Error occured: ', e)

    return list(filter(None, hey))


class FeaturesCSV:
    @staticmethod
    def topics(klaus):
        for y in topics_matches_domains:
            if y[0] == klaus:
                return y[1]

    @staticmethod
    def website_status(klaus):
        for y in status_codes:
            if y[0] == klaus:
                return y[1]

    @staticmethod
    def subdomains(klaus):
        subdomains_filtered = group_tuples_first_value(subdomains)
        for y in subdomains_filtered:
            if y[0] == klaus:
                return y[1:]

    @staticmethod
    def mail(klaus):
        mails_filtered = group_tuples_first_value(e_mail_ready)
        for y in mails_filtered:
            if y[0] == klaus:
                if any(k == 'Yes' for k in y):
                    return 'Yes'
                else:
                    return 'No'

    @staticmethod
    def parked(klaus):
        parked_filtered = group_tuples_first_value(parked_domains)
        for y in parked_filtered:
            if y[0] == klaus:
                if any(k == 'Yes' for k in y):
                    return 'Yes'
                else:
                    return 'No'


class CSVFile:
    def __init__(self):
        self.domains = 'Domains'
        self.keywords = 'Keyword Found'
        self.date = 'Monitoring Date'
        self.detected = 'Detected by'
        self.sourcecode = 'Source Code Match'
        self.status = 'Website Status'
        self.subdomains = 'Subdomains'
        self.email = 'Email Availability'
        self.parked = 'Parked Domains'
        self.fuzzy_domains = [y[0] for y in fuzzy_results if isinstance(y, tuple)]

    def create_basic_monitoring_file(self):
        console_file_path = f'{desktop}/Newly_Registered_Domains_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv'
        if not os.path.exists(console_file_path):
            print('Create Monitoring with Newly Registered Domains')
            header = [self.domains, self.keywords, self.date, self.detected, self.sourcecode, self.status, self.parked, self.subdomains, self.email]
            with open(console_file_path, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(header)

    def create_advanced_monitoring_file(self):
        console_file_path = f'{desktop}/Advanced_Monitoring_Results_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv'
        if not os.path.exists(console_file_path):
            print('Create Monitoring with Newly Registered Topic Domains')
            header = [self.domains, self.sourcecode, self.date]
            with open(console_file_path, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(header)

    @staticmethod
    def write_basic_monitoring_results():
        with open(
                f'{desktop}/Newly_Registered_Domains_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv',
                mode='a', newline='') as f:
            writer = csv.writer(f, delimiter=',')
            for k in fuzzy_results:
                if isinstance(k, tuple):
                    writer.writerow([k[0], k[1], k[2], k[3]])

    @staticmethod
    def write_advanced_monitoring_results(listo):
        with open(
                f'{desktop}/Advanced_Monitoring_Results_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv',
                mode='a', newline='') as f:
            writer = csv.writer(f, delimiter=',')
            for k in listo:
                writer.writerow([k[0], k[1], k[2]])

    def postprocessing_basic_monitoring(self):
        try:
            df = pd.read_csv(f'{desktop}/Newly_Registered_Domains_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', delimiter=',')
            df[self.sourcecode] = df.apply(lambda x: FeaturesCSV().topics(x['Domains']) if x['Domains'] in self.fuzzy_domains else x[self.sourcecode], axis=1)
            df[self.status] = df.apply(lambda x: FeaturesCSV().website_status(x['Domains']) if x['Domains'] in self.fuzzy_domains else x[self.status], axis=1)
            df[self.parked] = df.apply(lambda x: FeaturesCSV().parked(x['Domains']) if x['Domains'] in self.fuzzy_domains else x[self.parked], axis=1)
            df[self.subdomains] = df.apply(lambda x: FeaturesCSV().subdomains(x['Domains']) if x['Domains'] in self.fuzzy_domains else x[self.subdomains], axis=1)
            df[self.email] = df.apply(lambda x: FeaturesCSV().mail(x['Domains']) if x['Domains'] in self.fuzzy_domains else x[self.email], axis=1)
            df.to_csv(f'{desktop}/Newly_Registered_Domains_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', index=False)
        except pd.errors.ParserError:
            print('Newly_Registered_Domains_Calender_Week CSV File seems to be incorrectly formatted. Please rename the file')

    @staticmethod
    def postprocessing_advanced_monitoring():
        try:
            df = pd.read_csv(
                f'{desktop}/Advanced_Monitoring_Results_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv',
                delimiter=',')
            df.drop_duplicates(inplace=True, subset=['Domains'])
            df.to_csv(
                f'{desktop}/Advanced_Monitoring_Results_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv',
                index=False)
        except pd.errors.ParserError:
            print('Advanced_Monitoring_Results_Calender_Week CSV File seems to be incorrectly formatted. Please rename the file')


class InputFiles:
    def __init__(self, file):
        self.file = file
        self.keywords = 'keywords'
        self.unique = 'unique_brand_names'
        self.black = 'blacklist_keywords'
        self.lcs = 'blacklist_lcs'
        self.topic = 'topic_keywords'

    def download_domains(self):
        if os.path.isfile(f'{desktop}/{self.file}.txt'):
            os.remove(f'{desktop}/{self.file}.txt')

        previous_date_formated = previous_date + '.zip'
        this_new = base64.b64encode(previous_date_formated.encode('ascii'))
        domain_file = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(this_new.decode('ascii'))

        try:
            request = requests.get(domain_file)
            zipfiles = zipfile.ZipFile(BytesIO(request.content))
            zipfiles.extractall(desktop)

        except Exception:
            print(f'Something went wrong with downloading domain .zip file. Please check download link {domain_file}\n')
            print('Please also check https://www.whoisds.com/newly-registered-domains for daily Input')
            sys.exit()

    def read_domains(self):
        if os.path.isfile(f'{desktop}/{previous_date}.txt'):
            os.rename(f'{desktop}/{previous_date}.txt', f'{desktop}/{self.file}.txt')

        try:
            file_domains = open(f'{desktop}/{self.file}.txt', 'r', encoding='utf-8-sig')
            for my_domains in file_domains:
                domain = my_domains.replace("\n", "").lower().strip()
                list_file_domains.append(domain)
            file_domains.close()

        except Exception as e:
            print('Something went wrong with reading domain-names.txt Input File. Please check file name', e)
            sys.exit()

    def read_user_input(self):
        file_keywords = open(f'{desktop}/User Input/{self.file}.txt', 'r', encoding='utf-8-sig')
        for my_domains in file_keywords:
            domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
            if domain is not None and domain != '':
                if self.file == self.keywords:
                    brandnames.append(domain)
                elif self.file == self.unique:
                    uniquebrands.append(domain)
                elif self.file == self.black:
                    blacklist_keywords.append(domain)
                elif self.file == self.lcs:
                    list_file_blacklist_lcs.append(domain)
                elif self.file == self.topic:
                    list_topics.append(domain)
        file_keywords.close()


# X as sublist Input by cpu number separated sublists to make big input list more processable
# container1, container2 as container for getting domain monitoring results
def fuzzy_operations(x, container1, container2, blacklist):
    index = x[0]  # index of sub list
    value = x[1]  # content of sub list
    results_temp = []
    print(FR + f'Processor Job {index} for domain monitoring is starting\n' + S)

    for domain in value:
        if domain[1] in domain[0] and all(black_keyword not in domain[0] for black_keyword in blacklist):
            results_temp.append((domain[0], domain[1], today, 'Full Word Match'))

        elif StringMatching(domain[1], domain[0]).jaccard(n_gram=2) is not None:
            results_temp.append((domain[0], domain[1], today, 'Similarity Jaccard'))

        elif StringMatching(domain[1], domain[0]).damerau() is not None:
            results_temp.append((domain[0], domain[1], today, 'Similarity Damerau-Levenshtein'))

        elif StringMatching(domain[1], domain[0]).jaro_winkler() is not None:
            results_temp.append((domain[0], domain[1], today, 'Similarity Jaro-Winkler'))

        # elif StringMatching(domain[1], domain[0]).lcs(keywordthreshold=0.5) is not None:
        #     results_temp.append((domain[0], domain[1], today, 'Similarity Longest Common Substring'))

        elif unconfuse(domain[0]) is not domain[0]:
            latin_domain = unicodedata.normalize('NFKD', unconfuse(domain[0])).encode('latin-1', 'ignore').decode(
                'latin-1')
            if domain[1] in latin_domain and all(black_keyword not in latin_domain for black_keyword in blacklist):
                results_temp.append((domain[0], domain[1], today, 'IDN Full Word Match'))

            elif StringMatching(domain[1], latin_domain).damerau() is not None:
                results_temp.append((domain[0], domain[1], today, 'IDN Similarity Damerau-Levenshtein'))

            elif StringMatching(domain[1], latin_domain).jaccard(n_gram=2) is not None:
                results_temp.append((domain[0], domain[1], today, 'IDN Similarity Jaccard'))

            elif StringMatching(domain[1], latin_domain).jaro_winkler() is not None:
                results_temp.append((domain[0], domain[1], today, 'IDN Similarity Jaro-Winkler'))

    container1.put(results_temp)
    container2.put(index)
    print(FG + f'Processor Job {index} for domain monitoring is finishing\n' + S)


class FeatureThreading:
    def __init__(self):
        self.number_workers = os.cpu_count() + 4

    def subdomains_crtsh(self):
        with ThreadPoolExecutor(self.number_workers) as executor:
            future_to_subdomains = [executor.submit(FeatureProcessing(y[0]).subdomains_by_crt) for y in fuzzy_results if
                                    isinstance(y, tuple)]
            for future in as_completed(future_to_subdomains):
                try:
                    results = future.result()
                    return results

                except Exception as e:
                    print(e)

    def subdomains_hackertarget(self):
        with ThreadPoolExecutor(self.number_workers) as executor:
            future_to_subdomains = [executor.submit(FeatureProcessing(y[0]).subdomains_by_hackertarget) for y in fuzzy_results if
                                    isinstance(y, tuple)]
            for future in as_completed(future_to_subdomains):
                try:
                    results = future.result()
                    return results

                except Exception as e:
                    print(e)

    def subdomains_subdomaincenter(self):
        with ThreadPoolExecutor(self.number_workers) as executor:
            future_to_subdomains = [executor.submit(FeatureProcessing(y[0]).subdomains_by_subdomaincenter) for y in fuzzy_results if
                                    isinstance(y, tuple)]
            for future in as_completed(future_to_subdomains):
                try:
                    results = future.result()
                    return results

                except Exception as e:
                    print(e)

    def parked_domains(self):
        with ThreadPoolExecutor(self.number_workers) as executor:
            future_to_parked = [executor.submit(FeatureProcessing(y[0]).parked) for y in fuzzy_results if isinstance(y, tuple)]
            for future in as_completed(future_to_parked):
                try:
                    parked = future.result()
                    return parked

                except Exception as e:
                    print(e)

    def mx_record(self):
        with ThreadPoolExecutor(self.number_workers) as executor:
            future_to_mx = [executor.submit(FeatureProcessing(y[0]).mx_record) for y in fuzzy_results if
                            isinstance(y, tuple)]
            for future in as_completed(future_to_mx):
                try:
                    mx = future.result()
                    return mx

                except Exception as e:
                    print(e)

    def spf_record(self):
        with ThreadPoolExecutor(self.number_workers) as executor:
            future_to_spf = [executor.submit(FeatureProcessing(y[0]).spf_record) for y in fuzzy_results if
                             isinstance(y, tuple)]
            for future in as_completed(future_to_spf):
                try:
                    spf = future.result()
                    return spf

                except Exception as e:
                    print(e)

    def dmarc_record(self):
        with ThreadPoolExecutor(self.number_workers) as executor:
            future_to_dmarc = [executor.submit(FeatureProcessing(y[0]).dmarc_record) for y in fuzzy_results if
                               isinstance(y, tuple)]
            for future in as_completed(future_to_dmarc):
                try:
                    dmarc = future.result()
                    return dmarc

                except Exception as e:
                    print(e)


def sourcecode_matcher_advanced_monitoring(n):
    if len(uniquebrands) > 0:
        thread_ex_list = [y for x in list_topics for y in list_file_domains if x in y]
        print(len(thread_ex_list),
              'Newly registered domains detected with topic keywords from file topic_keywords.txt in domain name')
        print('Example Domains: ', thread_ex_list[1:5], '\n')

        dummy_u = []

        with ThreadPoolExecutor(n) as executor:
            results = executor.map(html_tags, thread_ex_list)
            for result in results:
                dummy_u.append(result)

        dummy_u2 = list(filter(None, dummy_u))

        topic_in_domainnames_results = [(x[0], y, today) for y in uniquebrands for x in dummy_u2 for z in x[1:] if
                                        len(x) > 1 and y in z and all(
                                            black_keyword not in z for black_keyword in blacklist_keywords)]

        if len(topic_in_domainnames_results) > 0:
            print('\nMatches detected: ', topic_in_domainnames_results)
            CSVFile().postprocessing_advanced_monitoring()
            CSVFile().write_advanced_monitoring_results(topic_in_domainnames_results)
            print('Please check:',
                  FY + f'{desktop}/Newly_Registered_Topic_Domains_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv' + S,
                  'file for results\n')

        else:
            print('\nNo Matches detected: ', topic_in_domainnames_results)
    else:
        print('No brand names provided in unique_brand_names.txt')


def sourcecode_matcher_basic_monitoring(n):
    with ThreadPoolExecutor(n) as executor:
        future_to_source = [executor.submit(TopicMatching(y[0]).matcher) for y in fuzzy_results if isinstance(y, tuple)]
        for future in as_completed(future_to_source):
            try:
                result = future.result()
                if result is not None and len(result) > 1:
                    topics_matches_domains.append(result)

            except Exception as e:
                print(e)

    return topics_matches_domains


if __name__ == '__main__':
    InputFiles('domain-names').download_domains()
    InputFiles('domain-names').read_domains()
    InputFiles("keywords").read_user_input()
    InputFiles('unique_brand_names').read_user_input()
    InputFiles('blacklist_keywords').read_user_input()
    InputFiles('topic_keywords').read_user_input()
    CSVFile().create_basic_monitoring_file()
    CSVFile().create_advanced_monitoring_file()

if __name__ == '__main__':
    print(FR + '\nStart Basic Domain Monitoring and Feature Scans' + S)
    print('Quantity of Newly Registered or Updated Domains from', daterange.strftime('%d-%m-%y') + ':',
          len(list_file_domains), 'Domains\n')

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

    processes = [multiprocessing.Process(target=fuzzy_operations, args=(sub, que_1, que_2, blacklist_keywords)) for sub
                 in sub_list]

    for p in processes:
        p.daemon = True
        p.start()

    fuzzy_results_temp = [[que_1.get(), que_2.get()] for p in processes]

    for p in processes:
        p.join()
        p.close()

    flatten(fuzzy_results_temp)
    CSVFile().write_basic_monitoring_results()
    print(FR + '\nStart E-Mail Availability Scans' + S)
    FeatureThreading().mx_record()
    FeatureThreading().spf_record()
    FeatureThreading().dmarc_record()
    print(FG + 'End E-Mail Availability Scans\n' + S)
    print(FR + '\nStart Subdomain & Status Scans' + S)
    FeatureThreading().subdomains_crtsh()
    FeatureThreading().subdomains_subdomaincenter()
    FeatureThreading().subdomains_hackertarget()
    FeatureThreading().parked_domains()
    print(FG + 'End Basic Domain Monitoring and Feature Scans\n' + S)
    ex_list = [y[0] for y in fuzzy_results if isinstance(y, tuple)]
    print(*ex_list, sep="\n")
    print(FY + f'{len(ex_list)} Newly registered domains detected\n' + S)

if __name__ == '__main__':
    print(FR + 'Start Search task for topic keywords in source codes of domain monitoring results\n' + S)
    sourcecode_matcher_basic_monitoring(50)
    CSVFile().postprocessing_basic_monitoring()
    print(FG + '\nEnd Search task for topic keywords in source codes of domain monitoring results\n' + S)
    print('Please check:',
          FY + f'{desktop}/Newly_Registered_Domains_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv' + S,
          ' file for results\n')

if __name__ == '__main__':
    print(FR + f'Start Advanced Domain Monitoring for brand keywords {uniquebrands} in topic domain names\n' + S)
    sourcecode_matcher_advanced_monitoring(50)
    print(FG + f'\nEnd Advanced Domain Monitoring for brand keywords {uniquebrands} in topic domain names' + S)

