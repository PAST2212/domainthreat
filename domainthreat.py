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

# Daterange of Newly Registered Domains Input from Source whoisds.com.
# Paramater "days=1" means newest feed from today up to maximum oldest feed of newly registered domains "days=4" with free access
daterange = datetime.datetime.today() - datetime.timedelta(days=1)

whoisit.bootstrap(overrides=True)

# Strings or brand names to monitor
# e.g. brands or mailing domain names that your company is using for sending mails
brandnames = ["tui", "tuitravel", "tuiairways", "tuifly", "tuiairlines", "ltur", "tuigroup", "tuicruises", "robinson", "tuifrance"]

# Important if there are common word collisions between brand names and other words to reduce false positives
# e.g. blacklist "lotto" if you monitor brand "otto"
Blacklist = ["cultur", "kultur", "intuit", "tuition"]

# Important if generic words are in brand names list to reduce false positives
# e.g. blacklist "group" if you monitor mailing domain string for your company "companygroup"
blacklist_LCS = ['travel', 'airways', 'airlines', 'cruises', 'france', 'group']

# Generic Header for making Page Source Requests
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', 'Pragma': 'no-cache', 'Cache-Control': 'no-cache'}

# Topic Keywords to look for in page source
# e.g. product brands or words that are describing your industry or products
# e.g. Keyword "fashion" for a fashion company
Topics = {'Exceptions': ['Page Source Code is not processable'],
          'Industry': ['holiday', 'vacation', 'travel', 'journey', 'hotel', 'book', 'cruise', 'resort', 'club']
          }

# Desktop as Standard Path for CSV file Output
desktop = os.path.join(os.path.join(os.environ['HOME']), 'Desktop')

# Print Out Date of Domains in CSV file
today = datetime.date.today()

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
        if (len(longestcommonsubstring) / len(keyword)) > keywordthreshold and len(longestcommonsubstring) is not len(keyword) and all(black_keyword_lcs not in keyword for black_keyword_lcs in blacklist_LCS) is True:
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

    except (whoisit.errors.UnsupportedError, KeyError, AttributeError, whoisit.errors.QueryError, UnicodeError, UnicodeEncodeError, UnicodeDecodeError):
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

# Normalize String and translate HTML Title and HTML Description via Google API
def normalize_caseless_tag(transl):
    translator = Translator()
    try:
        result = translator.translate(transl, dest='en').text
        return unicodedata.normalize("NFKD", result.casefold())
    except:
        return 'Page Source Code is not processable'

# Check if Topic Keyword is in Page Source
def topics_filter(tag):
    dummy_list = []
    for val in Topics.values():
        for i in val:
            if i in normalize_caseless_tag(tag):
                dummy_list.append(i)
    return dummy_list

# Return Topic Match if matched - Create and Merge Lists per scrapped HTML Tag
def Topic_Match():
    title_list = [tit for tit in topics_filter(html_title(domain)) if tit is not None]
    desc_list = [desc for desc in topics_filter(html_description(domain)) if desc is not None]
    return list(set(title_list+desc_list))

# Get HTML Title as String
def html_title(domain):
    domain = str('http://') + domain
    try:
        response = requests.get(domain, headers=headers)
        soup = BeautifulSoup(response.content, 'html.parser')
        if soup.title is not None:
            titel = soup.title.string
            titel = titel.text.replace('\n', '').lstrip()
            return titel
        else:
            return 'No Website Title Found'
    except requests.ConnectionError:
        return 'No Website Found'
        pass
    except (TypeError, AttributeError):
        return 'No Website Title Found'
    except (UnicodeError, UnicodeEncodeError, UnicodeDecodeError):
        pass
    except requests.exceptions.TooManyRedirects:
        return 'No Website Title Found'
        pass

# Get HTML Description Tag
def html_description(domain):
    domain = str('http://') + domain
    try:
        response = requests.get(domain, headers=headers)
        soup = BeautifulSoup(response.content, 'html.parser')
        meta_tag = soup.find('meta', attrs={'name': 'description'})
        meta_tag = meta_tag['content']
        if meta_tag is not None:
            meta_tag = meta_tag.replace('\n', '').lstrip()
            return meta_tag
        else:
            return 'No Website Description Found'
    except requests.ConnectionError:
        return 'No Website Found'
        pass
    except (TypeError, AttributeError):
        return 'No Website Description Found'
    except (UnicodeError, UnicodeEncodeError, UnicodeDecodeError):
        pass
    except requests.exceptions.TooManyRedirects:
        return 'No Website Description Found'
        pass

# Make sure to delete older file
if os.path.isfile(desktop+'/domain-names.txt'):
  os.remove(desktop+'/domain-names.txt')

# Get Input of newly registered and updated Domains from open source whoisds
previous_Date = daterange
previous_date_formated = previous_Date.strftime('20%y-%m-%d')+'.zip'
new = base64.b64encode(previous_date_formated.encode('ascii'))
domain_file = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(new.decode('ascii'))

# Request the base encoded formated URL
request = requests.get(domain_file)

# Extracting the zip file contents
zipfile = zipfile.ZipFile(BytesIO(request.content))
zipfile.extractall(desktop)

# Encode domain names 'utf-8-sig'
file1 = open(desktop+'/domain-names.txt', 'r', encoding='utf-8-sig')
lines = file1.readlines()
print('Quantity of Newly Registered or Updated Domains from', daterange.strftime('%d-%m-%y')+':', len(lines), 'Domains')

# Create new file with fixed columns
console_file_path = f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv'
if not os.path.exists(console_file_path):
    print('Create Monitoring with Newly Registered Domains')
    header = ['Domains', 'Keyword Found', 'Date', 'Topic found in Source Code', 'Detected by']
    with open(console_file_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        f.close()

# Write and append results to csv file per calender week
with open(f'{desktop}/Newly-Registered-Domains_Calender-Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv', mode='a', newline='') as f:
    writer = csv.writer(f, delimiter=',')
    for keyword in brandnames:
        for domain in lines:
            domain = domain.strip()
            if keyword in domain and all(black_keyword not in domain for black_keyword in Blacklist) is True:
                writer.writerow([domain, keyword, today, Topic_Match(), "Full Word Match"])

            elif jaccard(keyword, domain) is not None:
                writer.writerow([domain, keyword, today, Topic_Match(), "Jaccard"])

            elif damerau(keyword, domain) is not None:
                writer.writerow([domain, keyword, today, Topic_Match(), "Damerau-Levenshtein"])

            elif jaro_winkler(keyword, domain) is not None:
                writer.writerow([domain, keyword, today, Topic_Match(), "Jaro-Winkler"])

            elif LCS(keyword, domain, 0.5) is not None:
                writer.writerow([domain, keyword, today, Topic_Match(), "LCS"])

            elif unconfuse(domain) is not domain:
                latin_domain = unicodedata.normalize('NFKD', unconfuse(domain)).encode('latin-1', 'ignore').decode('latin-1')
                if keyword in latin_domain:
                    writer.writerow([domain, keyword, today, Topic_Match(), "IDN Full Word Match"])
                    
                elif damerau(keyword, latin_domain) is not None:
                    writer.writerow([domain, keyword, today, Topic_Match(), "IDN Similar Match"])

                elif jaccard(keyword, latin_domain) is not None:
                    writer.writerow([domain, keyword, today, Topic_Match(), "IDN Similar Match"])

                elif jaro_winkler(keyword, latin_domain) is not None:
                    writer.writerow([domain, keyword, today, Topic_Match(), "IDN Similar Match"])
