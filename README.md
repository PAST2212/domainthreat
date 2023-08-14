# domainthreat
**Daily Domain Monitoring for Brands and Mailing Domain Names**

**Current Version: 2.1**

**New in Version 2.0**
- Find brand impersonation websites which neither contain your brand in domain name nor are similar registered
- Export Results to separate file "Newly-Registered-Topic_Domains_Calender-Week"
- Add Multithreading and Muliprocessing

This is my first Project on Github.

Here you can find a Domain Monitoring tool. You can monitor your company brands (e.g. "amazon"), your mailing domains (e.g. "companygroup) or other words.

Typical Domain Monitoring relies on brand names as input. Sometimes this is not sufficient enough to detect phishing attacks in cases where the brand names and mailing domain names are not equal.

Thought experiment:
If example company "IBM" monitors their brand "IBM", send mails via @ibmgroup.com and attacker registers the domain ibrngroup.com (m = rn) for spear phishing purposes (e.g. CEO Fraud). 
Typical Brand (Protection) Domain Monitoring Solutions may experience difficulties because the distance between monitored brand name "IBM" and registered domain name "ibrngroup.com" is too big to classify it as a true positive and therefore makes it harder for the targeted company to take appropriate measures more proactively. This scenario is avoidable by also monitoring your mailing domain names and thus focussing more on text strings rather than brands.

This was the motivation for this project.

**You can recognize:**
- combo squatting (e.g. amazon-shop.com), 
- typo squatting (ammazon.com), 
- brand impersonations,
- phishing attacks (e.g. CEO-Fraud),
- IDN Detection / look-alike Domains based on full word matching (e.g. 𝗉ay𝞀al.com - greek letter RHO '𝞀' instead of latin letter 'p'),
- IDN Detection / look-alike Domains based on partial word matching (e.g. 𝗉ya𝞀a1.com - greek letter RHO '𝞀' instead of latin letter 'p' AND "ya" instead of "ay" AND Number "1" instead of Letter "l")

Im using this public source as daily data feed:
https://www.whoisds.com/newly-registered-domains

Some TLDs are not included in this public source (e.g. .de TLD). You can bypass it by using my other project https://github.com/PAST2212/certthreat that uses CERT Transparency Logs as Input instead. But feel free to change the source (e.g a paid source)

**Example Screenshot:**
![image](https://user-images.githubusercontent.com/124390875/219737268-0767db9d-0b9d-4a7e-9fba-83b1bf8e3636.png)

**Features:**
- Multithreading (50 workers by defaul) & Multiprocessing
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- brand name searches on websites which do not contain the brand itself in domain name
- IDN / Homoglyph Detection
- CSV Export
- Find domains that are identical or confusingly similar to your name/brand/mailing domain name/etc.
- Mix of Edit-based and Token-based textdistance algorithms to increase result quality by considering degree of freedom in choosing variations of domain names from attacker side
- Keyword Searches in Page Source Codes (HTML Title Tag and HTML Description Tag and HTML Keywords Tag), even if they are in other languages (using Google Translator API - english per default - beware of API rate limit). This is to cover needs of international companies and foreign-speaking markets / websites.
- MX- and A-Record lookups are included but not activated by default (Will update the functions in future).
- Sequence-based Fuzzy Matching Algorithm Longest Common Substring is included but not activated by default.
- Possibility to change pre-defined thresholds of fuzzy-matching algorithms if you want to<br>


**Principles**
1. Basic Domainmonitoring<br>
1.1. Keywords from file keywords.txt (e.g. tuigroup) are used to make full-word detection (e.g. newtuigroup.shop) and similar-word detection (e.g. tuiqroup.com (g=q)) on newly registered domain names.<br>
1.2. Keywords from file topic_keywords.txt are used to find these keywords (e.g. holiday) in content of (translated) webpages (e.g. new**tuigroup**.shop) of domain monitoring results from point 1.1.<br>
   ==> Results are exported to Newly-Registered-Domains .csv File<br>

2. Advanced Domainmonitoring<br>
2.1. Keywords from file topic_keywords.txt (e.g. holiday) are used to make full-word detection (e.g. usa-holiday.net) on newly registered domain names.<br>
2.2. Keywords from file unique_brand_names.txt are used to find these keywords (e.g. tui) in content of webpages of monitoring results from point 2.1.<br>
   ==> Results are exported to Newly-Registered-Topic_Domains .csv File<br>


**How to install:**
- git clone https://github.com/PAST2212/domainthreat.git
- cd domainthreat
- pip install -r requirements.txt

**How to run:**
- python3 domainthreat.py

**How to update**: Type command in domainthreat directory
- git pull
- In case of a Merge Error: Try "git reset --hard" before "git pull"

**Changelog**
- Please see Changelog for Updates:
- https://github.com/PAST2212/domainthreat/blob/main/Changelog

**Before the first run - How it Works:**
1. Put your brand names or mailing domain names into this TXT file "User Input/keywords.txt" line per line for monitoring operations (without the TLD). Some "TUI" Names are listed per default.

2. Put common word collisions into this TXT file "User Input/blacklist_keywords.txt" line per line you want to exclude from the results to reduce false positives.
-  e.g. blacklist "lotto" if you monitor keyword "otto", e.g. blacklist "amazonas" if you want to monitor "amazon", e.g. blacklist "intuitive" if you want to monitor "tui" ...

3. Put commonly used words into this TXT file "User Input/topic_keywords.txt" line per line that are describing your brands, industry, brand names, products on websites. These keywords will be used for searching / matching in page source codes. Default language is english for performing automated translation operations from HTML Title and Description Tag via Google Translator API.
-  e.g. Keyword "fashion" for a fashion company, e.g. "sneaker" for shoe company, e.g. "Zero Sugar" for Coca Cola Inc., e.g. "travel" for travel company...

4. Put your brand names into this TXT file "User Input/unique_brand_names.txt" line per line for monitoring operations on domains which neither contain your brand names in domain name nor are similar registered, but in page source code of website (used/listed on website). Some "TUI" Names are listed per default.

A perfect supplement to this wonderful project: https://github.com/elceef/dnstwist

**Authors**
- Patrick Steinhoff (https://www.linkedin.com/in/patrick-steinhoff-168892222/)

Written in Python 3.7

TO DO:
- Add additional fuzzy matching algorithms to increase true positive rate / accurancy.
- Add Possibility to make Subdomain Scans
- Add Possibility to enumerate user mail names
- Add Possibility to parse Arguments (e.g. workers for multithreading)

Note:
- Public Source whoisds has capped quantity of daily registrations to 100.000. You are also able to use cheap paid sources for daily work for around 9$/month as I do or other public sources
- **Thresholds are intentional tolerant by default (possible high false positive rate) in order to consider degree of freedom in choosing variations of domain names from attacker side more accurate** .Change them if you want to match your particular needs
- Exception Notification "Server Connection Error" while parsing page source codes is not unusual for newly registered domains.
- Recommend python version >= 3.7 
