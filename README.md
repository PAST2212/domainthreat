# domainthreat
**Daily Domain Monitoring for Brands and Mailing Domain Names**

**Current Version 3.12**

Here you can find a Domain Monitoring tool. You can monitor your company brands (e.g. "amazon"), your mailing domains (e.g. "companygroup) or other words.

# **Motivation**
Typical Domain Monitoring relies on brand names as input. Sometimes this is not sufficient enough to detect phishing attacks in cases where the brand names and mailing domain names are not equal.

Thought experiment:
If example company "IBM" monitors their brand "IBM", send mails via @ibmgroup.com and attacker registers the domain ibrngroup.com (m = rn) for spear phishing purposes (e.g. CEO Fraud). 
Typical Brand (Protection) Domain Monitoring Solutions may experience difficulties because the distance between monitored brand name "IBM" and registered domain name "ibrngroup.com" is too big to classify it as a true positive and therefore makes it harder for the targeted company to take appropriate measures more proactively. This scenario is avoidable by also monitoring your mailing domain names and thus focussing more on text strings rather than brands.

This was the motivation for this project.<br>

# **Detection Scope**
- full-word matching (e.g. amazon-shop.com), 
- regular typo squatting cases (e.g. ammazon.com), 
- typical look-alikes / phishing / so called CEO-Fraud domains (e.g. arnazon.com (rn = m),
- IDN Detection / look-alike Domains based on full word matching (e.g. 𝗉ay𝞀al.com - greek letter RHO '𝞀' instead of latin letter 'p'),
- IDN Detection / look-alike Domains based on partial word matching (e.g. 𝗉ya𝞀a1.com - greek letter RHO '𝞀' instead of latin letter 'p' AND "ya" instead of "ay" AND Number "1" instead of Letter "l")


**Example Screenshot: Illustration of detected topic keyword 'tech' in source code of newly registered domain 'microsoftintegration[.]com' and detected subdomains**
![image](https://github.com/PAST2212/domainthreat/assets/124390875/b9d27c1c-a366-49bf-8c69-666681f87041)


# **Features**
**Key Features & CSV Output Columns**
- Unicode domain names (IDN) / Homoglyph / Homograph Detection
- Variety of domain fuzzing / similarity algorithms
- Automated Website Translations
- Support of a variety of different languages <br>

- Detected By: Full Keyword Match or Similar/Fuzzy Keyword Match <br>
- Source Code Match: Keyword detection in websites - even if they are in other languages (e.g. chinese) by using different translators (normalized to english per default)<br>
  ==> This is to cover needs of international companies and foreign-speaking markets
- Check website status by http status codes: HTTPError for a 4XX client error or 5XX server error response code
- Parked: Check if domain is parked or not for 2XX or 3XX Status Code domains (experimental state)
- Subdomains: Subdomain Scan
- E-Mail Availability: Check if domain is ready for receiving mails and/or ready for sending mails
- Daily CSV export into a calender week based CSV file (can be filtered by dates)<br>

**Other Features**
- Multithreading (CPU core based) & Multiprocessing
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- Keyword detection in websites which neither contain brands in domain names nor are similar registered<br>

# **Principles**
**1. Basic Domainmonitoring**<br>

1.1. Keywords from file keywords.txt (e.g. tuigroup) are used to make full-word detection (e.g. newtuigroup.shop) and similar-word detection (e.g. tuiqroup.com (g=q)) on newly registered domain names.<br>

1.2. Keywords from file topic_keywords.txt are used to find these keywords (e.g. travel) in source code of (translated) webpages (e.g. dulichtui.com) of domain monitoring results from point 1.1.<br>

   ==> Results are exported to Newly_Registered_Domains_Calender_Week_ .csv File<br>

**2. Advanced Domainmonitoring**<br>

2.1. Keywords from file topic_keywords.txt (e.g. holiday) are used to make full-word detection (e.g. usa-holiday.net) on newly registered domain names.<br>

2.2. Keywords from file topic_keywords.txt (e.g. holiday) are automatically translated into the languages which are provided by the User in the "User Input/languages_advanced_monitoring.txt" file. Please see supported_languages.txt for supported languages at this moment. Copy / Paste the demanded languages from supported_languages.txt to "User Input/languages_advanced_monitoring.txt" file if you want to (empty per default). Punycode domains are not supported by these translations at the moment. <br>

==> Results from 2.1. will be enhanced by translated keywords from topic-keywords.txt file. For example "urlaub" is the german word for "holiday". The program will now find in addition german registerd     domains like "sea-urlaub.com"<br>

2.3. Keywords from file unique_brand_names.txt are used to find these keywords (e.g. tui) in webpages of monitoring results from point 2.1. (e.g. usa-holiday.net) and from 2.2. (e.g. sea-urlaub.com) (if any supported languages are provided)<br>

   ==> Results are exported to Advanced_Monitoring_Results_Calender_Week_ .csv File<br>

# **Instructions**

**How to install:**
- git clone https://github.com/PAST2212/domainthreat.git
- cd domainthreat
- pip install -r requirements.txt

**How to run:** <br>

--similarity : Selection of similarity mode of homograph, typosquatting detection algorithms with options "close" OR "wide".
- close: Less false positives and (potentially) more false negatives
- wide: More false positives and (potentially) less false negatives
- Default: Tradeoff between both mode options.<br>

--threads : Number of Threads
- Default: Number of Threads is based on CPU cores <br>

Running program in standard mode (CPU cores + default similarity mode):
- "python3 domainthreat.py" <br>

Running program in wide similarity mode with 50 threads:
- "python3 domainthreat.py --similarity wide --threads 50"
![image](https://github.com/PAST2212/domainthreat/assets/124390875/44e60e02-5f49-49b0-8eca-5829e809118e)


**How to update:**
- cd domainthreat
- git pull
- In case of a Merge Error: Try "git reset --hard" before "git pull"

**Before the first run - How it Works:**
1. Put your brand names or mailing domain names into this TXT file "User Input/keywords.txt" line per line for monitoring operations (without the TLD). Some "TUI" Names are listed per default.

2. Put common word collisions into this TXT file "User Input/blacklist_keywords.txt" line per line you want to exclude from the results to reduce false positives.
-  e.g. blacklist "lotto" if you monitor keyword "otto", e.g. blacklist "amazonas" if you want to monitor "amazon", e.g. blacklist "intuitive" if you want to monitor "tui" ...

3. Put commonly used words into this TXT file "User Input/topic_keywords.txt" line per line that are describing your brands, industry, brand names, products on websites. These keywords will be used for searching / matching in source codes of webistes. Default and **normalized** language is english for performing automated translation operations from HTML Title, Description and Keywords Tag via different translators.
-  e.g. Keyword "fashion" for a fashion company, e.g. "sneaker" for shoe company, e.g. "Zero Sugar" for Coca Cola Inc., e.g. "travel" for travel company...

4. Put your brand names into this TXT file "User Input/unique_brand_names.txt" line per line for monitoring operations (e.g. "tui"). These keywords will be used for searching / matching in sources codes on websites which neither contain your brand names in domain name nor are similar registered to them (e.g. usa-holiday.net). Some "TUI" Names are listed per default. 

# **Troubleshooting**
- In case of errors with modules "httpcore" or "httpx" - possible fixes:
   - pip uninstall googletrans (in case you have installed older version of domainthreat as of version <= 2.11)
   - pip install --upgrade pip
   - pip install --upgrade httpx
   - pip install --upgrade httpcore

# **Changelog**
- Please see Changelog for Updates:
- https://github.com/PAST2212/domainthreat/blob/main/Changelog

# **Notes**

**Author**
- Patrick Steinhoff (https://www.linkedin.com/in/patrick-steinhoff-168892222/)

**TO DO**
- Add additional fuzzy matching algorithms to increase true positive rate / accurancy (Sequence-based algorithm "Longest Common Substring" is already included but not activated by default)
- Enhance source code keyword detection on subdomain level
- AI based Logo Detection by Object Detection

**Additional**
- Used public source whoisds (https://www.whoisds.com/newly-registered-domains) has capped quantity of daily registrations to 100.000. There are other sources out there. Use them instead if you feel to it.
- Thresholds for similarity modes (wide, standard, close) have been selected carefully. The "wide" range has a possible high false positive rate (and therefore lower precision rate) in order to consider degree of freedom in registering different variations of domain names more accurately (reduce occurrence of false negatives and therefore better recall rate). Change the thresholds over the different modes if you want to match your needs better. I can strongly recommend this article go get a better understanding of recall-precision tradeoff: https://towardsdatascience.com/precision-vs-recall-evaluating-model-performance-in-credit-card-fraud-detection-bb24958b2723 
- A perfect supplement to this wonderful project: https://github.com/elceef/dnstwist
- Written in Python 3.10
- Recommended Python Version >= 3.7
- Some TLDs are not included in this public source (e.g. ".de" domains). You can bypass it by using my other project https://github.com/PAST2212/certthreat that uses CERT Transparency Logs as Input instead.
