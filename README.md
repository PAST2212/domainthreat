# domainthreat
**Daily Domain Monitoring for Brands and Mailing Domain Names**

**Current Version: 2.2**
- New in this version: Subdomain Scans for newly registered Domains

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


**Example Screenshot: Illustration of detected topic keyword in source code of newly registered domains**
![image](https://user-images.githubusercontent.com/124390875/219737268-0767db9d-0b9d-4a7e-9fba-83b1bf8e3636.png)

<br>
<br>

**Example Screenshot: Illustration of detected subdomains of newly registered domains as of version >= 2.2**
![image](https://github.com/PAST2212/domainthreat/assets/124390875/3f3bec62-3229-42c5-a150-a1c3a0b712f4)


# **Features**
**Key & CSV Output Features**
- Check if domain is parked or not (experimental state)
- Subdomain enumeration via crt.sh, dnsdumpster and subdomain.center
- Check website status by http status codes
- Check if domain is ready for receiving mails (by mx record) or ready for sending mails (by SPF record and dmarc record)
- Keyword detection in (english translated) source codes of newly registered domains via HTML Title, Description and HTML Keywords Tag - even if they are in other languages by using different translators (normalized to english per default)
  ==> This is to cover needs of international companies and foreign-speaking markets
- IDN / Homoglyph Detection
- Daily CSV export into a calender week based CSV file (can be filtered by dates)<br>

**Other Features**
- Multithreading (50 workers by default) & Multiprocessing
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- Keyword detection in source code of newly registered domains which neither contain brands in domain names nor are similar registered 
- Mix of Edit-based and Token-based textdistance algorithms to increase result quality by considering degree of freedom in choosing variations of domain names from attacker side
- Sequence-based algorithm "Longest Common Substring" is already included but not activated by default
- Possibility to change pre-defined thresholds of fuzzy-matching algorithms if you want to<br>

# **Principles**
**1. Basic Domainmonitoring**<br>

1.1. Keywords from file keywords.txt (e.g. tuigroup) are used to make full-word detection (e.g. newtuigroup.shop) and similar-word detection (e.g. tuiqroup.com (g=q)) on newly registered domain names.<br>
1.2. Keywords from file topic_keywords.txt are used to find these keywords (e.g. travel) in source code of (translated) webpages (e.g. dulichtui.com) of domain monitoring results from point 1.1.<br>

   ==> Results are exported to Newly-Registered-Domains .csv File<br>

**2. Advanced Domainmonitoring**<br>

2.1. Keywords from file topic_keywords.txt (e.g. holiday) are used to make full-word detection (e.g. usa-holiday.net) on newly registered domain names.<br>
2.2. Keywords from file unique_brand_names.txt are used to find these keywords (e.g. tui) in content of webpages of monitoring results from point 2.1.<br>

   ==> Results are exported to Newly-Registered-Topic_Domains .csv File<br>

# **Instructions**

**How to install:**
- git clone https://github.com/PAST2212/domainthreat.git
- cd domainthreat
- pip install -r requirements.txt

**How to run:**
- python3 domainthreat.py

**How to update:**
- cd domainthreat
- git pull
- In case of a Merge Error: Try "git reset --hard" before "git pull"

**Before the first run - How it Works:**
1. Put your brand names or mailing domain names into this TXT file "User Input/keywords.txt" line per line for monitoring operations (without the TLD). Some "TUI" Names are listed per default.

2. Put common word collisions into this TXT file "User Input/blacklist_keywords.txt" line per line you want to exclude from the results to reduce false positives.
-  e.g. blacklist "lotto" if you monitor keyword "otto", e.g. blacklist "amazonas" if you want to monitor "amazon", e.g. blacklist "intuitive" if you want to monitor "tui" ...

3. Put commonly used words into this TXT file "User Input/topic_keywords.txt" line per line that are describing your brands, industry, brand names, products on websites. These keywords will be used for searching / matching in source codes of webistes. Default language is english for performing automated translation operations from HTML Title, Description and Keywords Tag via different translators.
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

**Authors**
- Patrick Steinhoff (https://www.linkedin.com/in/patrick-steinhoff-168892222/)

**TO DO**
- Add additional fuzzy matching algorithms to increase true positive rate / accurancy.
- Enhance source code keyword detection on subdomains
- Add Possibility to parse Arguments (e.g. workers for multithreading)
- Evaluate other public newly registered domain sources beside whoisds
- Logo Recognition / Similarity Matching

**Additional**
- Used public source whoisds (https://www.whoisds.com/newly-registered-domains) has capped quantity of daily registrations to 100.000. You are also able to use cheap paid sources for daily work for around 9$/month as I do or other public sources
- Thresholds are intentional tolerant by default (possible high false positive rate) in order to consider degree of freedom in choosing variations of domain names from attacker side more accurate. Change them if you want to match your particular (company) needs
- A perfect supplement to this wonderful project: https://github.com/elceef/dnstwist
- Written in Python 3.10
- Recommended Python Version >= 3.6
- Some TLDs are not included in this public source (e.g. ".de" TLD). You can bypass it by using my other project https://github.com/PAST2212/certthreat that uses CERT Transparency Logs as Input instead.
