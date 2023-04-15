# domainthreat
**Daily Domain Monitoring for Brands and Mailing Domain Names**

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
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- IDN / Homoglyph Detection
- CSV Export ("home\User\domainthreat" path is default path to create output)
- Find domains that are identical or confusingly similar to your name/brand/mailing domain name/etc.
- Mix of Sequence-based, Edit-based and Token-based textdistance algorithms to increase result quality by considering degree of freedom in choosing variations of domain names from attacker side
- Keyword Searches in Page Source Codes (HTML Title Tag and HTML Description Tag), even if they are in other languages (using Google Translator API - english per default - beware of API rate limit). This is to cover needs of international companies and foreign-speaking markets / websites.
- Domain Registrar, Domain Creation Date, MX- and A-Record lookups are included but not activated by default.
- Possibility to change pre-defined thresholds of fuzzy-matching algorithms if you want to

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
-  e.g. blacklist "lotto" if you monitor keyword "otto", e.g. blacklist "amazonas" if you want to monitor "amazon", ...

3. Put generic words from your strings into this TXT file "User Input/blacklist_lcs.txt" line per line you have in your keywords list to exlcude from the longest common substring (LCS) textdistance operations in order to reduce false positives. LCS only performs for keywords longer than 8 characters per default.
-  e.g. blacklist "group" if you monitor keyword "companygroup", e.g. blacklist "france" if you monitor keyword "companyfrance", ...

4. Put commonly used words into this TXT file "User Input/topic_keywords.txt" line per line that are describing your brands, industry, brand names, products on websites. These keywords will be used for searching / matching in page source codes. Default language is english for performing automated translation operations from HTML Title and Description Tag via Google Translator API.
-  e.g. Keyword "fashion" for a fashion company, e.g. "sneaker" for shoe company, e.g. "Zero Sugar" for Coca Cola Inc., ...

A perfect supplement to this wonderful project: https://github.com/elceef/dnstwist

**Authors**
- Patrick Steinhoff (https://www.linkedin.com/in/patrick-steinhoff-168892222/)


Written in Python 3.7

TO DO:
- Add additional fuzzy matching algorithms to increase true positive rate / accurancy.
- Add Possibility to make Subdomain Scans
- Add New Source - whoisds has capped quantity of daily registrations to 100.000
- Add Possibility to enumerate user mail names
