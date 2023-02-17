# domainthreat
**Daily Domain Monitoring for Brands and Mailing Domain Names**

This is my first Project on Github.

Here you can find a Domain Monitoring tool. You can monitor your company brands (e.g. "amazon"), your mailing domains (e.g. "companygroup) or other words.

Typical Domain Monitoring relies on brand names as input. Sometimes this is not sufficient enough to detect phishing attacks in cases where the brand names and mailing domain names are not equal.

Thought experiment:
If example company "IBM" monitors their brand "IBM", send mails via @ibmgroup.com and attacker registers the domain ibrngroup.com (m = rn) for spear phishing purposes (e.g. CEO Fraud). 
Typical Brand (Protection) Domain Monitoring Solutions may experience difficulties because the distance between monitored brand name "IBM" and registered domain name "ibrngroup.com" is too big to classify it as a true positive and therefore makes it harder for the targeted company to take appropriate measures more proactively. This scenario is avoidable by also monitoring your mailing domain names and thus focussing more on text strings rather than brands.

This was the motivation for this project.

**You can recognize**
- combo squatting (e.g. amazon-shop.com), 
- typo squatting (ammazon.com), 
- brand impersonations, 
- phishing attacks (e.g. CEO-Fraud),
- and other forms of phishing websites / look-alike Domains (e.g. 𝗉ay𝞀al.com - greek letter RHO '𝞀' instead of latin letter 'p')

Im using this public source as daily data feed:
https://www.whoisds.com/newly-registered-domains

Some TLDs are not included in this public source (e.g. .de TLD). You can bypass it by using my other project https://github.com/PAST2212/certthreat that uses CERT Transparency Logs as Input instead. But feel free to change the source (e.g a paid source)

**Features:**
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- IDN / Homoglyph Detection
- CSV Export (HOME path is default path to create output)
- Find domains that are identical or confusingly similar to your name/brand/mailing domain name/etc.
- Mix of Sequence-based, Edit-based and Token-based textdistance algorithms to increase result quality by considering degree of freedom in choosing variations of domain names from attacker side
- Keyword Searches in Page Source Codes (HTML Title Tag and HTML Description Tag), even if they are in other languages (using Google Translator API - english per default - beware of API rate limit). This is to cover needs of international companies and foreign-speaking markets / websites.
- Domain Registrar, Domain Creation Date, MX- and A-Record lookups are included but not activated by default.
- Possibility to change pre-defined thresholds of fuzzy-matching algorithms if you want to

**Example Screenshot:**
![image](https://user-images.githubusercontent.com/124390875/219737268-0767db9d-0b9d-4a7e-9fba-83b1bf8e3636.png)

**How to install:**
- git clone https://github.com/PAST2212/domainthreat.git
- pip install -r requirements.txt

**How to run:**
- python3 domainthreat.py

**Before the first run - How it Works:**

![image](https://user-images.githubusercontent.com/124390875/216693263-1f4b68dd-ac95-4bda-8887-dba1044b3103.png)
Put your brands or mailing domain names into this list for monitoring operations (without the TLD).

![image](https://user-images.githubusercontent.com/124390875/216693388-b5543d15-26a0-410d-a62b-6e3764b713b6.png)
Put here common word collisions you want to exclude from the results to reduce false positives.

![image](https://user-images.githubusercontent.com/124390875/216693614-2b112eda-d900-4283-9161-ef96562d9357.png)
Put here generic words from your strings you have in your monitoring list to exlcude them from the longest common substring textdistance operations to reduce false positives.


![image](https://user-images.githubusercontent.com/124390875/216693534-06a412d5-597d-4fae-acd5-1ce18502d5c5.png)

Put in Key 'Industry' commonly used words that are describing your brands, industry, brand names, products on websites. Default language is english for performing automated translation operations from HTML Title and Description Tag via Google Translator API. 
Leave Key 'Exceptions' unchanged. 


A perfect supplement to this wonderful project: https://github.com/elceef/dnstwist

Written in Python 3.7

TO DO:
- Increase Speed - Website Page source requests for hundreds of domains massively slows down the whole process time. 
- Add additional fuzzy matching algorithms to increase true positive rate / accurancy.
- Add Possibility to make Subdomain Scans
