# domainthreat
Daily Domain Monitoring for Brands and Mailing Domain Names

This is my first Project on Github.

Here you can find a Domain Monitoring tool. You can monitor your company brands (e.g. "amazon"), your mailing domains (e.g. "companygroup) or other words.

You can recognize 
- combo squatting (e.g. amazon-shop.com), 
- typo squatting (ammazon.com), 
- brand impersonations, 
- phishing attacks (e.g. CEO-Fraud),
- and other forms of look-alike Domains (e.g. arnazon.com)

Im using this public source as daily feed:
https://www.whoisds.com/newly-registered-domains

Some TLDs are not included in this public source (e.g. .de TLD). I will publish another script in near future to bypass it by using CERT Transparency Logs as Input instead. But feel free to change the source (e.g a paid source)

Features:
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- IDN Detection
- CSV Export (Desktop path is default path to create output)
- Find domains that are identical or confusingly similar to your name/brand/mailing domain name/etc.
- Mix of Sequence-based, Edit-based and Token-based textdistance algorithms to increase result quality
- Keyword Searches in Page Source Codes with describing Keywords, even if they are in other languages (using Google Translator API - english per default)
- Domain Registrar, Domain Creation Date, MX- and A-Record lookups are included but not activated by default


How it Works:
![image](https://user-images.githubusercontent.com/124390875/216693263-1f4b68dd-ac95-4bda-8887-dba1044b3103.png)
Put your brands or mailing domain names into this list to monitor (without the TLD).

![image](https://user-images.githubusercontent.com/124390875/216693388-b5543d15-26a0-410d-a62b-6e3764b713b6.png)
Put here your legal word collisions you want to exclude from the results to reduce false positives

![image](https://user-images.githubusercontent.com/124390875/216693614-2b112eda-d900-4283-9161-ef96562d9357.png)
Put here generic words from your strings you have in your monitoring list to exlcude them from the longest common substring textdistance operations to reduce false positives


![image](https://user-images.githubusercontent.com/124390875/216693534-06a412d5-597d-4fae-acd5-1ce18502d5c5.png)

Put here common words that are describing your brands, industry, brand names, etc. Default language is english for performing automated translation operations from HTML Title and Description Tag via Google Translator API. 
Leave Key 'Exceptions' unchanged. 
