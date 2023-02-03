# domainthreat
Daily Domain Monitoring for Brands and Mailing Domains 

This is my first Project on Github.

Here you can find a Domain Monitoring tool. You can monitor your company brands (e.g. "amazon"), your mailing domains (e.g. "companygroup.com) in case of look-alike domains and other words you want on a daily base.

You can use it to monitor and track recently registered domains with your brands in it or that looks similar to your brands to recognize for example phishing attacks (e.g. CEO-Fraud) or other forms of fraud.

Im using this public source as daily feed:
https://www.whoisds.com/newly-registered-domains

Some TLDs are not included in this public source (e.g. .de TLD). I will publish another script in near future to bypass it by using CERT Transparency Logs as Input instead. But feel free to change the source (e.g a paid source)


Features:
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- IDN Detection
- Find domains that are identical or confusingly similar to your name/brand/mailing domain name/etc.
- Mix of Sequence-based, Edit-based and Token-based textdistance algorithms to increase result quality
- Keyword Searches in Page Source Codes with describing Keywords, even if they are in other languages (using Google Translator API)
- Domain Registrar, Domain Creation Date, MX- and A-Record lookups are included but not activated by default

