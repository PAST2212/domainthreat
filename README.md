# domainthreat
Daily Domain Monitoring for Brands and Mailing Domains 

This is my first Project on Github.

Here you can find a Domain Monitoring tool. You can monitor your company brands (e.g. "amazon"), your mailing domains (e.g. "companygroup.com) in case of look-alike domains and other words you want on a daily base.

You can use it to monitor and track recently registered domains with your brands in it or that looks similar to your brands to recognize for example phishing attacks (e.g. CEO-Fraud) or other forms of fraud.

Im using this public source as daily feed:
https://www.whoisds.com/newly-registered-domains

Desktop path is default path to create output.

Some TLDs are not included in this public source (e.g. .de TLD). I will publish another script in near future to bypass it by using CERT Transparency Logs as Input instead. But feel free to change the source (e.g a paid source)

Features:
- False Positive Reduction Instruments (e.g. self defined Blacklists, Thresholds depending on string lenght)
- IDN Detection
- Find domains that are identical or confusingly similar to your name/brand/mailing domain name/etc.
- Mix of Sequence-based, Edit-based and Token-based textdistance algorithms to increase result quality
- Keyword Searches in Page Source Codes with describing Keywords, even if they are in other languages (using Google Translator API)
- Domain Registrar, Domain Creation Date, MX- and A-Record lookups are included but not activated by default


How it Works:
![image](https://user-images.githubusercontent.com/124390875/216680838-2f862bb8-093c-4fbf-a5bf-d53c4f45e9c3.png)
Put your brands or mailing domain names into this list to monitor

![image](https://user-images.githubusercontent.com/124390875/216681164-9e82874c-a0bb-4658-b3c5-7408753cd4b7.png)
Put here your legal word collisions you want to exclude from the results to reduce false positives

![image](https://user-images.githubusercontent.com/124390875/216681414-59efc295-50ac-4241-a8b2-61e3d38b5f9b.png)
Put here generic words from your strings you have in your monitoring list to exlcude them from the longest common substring textdistance operations to reduce false positives

![image](https://user-images.githubusercontent.com/124390875/216681886-731b918b-87bf-4812-b2eb-448976c7e497.png)
Put here common words that are describing your brands, industry, brand names, etc. 
