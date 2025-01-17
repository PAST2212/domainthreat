# domainthreat

Daily Domain Monitoring for Brands and Mailing Domain Names

**Current Version:** 3.21

## What's New in Version 3.21
- Better Subdomain Scan Operation in terms of sources, speed and progress visualization
- other fixes

## Motivation

Traditional domain monitoring often relies solely on brand names, which may not be sufficient to detect all phishing attacks, especially when brand names and mailing domain names differ. This project aims to address this gap by monitoring both brand names and mailing domains, focusing on text strings rather than just brands.

## Detection Scope
- Full-word matching (e.g., amazon-shop.com)
- Regular typosquatting cases (e.g., ammazon.com)
- Look-alikes / phishing / CEO-Fraud domains (e.g., arnazon.com)
- IDN Detection / look-alike domains based on full word matching (e.g., 𝗉ay𝞀al.com)
- IDN Detection / look-alike domains based on partial word matching (e.g., 𝗉ya𝞀a1.com)

![Detection Example](https://github.com/PAST2212/domainthreat/assets/124390875/b9d27c1c-a366-49bf-8c69-666681f87041)

## Features

### Key Features
- Unicode domain names (IDN) / Homoglyph / Homograph Detection
- Various domain fuzzing / similarity algorithms
- Automated website translations
- Support for multiple languages
- Daily CSV exports (calendar week based included additional feature coloumns and monitored domain results only)

### CSV Output Columns / Additional Features
- Detected By: Full Keyword Match or Similar/Fuzzy Keyword Match
- Source Code Match: Keyword detection in websites (supports multiple languages)
- Website Status: HTTP status codes
- Parked: Check if domain is parked (experimental)
- Subdomains: Subdomain scan
- E-Mail Availability: Check domain readiness for receiving/sending emails

### Other Features
- Multithreading (CPU core based), Multiprocessing & Async Requests
- False Positive Reduction Instruments
- Keyword detection in websites without brand names in domain

## Principles

### 1. Basic Domain Monitoring
1.1. Full-word and similar-word domain name detection using keywords from `keywords.txt`

1.2. Keyword detection in source code using `topic_keywords.txt`

Results are exported to `Newly_Registered_Domains_Calender_Week_.csv` file in the project root directory. 

Domain Results only are exprted to `domain_results_.csv`file in the project root directory.

### 2. Advanced Domain Monitoring
2.1. Full-word domain name detection using keywords from `topic_keywords.txt`

2.2. (Optional) Automated `topic_keywords.txt` keyword translation based on user-provided languages using `languages_advanced_monitoring.txt`
   - File `supported_languages.txt` gives an overview of currently supported languages for `languages_advanced_monitoring.txt`
   - Full-word domain name detection using keywords AND translated keywords from `topic_keywords.txt`

2.3. Brand name detection in source code using `unique_brand_names.txt`

Results are exported to `Advanced_Monitoring_Results_Calender_Week_.csv` file in the project root directory.

## Installation

```bash
git clone https://github.com/PAST2212/domainthreat.git
cd domainthreat
pip install -r requirements.txt
```

## Usage

Basic usage (default setting):
```bash
python3 domainthreat.py
```

Advanced usage (example command):
```bash
python3 domainthreat.py --similarity wide --threads 50
```

Options:
- `--similarity`: Select similarity mode (close, wide, medium)
  - close: Less false positives and (potentially) more false negatives (per default)
  - wide: More false positives and (potentially) less false negatives 
  - medium: Tradeoff between both mode options close and wide.
- `--threads`: Number of threads (default: CPU core-based)

## Updating

```bash
cd domainthreat
git pull
```

If you encounter a merge error:
```bash
git reset --hard
git pull
```

**Note:** Backup your userdata folder before updating.

## Configuration

1. Add brand names or mailing domain names to `domainthreat/data/userdata/keywords.txt`
2. (Optional) Add common word collisions to `domainthreat/data/userdata/blacklist_keywords.txt`
3. (Optional) Add industry-, company-, product-related keywords to `domainthreat/data/userdata/topic_keywords.txt`
4. (Optional) Add brand names to `domainthreat/data/userdata/unique_brand_names.txt`

## Changelog

For updates, please see the [Changelog](https://github.com/PAST2212/domainthreat/blob/main/Changelog).

## Notes

### Author
Patrick Steinhoff - [LinkedIn](https://www.linkedin.com/in/patrick-steinhoff-168892222/)

### To-Do
- Add additional fuzzy matching algorithms
- Enhance source code keyword detection on subdomain level
- AI-based Logo Detection by Object Detection
- Implement PEP8 compliance

### Additional Information
- Public source for newly registered domains (whoisds) is capped at 70,000 daily registrations. 
- New Source [NRD project](https://github.com/xRuffKez/NRD) was added in Version 3.20. The provided 14-Day-Lists will be converted to a daily feed upon first download.
- Thresholds for similarity modes can be adjusted to match specific needs.
- Recommended Python version: >= 3.8 (Written in Python 3.10)
- Some TLDs (e.g., ".de" domains) may not be consistently included in the public source. You can use [certthreat](https://github.com/PAST2212/certthreat) to bypass this issue.
- A perfect supplement to this project [dnstwist](https://github.com/elceef/dnstwist)
