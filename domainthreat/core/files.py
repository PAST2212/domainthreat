#!/usr/bin/env python3

import os
import base64
import sys
from pathlib import Path
import datetime
import csv
from io import BytesIO
import zipfile
import requests
import pandas as pd
from domainthreat.core.utilities import FeaturesToCSV

DATA_DIRECORY = Path(__file__).parents[1] / 'data'

USER_DATA_DIRECTORY = DATA_DIRECORY / 'userdata'
DOMAIN_FILE_DIRECTORY = DATA_DIRECORY / 'domainfile'


class ManageFiles:
    def __init__(self):
        self.advanced_file = f"Advanced_Monitoring_Results_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv"
        self.basic_file = f"Newly_Registered_Domains_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv"
        self.domain_output_file = f"domain_results_{datetime.datetime.today().strftime('20%y_%m_%d')}.csv"
        self.keywords = 'keywords'
        self.unique = 'unique_brand_names'
        self.black = 'blacklist_keywords'
        self.lcs = 'blacklist_lcs'
        self.topic = 'topic_keywords'
        self.languages = 'languages_advanced_monitoring'
        self.whoids_filename = f"whoisds_domains_{datetime.datetime.today().strftime('20%y_%m_%d')}.txt"
        self.previous_date = (datetime.datetime.today() - datetime.timedelta(days=1)).strftime('20%y-%m-%d')
        self.domains = 'Domains'
        self.csvcolumn_keyword = 'Keyword Found'
        self.date = 'Monitoring Date'
        self.detected = 'Detected by'
        self.sourcecode = 'Source Code Match'
        self.status = 'Website Status'
        self.subdomains = 'Subdomains'
        self.email = 'Email Availability'
        self.parked = 'Parked Domains'
        self.current_github_filename = f"github_domains_{datetime.datetime.today().strftime('20%y_%m_%d')}.txt"
        self.previous_github_filename = 'previous_github_domains.txt'

    def download_whoisds_domains(self) -> None:
        domain_file_path = DOMAIN_FILE_DIRECTORY / self.whoids_filename
        if domain_file_path.exists():
            domain_file_path.unlink()

        previous_date_formated = self.previous_date + '.zip'
        this_new = base64.b64encode(previous_date_formated.encode('ascii'))
        whoisds_link = f"https://whoisds.com//whois-database/newly-registered-domains/{this_new.decode('ascii')}/nrd"
        try:
            request = requests.get(whoisds_link)
            zipfiles = zipfile.ZipFile(BytesIO(request.content))
            zipfiles.extractall(DOMAIN_FILE_DIRECTORY)
            zipfiles.close()
            print(f"Whoisds Domain file downloaded successfully to {domain_file_path}")

        except requests.RequestException as e:
            print(f"Error downloading Whoisds domain file: {str(e)}. Please check: {whoisds_link}\n")

    def read_whoisds_domains(self) -> list[str]:
        download_file_path = DOMAIN_FILE_DIRECTORY / 'domain-names.txt'
        domain_file_path = DOMAIN_FILE_DIRECTORY / self.whoids_filename
        if download_file_path.exists():
            os.rename(f"{DOMAIN_FILE_DIRECTORY}/domain-names.txt", domain_file_path)

        list_file_domains = []
        try:
            with domain_file_path.open('r', encoding='utf-8-sig') as file:
                for domain in file:
                    list_file_domains.append(domain.replace("\n", "").lower().strip())

        except IOError as e:
            print(f"Something went wrong with reading Whoisds Domain File: {str(e)}. Please check file {domain_file_path}")

        return list_file_domains

    @staticmethod
    def download_github_domains() -> None:
        domain_file_path = DOMAIN_FILE_DIRECTORY / f"github_domains_{datetime.datetime.today().strftime('20%y_%m_%d')}.txt"
        if not domain_file_path.exists():
            github_url = 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/nrd7.txt'
            try:
                response = requests.get(github_url)
                response.raise_for_status()
                with domain_file_path.open('wb') as file:
                    file.write(response.content)
                print(f"Github Domain file downloaded successfully to {domain_file_path}")

            except requests.RequestException as e:
                print(f"Error downloading Github domain file: {str(e)}. Please check: {github_url}\n")

        else:
            domain_file_path.unlink()

    @staticmethod
    def _read_github_domains(filename: str) -> list[str]:
        domain_file_path = DOMAIN_FILE_DIRECTORY / filename
        github_domains = set()
        try:
            with domain_file_path.open('r', encoding='utf-8-sig') as file:
                for domain in file:
                    if domain and not domain.startswith('#'):
                        github_domains.add(domain.replace("\n", "").lower().strip())

        except Exception as e:
            print(f"Error reading Domain File: {str(e)}. Please check: {domain_file_path}")

        return list(github_domains)

    def get_new_github_domains(self) -> list[str]:
        current_domains = self._read_github_domains(self.current_github_filename)
        print(f"Note: On the first run, all {len(current_domains)} Github Domains (Domains registered within the past 7 days) will be considered as 'Newly Registered or Updated Domains', since there is no 'previous_github_domains.txt' file existent in {DOMAIN_FILE_DIRECTORY} Directory to compare against.")
        print(f"Please check 'https://github.com/hagezi/dns-blocklists?tab=readme-ov-file#nrd' for more notes")
        previous_file_path = DOMAIN_FILE_DIRECTORY / self.previous_github_filename
        current_file_path = DOMAIN_FILE_DIRECTORY / self.current_github_filename
        if previous_file_path.exists():
            previous_domains = self._read_github_domains(self.previous_github_filename)
            new_domains = list(set(current_domains) - set(previous_domains))
            previous_file_path.unlink()
        else:
            new_domains = current_domains

        if current_file_path.exists():
            current_file_path.rename(previous_file_path)

        return new_domains

    def user_data(self, file: str) -> list:
        try:
            file_keywords = open(f"{USER_DATA_DIRECTORY}/{file}.txt", 'r', encoding='utf-8-sig')
            keywords = []
            for my_domains in file_keywords:
                domain = my_domains.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
                if domain is not None and domain != '':
                    if file == self.keywords:
                        keywords.append(domain)
                    elif file == self.unique:
                        keywords.append(domain)
                    elif file == self.black:
                        keywords.append(domain)
                    elif file == self.lcs:
                        keywords.append(domain)
                    elif file == self.topic:
                        keywords.append(domain)
                    elif file == self.languages:
                        keywords.append(domain)
            file_keywords.close()
        except Exception as e:
            print(f"Something went wrong with reading User Data File: {str(e)}. Please check file {USER_DATA_DIRECTORY}/{file}.txt")
            sys.exit(1)

        return keywords

    def create_csv_basic_monitoring(self) -> None:
        console_file_path = self.basic_file
        if not os.path.exists(console_file_path):
            print("Create Monitoring with Newly Registered Domains")
            header = [self.domains, self.csvcolumn_keyword, self.date, self.detected, self.sourcecode, self.status, self.parked, self.subdomains, self.email]
            with open(console_file_path, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(header)

    def create_domain_output_file(self) -> None:
        console_file_path = self.domain_output_file
        if not os.path.exists(console_file_path):
            header = [self.domains, self.csvcolumn_keyword, self.date, self.detected]
            with open(console_file_path, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(header)

    def create_csv_advanced_monitoring(self) -> None:
        console_file_path = self.advanced_file
        if not os.path.exists(console_file_path):
            header = ['Domains', 'Source Code Match', 'Monitoring Date']
            with open(console_file_path, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(header)

    def write_csv_basic_monitoring(self, iterables: list) -> None:
        with open(self.basic_file, mode='a', newline='') as f:
            writer = csv.writer(f, delimiter=',')
            for k in iterables:
                if isinstance(k, tuple):
                    writer.writerow([k[0], k[1], k[2], k[3]])

    def write_domain_output_file(self, iterables: list) -> None:
        with open(self.domain_output_file, mode='a', newline='') as f:
            writer = csv.writer(f, delimiter=',')
            for k in iterables:
                if isinstance(k, tuple):
                    writer.writerow([k[0], k[1], k[2], k[3]])

    def write_csv_advanced_monitoring(self, iterables: list) -> None:
        with open(self.advanced_file, mode='a', newline='') as f:
            writer = csv.writer(f, delimiter=',')
            for k in iterables:
                writer.writerow([k[0], k[1], k[2]])

    def postprocessing_basic_monitoring(self, iterables: list, source: list, website_status: list, park_domain: list, subdomain: set, email_info: list) -> None:
        try:
            df = pd.read_csv(self.basic_file, delimiter=',')
            df[self.sourcecode] = df.apply(lambda x: FeaturesToCSV().topics_and_status(x['Domains'], features=source) if x['Domains'] in iterables else x[self.sourcecode], axis=1)
            df[self.status] = df.apply(lambda x: FeaturesToCSV().topics_and_status(x['Domains'], features=website_status) if x['Domains'] in iterables else x[self.status], axis=1)
            df[self.parked] = df.apply(lambda x: FeaturesToCSV().email_and_parked(x['Domains'], features=park_domain) if x['Domains'] in iterables else x[self.parked], axis=1)
            df[self.subdomains] = df.apply(lambda x: FeaturesToCSV().subdomains(x['Domains'], features=subdomain) if x['Domains'] in iterables else x[self.subdomains], axis=1)
            df[self.email] = df.apply(lambda x: FeaturesToCSV().email_and_parked(x['Domains'], features=email_info) if x['Domains'] in iterables else x[self.email], axis=1)
            df.to_csv(self.basic_file, index=False)
        except pd.errors.ParserError:
            print("Newly_Registered_Domains_Calender_Week CSV File seems to be incorrectly formatted. Please rename the file")

    def postprocessing_advanced_monitoring(self) -> None:
        try:
            df = pd.read_csv(self.advanced_file, delimiter=',')
            df.drop_duplicates(inplace=True, subset=['Domains'])
            df.to_csv(self.advanced_file, index=False)
            print(f"\nPlease check {self.advanced_file} for results\n")
        except pd.errors.ParserError:
            print("Advanced_Monitoring_Results_Calender_Week CSV File seems to be incorrectly formatted. Please rename the file")

    def get_keywords(self):
        return self.user_data(self.keywords)

    def get_unique_brands(self):
        return self.user_data(self.unique)

    def get_blacklist_keywords(self):
        return self.user_data(self.black)

    def get_topic_keywords(self):
        return self.user_data(self.topic)

    def get_languages(self):
        return self.user_data(self.languages)

    def get_blacklist_lcs(self):
        return self.user_data(self.lcs)

    def get_whoisds_domainfile(self):
        return self.read_whoisds_domains()

    def get_github_domainfile(self):
        return self.get_new_github_domains()
