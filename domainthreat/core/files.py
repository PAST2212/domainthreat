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
from .utilities import FeaturesToCSV

# Daterange of Newly Registered Domains Input from Source whoisds.com.
# Paramater "days=1" means newest feed from today up to maximum oldest feed of newly registered domains "days=4" with free access

DATA_DIRECORY = Path(__file__).parents[1] / 'data'

USER_DATA_DIRECTORY = DATA_DIRECORY / 'userdata'
DOMAIN_FILE_DIRECTORY = DATA_DIRECORY / 'domainfile'


class ManageFiles:
    def __init__(self):
        self.advanced_file = f'Advanced_Monitoring_Results_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv'
        self.basic_file = f'Newly_Registered_Domains_Calender_Week_{datetime.datetime.now().isocalendar()[1]}_{datetime.datetime.today().year}.csv'
        self.keywords = 'keywords'
        self.unique = 'unique_brand_names'
        self.black = 'blacklist_keywords'
        self.lcs = 'blacklist_lcs'
        self.topic = 'topic_keywords'
        self.languages = 'languages_advanced_monitoring'
        self.domain_filename = 'domain-names'
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

    def download_domains(self) -> None:
        if os.path.isfile(f'{DOMAIN_FILE_DIRECTORY}/{self.domain_filename}.txt'):
            os.remove(f'{DOMAIN_FILE_DIRECTORY}/{self.domain_filename}.txt')

        previous_date_formated = self.previous_date + '.zip'
        this_new = base64.b64encode(previous_date_formated.encode('ascii'))
        domain_file = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(this_new.decode('ascii'))

        try:
            request = requests.get(domain_file)
            zipfiles = zipfile.ZipFile(BytesIO(request.content))
            zipfiles.extractall(DOMAIN_FILE_DIRECTORY)
            zipfiles.close()

        except Exception as e:
            print(f'Something went wrong with downloading domain .zip file. Please check download link {domain_file}\n', e)
            print('Please check https://www.whoisds.com/newly-registered-domains for availability of daily input files')
            sys.exit()

    def read_domains(self) -> list:
        list_file_domains = []
        if os.path.isfile(f'{DOMAIN_FILE_DIRECTORY}/{self.previous_date}.txt'):
            os.rename(f'{DOMAIN_FILE_DIRECTORY}/{self.previous_date}.txt', f'{DOMAIN_FILE_DIRECTORY}/{self.domain_filename}.txt')

        try:
            file_domains = open(f'{DOMAIN_FILE_DIRECTORY}/{self.domain_filename}.txt', 'r', encoding='utf-8-sig')
            for my_domains in file_domains:
                domain = my_domains.replace("\n", "").lower().strip()
                list_file_domains.append(domain)
            file_domains.close()

        except Exception as e:
            print(f'Something went wrong with reading Domain File. Please check file {DOMAIN_FILE_DIRECTORY}/{self.domain_filename}.txt', e)
            sys.exit()

        return list_file_domains


    def user_data(self, file: str) -> list:
        try:
            file_keywords = open(f'{USER_DATA_DIRECTORY}/{file}.txt', 'r', encoding='utf-8-sig')
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
            print(f'Something went wrong with reading User Data File. Please check file {USER_DATA_DIRECTORY}/{file}.txt', e)
            sys.exit()

        return keywords

    def create_csv_basic_monitoring(self) -> None:
        console_file_path = self.basic_file
        if not os.path.exists(console_file_path):
            print('Create Monitoring with Newly Registered Domains')
            header = [self.domains, self.csvcolumn_keyword, self.date, self.detected, self.sourcecode, self.status, self.parked, self.subdomains, self.email]
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
            print('Newly_Registered_Domains_Calender_Week CSV File seems to be incorrectly formatted. Please rename the file')

    def postprocessing_advanced_monitoring(self) -> None:
        try:
            df = pd.read_csv(self.advanced_file, delimiter=',')
            df.drop_duplicates(inplace=True, subset=['Domains'])
            df.to_csv(self.advanced_file, index=False)
            print(f'\nPlease check {self.advanced_file} for results\n')
        except pd.errors.ParserError:
            print('Advanced_Monitoring_Results_Calender_Week CSV File seems to be incorrectly formatted. Please rename the file')

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

    def get_domainfile(self):
        return self.read_domains()
