#!/usr/bin/env python3

import datetime
import psutil


def get_workers() -> int:
    cpu_count = psutil.cpu_count(logical=False)
    print(f"{cpu_count} Physical cores detected")
    worker = cpu_count - 1
    print(f"Use {worker} CPU Cores for multiprocessing")
    return int(worker)


class SmoothingResults:
    def __init__(self):
        self.out = []

    @staticmethod
    def group_tuples_first_value(klaus) -> list:
        out = {}
        for elem in klaus:
            try:
                out[elem[0]].extend(elem[1:])
            except KeyError:
                out[elem[0]] = list(elem)
        return [tuple(values) for values in out.values()]

    def _flatten(self, nested_list: list) -> None:
        for item in nested_list:
            if isinstance(item, (str, bool, int, tuple)):
                self.out.append(item)
            elif isinstance(item, dict):
                for i in item.items():
                    self.out.extend(i)

            elif isinstance(item, list):
                self._flatten(item)
            else:
                self.out.extend(list(item))

    def get_flatten_list(self, nested_list: list) -> list:
        self._flatten(nested_list)
        return self.out


class FeaturesToCSV:
    @staticmethod
    def topics_and_status(klaus: list, features: list) -> str:
        for y in features:
            if y[0] == klaus:
                return y[1]

    @staticmethod
    def subdomains(klaus, features: set) -> set:
        subdomains_filtered = SmoothingResults().group_tuples_first_value(features)
        subdomains_filtered_1 = [tuple(dict.fromkeys(k)) for k in subdomains_filtered if
                                 len(tuple(dict.fromkeys(k))) > 1]
        for y in subdomains_filtered_1:
            if y[0] == klaus:
                return y[1:]

    @staticmethod
    def email_and_parked(klaus, features) -> str:
        features_filtered = SmoothingResults().group_tuples_first_value(features)
        for y in features_filtered:
            if y[0] == klaus:
                if any(k == 'Yes' for k in y):
                    return 'Yes'
                else:
                    return 'No'


class Helper:
    @staticmethod
    def get_previous_date():
        previous_date = (datetime.datetime.today() - datetime.timedelta(days=1)).strftime('20%y-%m-%d')
        return previous_date

    @staticmethod
    def get_today():
        today = datetime.date.today()
        return today

    @staticmethod
    def split_into_chunks(domain_input_list: list, n) -> list:
        a, b = divmod(len(domain_input_list), n)
        split_domaininput = [domain_input_list[i * a + min(i, b):(i + 1) * a + min(i + 1, b)] for i in range(n)]
        split_domaininput_order = [[i, v] for i, v in enumerate(split_domaininput)]
        return split_domaininput_order
