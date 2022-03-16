from attacks import crawler
from termcolor import colored

def analyze(COMMON_MALWARE_FAMILIES):
    for malware in COMMON_MALWARE_FAMILIES:
        crawler.getMalwareURLs(malware)