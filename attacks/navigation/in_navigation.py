import settings
from attacks import crawler
from termcolor import colored

def analyze(firstTime, COMMON_MALWARE_FAMILIES):
    for family in COMMON_MALWARE_FAMILIES:
            crawler.getMalwareURLs(family)
    
    print('TODO: Analizar')

    print('')