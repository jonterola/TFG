from attacks import crawler
from termcolor import colored

def analyze(firstTime, COMMON_MALWARE_FAMILIES):
    if firstTime == True:
        for malware in COMMON_MALWARE_FAMILIES:
            crawler.getMalware(malware)
    else:
        print('TODO: Analizar')