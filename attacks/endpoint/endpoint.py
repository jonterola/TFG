import pathlib
import settings
from pyzip import PyZip
from attacks import crawler
from termcolor import colored

DIRECTORY_PATH = pathlib.Path().resolve()

def analyze(firstTime, COMMON_MALWARE_FAMILIES):

    if firstTime == True:
        for malware in COMMON_MALWARE_FAMILIES:
            crawler.getMalware(malware)
    else:
        print('TODO: Analizar')




def extractFiles():
    print('')
    print('UNZIPPING FILES INTO: ' + str(settings.DIRECTORY_PATH) + '/attacks/endpoint/malware/')
    print('')



