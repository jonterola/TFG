from attacks import crawler
from termcolor import colored
import win32com.client

##GMAIL##

## Address. Example: hello@gmail.com
GMAIL_ADDRESS = ""
## Password.
GMAIL_PASSWORD = ""




def analyze(firstTime, COMMON_MALWARE_FAMILIES):
    if firstTime == True:
        for malware in COMMON_MALWARE_FAMILIES:
            crawler.getMalware(malware)
    else:
        print('TODO: MANDAR EMAILS')
        