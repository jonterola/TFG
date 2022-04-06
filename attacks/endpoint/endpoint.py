import pathlib
import settings
import pyzipper
from attacks import crawler
from malcrypto import cryptography
from termcolor import colored

DIRECTORY_PATH = pathlib.Path().resolve()

def analyze(firstTime, COMMON_MALWARE_FAMILIES):

    if firstTime == True:
        for malware in COMMON_MALWARE_FAMILIES:
            crawler.getMalware(malware)
    
    extractFiles()




def extractFiles():
    print('')
    print('UNZIPPING FILES INTO: ' + str(settings.DIRECTORY_PATH) + '/attacks/endpoint/malware/')
    print('')

    for family in settings.COMMON_MALWARE_FAMILIES:
        for malsample in settings.MALWAREDICT[family]:
            with open(str(settings.DIRECTORY_PATH) + '/malsamples/' + family + '/' + malsample + '.zip', 'rb') as f:
                encryptedMalware = f.read()
                decryptedMalware = cryptography.decrypt(encryptedMalware)

            with open(str(settings.DIRECTORY_PATH) + '/malsamples/' + family + '/' + malsample + '.zip', 'wb') as f:
                f.write(decryptedMalware)

            with pyzipper.AESZipFile(str(settings.DIRECTORY_PATH) + '/malsamples/' + family + '/' + malsample + '.zip') as f:
                f.pwd = b'infected'
                malware = f.read(malsample + '.' + settings.MALWAREDICT[family][malsample][0])

            with open(str(settings.DIRECTORY_PATH) + '/attacks/endpoint/malware/' + 
                malsample + '.' + settings.MALWAREDICT[family][malsample][0],'wb') as f:
                f.write(malware)

    print('')
    print(colored('FILES UNZIPPED!','green',attrs=['bold']))
    print('')   



