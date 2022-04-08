import settings, requests
from attacks import crawler
from termcolor import colored

def analyze(firstTime, COMMON_MALWARE_FAMILIES):
    for family in COMMON_MALWARE_FAMILIES:
            crawler.getMalwareURLs(family)
    
    print('')
    print('Starting the incoming navigation analysis...')
    print('')

    for fam in settings.COMMON_MALWARE_FAMILIES:
        print('')
        print(colored(str(fam).upper() + ':','white',attrs=['underline']))
        print('')

        for url in settings.URLDICT[fam]:
            
            r = requests.get(url)

            if(r.status_code != 200):
                print('')
                print(colored('[\u2713] URL : ' + url + ' has been blocked.','green',attrs=['bold']))
                print('')

            else:                
                settings.URLDICT[fam][url][2] = True
                print('')
                print(colored('[X] URL : ' + url + ' hasnt been blocked.','red',attrs=['bold']))
                print('')

        dict2json()


def dict2json():
    print('TODO')