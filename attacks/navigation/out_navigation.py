import settings, requests
from attacks import crawler
from termcolor import colored

def analyze(COMMON_MALWARE_FAMILIES):
    print('')
    print('Starting the outgoing navigation analysis...')
    print('')

    for fam in settings.COMMON_MALWARE_FAMILIES:
        print('')
        print(colored(str(fam).upper() + ':','white',attrs=['underline']))
        print('')

        for url in settings.URLDICT[fam]:
            
            r = requests.get(settings.URLDICT[fam][url][1] + '://' + settings.URLDICT[fam][url][0])

            if(r.status_code != 200):
                print('')
                print(colored('[\u2713] DOMAIN/IP : ' + settings.URLDICT[fam][url][0] + ' has been blocked.','green',attrs=['bold']))
                print('')

            else:                
                settings.URLDICT[fam][url][3] = True
                print('')
                print(colored('[X] DOMAIN/IP : ' + settings.URLDICT[fam][url][0] + ' hasnt been blocked.','red',attrs=['bold']))
                print('')

    dict2json()



def dict2json():
    print('TODO')