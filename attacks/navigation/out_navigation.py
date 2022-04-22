import settings, requests
from attacks import crawler
from termcolor import colored

def analyze():
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

   



def dict2json():
    dictionary = settings.URLDICT
    jsonPath = str(settings.DIRECTORY_PATH) + '/docs/navigation.json'
    with open(jsonPath, 'w') as f:
        f.write('''{
                "malware" : [
                        {
                                ''')

    ##Flatten de todas las familias de malware
    malList = []
    for fam in settings.COMMON_MALWARE_FAMILIES:
        for url in dictionary[fam]:
            dictionary[fam][url].append(fam)
            dictionary[fam][url].append(url)
            malware = dictionary[fam][url]
            malList.append(malware)


    ##Formato para todos los elementos menos el ultimo
    for mal in malList[:-1]:
            jsonString = '''"url": "{0}",
                            "filetype": "{1}",
                            "incoming_status": "{2}",
                            "outgoing_status": "{3}"
                        }},
                        {{
                            '''  
            if(mal[2] == False):
                incoming_status = 'blocked'
            else:
                incoming_status = 'vulnerable'

            if(mal[3] == False):
                outgoing_status = 'blocked'
            else:
                outgoing_status = 'vulnerable'

            filetype = ''
            if(len(str(mal[5]).split('/')[-1].split('.')) > 1):
                filetype = str(mal[5]).split('/')[-1].split('.')[-1]

            with open(jsonPath, 'a') as f:
                f.write(jsonString.format(mal[5],filetype, incoming_status , outgoing_status))
        
    ##Ultimo elemento
    jsonString = '''"url": "{0}",
                    "filetype": "{1}",
                    "incoming_status": "{2}",
                    "outgoing_status": "{3}"
                }}
            ]
        }}'''
    
    if(malList[-1][2] == False):
            incoming_status = 'blocked'
    else:
            incoming_status = 'vulnerable'

    if(malList[-1][3] == False):
            outgoing_status = 'blocked'
    else:
            outgoing_status = 'vulnerable'

    filetype = ''
    if(len(str(malList[-1][5]).split('/')[-1].split('.')) > 1):
        filetype = str(malList[-1][5]).split('/')[-1].split('.')[-1]

    with open(jsonPath, 'a') as f:
        f.write(jsonString.format(malList[-1][4], filetype, incoming_status, outgoing_status))