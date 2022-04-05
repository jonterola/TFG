import requests, json, time, pathlib, os, shutil, settings
from termcolor import colored
from malcrypto import cryptography

## All the malware is extracted from MalwareBazaar project. The goal of this project is to share malware samples
## with the infosec community, AV vendors and threat intelligence providers.

## For its use a API key is needed. You can get yours by registering in : https://bazaar.abuse.ch/

API_KEY = "9e24bc6c5347c236c79b8d25a8ddc1a9"


#Obtener mediante consultas a la BD muestras de malware que formen parte de una familia de malware determinada
def getMalware(malwareFamily):

    print("Crawling malware: " + malwareFamily.upper())
    print('')


    data = {'query': 'get_siginfo', 'signature': malwareFamily, 'limit': 50}
    url = "https://mb-api.abuse.ch/api/v1/"
    response = requests.post(url, data=data).json()
    
    malwareInfo = {}

    if response['query_status'] != 'ok' :
        print('No sample found.')

    else:
        data = response['data']

        for mal in data:
            ##MALWARE INFO STRUCT:
                #   0 : FILE TYPE
                #   1 : ENDPOINT RESULT ==> False = Blocked , True = Vulnerable
                #   2 : EMAIL RESULT ==> None = Blocked , Inbox = Message arrived to Inbox, Spam = Message arrived to Spam
                #   3 : IN NAVIGATION RESULT ==> False = Blocked, True = Vulnerable
                #   4 : OUT NAVIGATION RESULT ==> False = Blocked, True = Vulnerable
            malwareInfo[mal['sha256_hash']] = [mal['file_type'], False, 'None', False, False]

        print(str(len(malwareInfo)) + ' muestras encontradas.')
        settings.MALWAREDICT[malwareFamily] = malwareInfo

        getMalwareSamples(malwareInfo, malwareFamily)

    

#Obtener lista de URLs e IPs maliciosas
##HAY QUE CAMBIAR TODO, HAY QUE USAR URLHAUS
def getMalwareURLs(malwareFamily):
    print("Crawling malware: " + malwareFamily.upper())
    print('')


    data = {'query': 'malwareinfo', 'malware': malwareFamily, 'limit': 50}
    url = "https://threatfox-api.abuse.ch/api/v1/"
    response = requests.post(url, data=json.dumps(data)).json()

    if response['query_status'] != 'ok' :
        print('No sample found.')

    else:
        data = response['data']
        malwareInfo = []

        for mal in data:
            if mal['ioc_type'] == 'ip:port' or mal['ioc_type'] == 'url':                    
                malwareInfo.append([mal['ioc'], mal['ioc_type_desc']])

        
        if(len(malwareInfo) == 0):
            print('No sample found.')
        else:
            print(str(len(malwareInfo)) + ' samples found.')
        
        


#Descargar las muestras de malware que coincidan con los hashes sha-256
def getMalwareSamples(malwareInfo, malwareFamily):
    print('')
    print("Descargando muestras...")
    print('')

    samplePath = str(settings.DIRECTORY_PATH) + "/malsamples/" + malwareFamily + "/"
    os.mkdir(samplePath)

    for mal in malwareInfo:
        time.sleep(0.5)
        try:
            data = {'query': 'get_file', 'sha256_hash': mal}
            url = "https://mb-api.abuse.ch/api/v1/"
            malfile = requests.post(url, data=data)

        except:
            print("Algo no ha ido como se esperaba... :(")
    
        encryptedMalware =  cryptography.encrypt(malfile.content)

        with open(samplePath + mal +".zip", "wb") as f:
            f.write(encryptedMalware)
    print('Malware recopilado con exito!')
    print('')
    print('')


