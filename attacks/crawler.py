import requests, json, time, pathlib, os, shutil, settings
from termcolor import colored
from malcrypto import cryptography

## All the malware is extracted from MalwareBazaar project. The goal of this project is to share malware samples
## with the infosec community, AV vendors and threat intelligence providers.

## For its use a API key is needed. You can get yours by registering in : https://bazaar.abuse.ch/

API_KEY = "9e24bc6c5347c236c79b8d25a8ddc1a9"


#Obtener mediante consultas a la BD muestras de malware que formen parte de una familia de malware determinada
def getMalware(malwareFamily):

    print("Collecting malware: " + malwareFamily.upper())
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
            malwareInfo[mal['sha256_hash']] = [mal['file_type'], False, 'None']

        print(str(len(malwareInfo)) + ' samples found.')
        settings.MALWAREDICT[malwareFamily] = malwareInfo

        getMalwareSamples(malwareInfo, malwareFamily)

    

#Obtener lista de URLs e IPs maliciosas
def getMalwareURLs(malwareFamily):
    print('')
    print("Collecting malicious URLs: " + malwareFamily.upper())


    data = {'signature': malwareFamily}
    url = "https://urlhaus-api.abuse.ch/v1/signature/"
    response = requests.post(url, data=data).json()

    if response['query_status'] != 'ok' :
        print('No sample found.')

    else:
        data = response['urls']
        urlInfo = {}

        #Se escogen las primeras 50 URLs de la consulta
        for mal in data[:50]:
            if mal['url_status'] == 'online':
                if str(mal['url']).startswith('http:'):
                    protocol = 'http'
                    domain = str(mal['url']).removeprefix('http://').split('/', 1)[0]
                else:
                    protocol = 'https'
                    domain = str(mal['url']).removeprefix('https://').split('/', 1)[0]

                ##URL INFO STRUCT:
                #   0 : DOMINIO/MAQUINA
                #   1 : PROTOCOLO
                #   2 : IN NAVIGATION RESULT ==> False = Blocked , True = Vulnerable
                #   3 : OUT NAVIGATION RESULT ==> None = Blocked , True = Vulnerable
                urlInfo[mal['url']] = [domain, protocol, False, False]

        settings.URLDICT[malwareFamily] = urlInfo
        if(len(urlInfo) == 0):
            print('No sample found.')
        else:
            print(str(len(urlInfo)) + ' samples found.')
        
        


#Descargar las muestras de malware que coincidan con los hashes sha-256
def getMalwareSamples(malwareInfo, malwareFamily):
    print('')
    print("Downloading samples...")
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
            print("Something went wrong... :(")
    
        encryptedMalware =  cryptography.encrypt(malfile.content)

        with open(samplePath + mal +".zip", "wb") as f:
            f.write(encryptedMalware)
    print('Malware successfully collected!')
    print('')
    print('')



