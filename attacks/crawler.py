import requests, json, time
from termcolor import colored

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

    if response['query_status'] != 'ok' :
        print('No sample found.')

    else:
        data = response['data']
        malwareHashes = []

        for mal in data:
            malwareHashes.append(mal['sha256_hash'])

        print(str(len(malwareHashes)) + ' muestras encontradas.')
        
        getMalwareSamples(malwareHashes)


#Obtener lista de URLs e IPs maliciosas
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
def getMalwareSamples(malwareHashes):
    print("Recopilando MalwareSamples...")
    print('')

    for mal in malwareHashes:
        time.sleep(1)
        try:
            data = {'query': 'get_file', 'sha256_hash': mal}
            url = "https://mb-api.abuse.ch/api/v1/"
            malfile = requests.post(url, data=data)

            with open('../malsamples/'+ mal + '.zip', 'wb') as f:
                f.write(malfile.content)
        except:
            print("Algo no ha ido como se esperaba... :(")
    
    print('Malware recopilado con exito!')
    print('')
    print('')

