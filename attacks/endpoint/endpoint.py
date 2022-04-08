import pathlib, settings, pyzipper
from attacks import crawler
from malcrypto import cryptography
from termcolor import colored
from time import sleep
from tqdm import tqdm




def analyze(firstTime, COMMON_MALWARE_FAMILIES):

    if firstTime == True:
        for malware in COMMON_MALWARE_FAMILIES:
            crawler.getMalware(malware)
    
    #extractFiles()
    
    #Wait 3 minutes before cheching if the files have been removed.
    print('')
    print('Wait 3 minutes before checking if files have been removed...')
    print('')

    # for i in tqdm(range(18000)):
    #    sleep(0.01)

    ##TODO: COMPROBAR QUE ARCHIVOS SE HAN BORRADO

    dict2json()

    print('')
    print(colored('Results stored in: ','white', attrs=['underline', 'bold']) + '' +
    str(settings.DIRECTORY_PATH) + '/docs/endpoint.json')
    print('')


##TODO: EXTRAER EN CARPETAS DIFERENTES EN FUNCION DE LA FAMILIA DE MALWARE
def extractFiles():
    print('')
    print('UNZIPPING FILES INTO: ' + str(settings.DIRECTORY_PATH) + '/attacks/endpoint/malware/')
    print('')

    for family in settings.COMMON_MALWARE_FAMILIES:
        for malsample in settings.MALWAREDICT[family]:

            #LEER EL MALWARE ENCRIPTADO Y OBTENER SU CONTENIDO DESENCRIPTADO
            with open(str(settings.DIRECTORY_PATH) + '/malsamples/' + family + '/' + malsample + '.zip', 'rb') as f:
                encryptedMalware = f.read()
                decryptedMalware = cryptography.decrypt(encryptedMalware)

            #SOBREESCRIBIR EL MALWARE CON SU CONTENIDO DESENCRIPTADO
            with open(str(settings.DIRECTORY_PATH) + '/malsamples/' + family + '/' + malsample + '.zip', 'wb') as f:
                f.write(decryptedMalware)

            #OBTENER EL MALWARE DESCOMPRIMIDO
            with pyzipper.AESZipFile(str(settings.DIRECTORY_PATH) + '/malsamples/' + family + '/' + malsample + '.zip') as f:
                f.pwd = b'infected'
                malware = f.read(malsample + '.' + settings.MALWAREDICT[family][malsample][0])

            #ESCRIBIR EL MALWARE DESCOMPRIMIDO EN LA CARPETA /attacks/endpoint/malware/
            with open(str(settings.DIRECTORY_PATH) + '/attacks/endpoint/malware/' + 
                malsample + '.' + settings.MALWAREDICT[family][malsample][0],'wb') as f:
                f.write(malware)

    print('')
    print(colored('FILES UNZIPPED!','green',attrs=['bold']))
    print('')   



##Generar json a partir de la informacion recopilada durante la ejecucion
def dict2json():
    dictionary = settings.MALWAREDICT
    jsonPath = str(settings.DIRECTORY_PATH) + '/docs/endpoint.json'
    with open(jsonPath, 'w') as f:
        f.write('''{
                "malware" : [
                        {
                                ''')

    ##Flatten de todas las familias de malware
    malList = []
    for fam in settings.COMMON_MALWARE_FAMILIES:
        for mal in dictionary[fam]:
            dictionary[fam][mal].append(fam)
            dictionary[fam][mal].append(mal)
            malware = dictionary[fam][mal]
            malList.append(malware)


    ##Formato para todos los elementos menos el ultimo
    for mal in malList[:-1]:
            jsonString = '''"hash": "{0}",
                            "filetype": "{1}",
                            "malfamily": "{2}",
                            "endpointstatus": "{3}"
                        }},
                        {{
                            '''  
            if(mal[1] == False):
                status = 'blocked'
            else:
                status = 'vulnerable'
            with open(jsonPath, 'a') as f:
                f.write(jsonString.format(mal[4],mal[0],mal[3],status))
        
    ##Ultimo elemento
    jsonString = '''"hash": "{0}",
                    "filetype": "{1}",
                    "malfamily": "{2}",
                    "endpointstatus": "{3}"
                }}
            ]
        }}'''
    
    if(malList[-1][1] == False):
            status = 'blocked'
    else:
            status = 'vulnerable'

    with open(jsonPath, 'a') as f:
        f.write(jsonString.format(malList[-1][4], malList[-1][0], malList[-1][3], status))
