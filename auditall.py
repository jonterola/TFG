import sys, getopt, re, shutil, pathlib, os

from attr import attr
import settings
from attacks.email import email
from attacks.navigation import in_navigation, out_navigation
from attacks.endpoint import endpoint
from termcolor import colored
from cryptography.fernet import Fernet


arguments = sys.argv[1:]

short_options = "henp"
long_options = ["help","email","navigation","endpoint"]

run_options = {
    "email" : False,
    "navigation" : False,
    "endpoint" : False
}





##Eliminar muestras de malware descargadas
def clear():
    malwareDirectoryPath = str(settings.DIRECTORY_PATH) + '/malsamples/'
    shutil.rmtree(malwareDirectoryPath)

    if os.exists(str(settings.DIRECTORY_PATH)+ '/attacks/endpoint/malware/'):
        shutil.rmtree(str(settings.DIRECTORY_PATH)+ '/attacks/endpoint/malware/')

    if os.exists(str(settings.DIRECTORY_PATH)+ '/attacks/email/malware/'):
        shutil.rmtree(str(settings.DIRECTORY_PATH)+ '/attacks/email/malware/')
        
##Depuracion de los argumentos del comando

try:
    arguments, values = getopt.getopt(arguments, short_options, long_options)
except getopt.error as err:
    print (str(err))
    sys.exit(2)

##Ningun argumento
if(len(arguments) == 0):
    sys.exit("Usage: python auditall.py [--help] [--email] [--navigation] [--endpoint]")

##Argumento help más otros argumentos
if (("-h","") in arguments or ("--help", "") in arguments) and len(arguments) > 1:
    sys.exit("Usage: python auditall.py [--help] [--email] [--navigation] [--endpoint]")

##Mas argumentos de los permitidos
if (("-h","") not in arguments and ("--help", "") not in arguments) and len(arguments) > 4 :
    sys.exit("Usage: python auditall.py [--help] [--email] [--navigation] [--endpoint]")


##Obtencion de los valores de los argumentos
for current_argument, current_value in arguments:
    if current_argument in ("-h", "--help"):
        print ('''Usage: python auditall.py [--help] [--email] [--navigation] [--endpoint]
        
        ARGUMENT             DESC
        ---------------------------
        -h / --help      
        -e / --email         Scan the target email's security towards malicious mails 
        -n / --navigation    Scan incoming and outgoing navigation of the local host
        -p / --endpoint      Scan endpoint security of the local host'''
        )
        sys.exit()
    elif current_argument in ("-e", "--email"):
        run_options["email"] = True

    elif current_argument in ("-n", "--navigation"):
        run_options["navigation"] = True

    elif current_argument in ("-p", "--endpoint"):
        run_options["endpoint"] = True
    
    else:
        sys.exit("Unknown argument: \'" + current_argument + "\'")

##Si firstTime = True  ==> es necesario recopilar malware de la BD
##             = False ==> no hacer llamadas a la BD 
firstTime = True


settings.init()

##Generación de la clave de encriptacion para la descarga de las muestras
clave = Fernet.generate_key()
with open(str(settings.DIRECTORY_PATH) + '/malcrypto/clave.key', 'wb') as key :
    key.write(clave)

##Creacion de la carpeta malsamples donde se guardaran todas las muestras comprimidas
malwarePath = str(settings.DIRECTORY_PATH) + '/malsamples/'
if os.path.exists(malwarePath):
    shutil.rmtree(malwarePath)

os.mkdir(malwarePath)
print('')
print('FOLDER WITH MALWARE SAMPLES CREATED ON : ' + malwarePath)
print('')

##VECTOR DE ATAQUE: EMAIL
if(run_options["email"] == True):
    print('')
    print('')
    print('')
    print(colored('###################################################','cyan',attrs=['bold']))
    print(colored("###################### EMAIL ######################",'cyan',attrs=['bold']))
    print(colored('###################################################','cyan',attrs=['bold']))
    print('')
    print('')
    print('')

    #Creación de la carpeta malware
    emailMalwarePath = str(settings.DIRECTORY_PATH)+ '/attacks/email/malware/'
    if os.path.exists(emailMalwarePath):
        shutil.rmtree(emailMalwarePath)
    os.mkdir(emailMalwarePath)

    for fam in settings.COMMON_MALWARE_FAMILIES :
        os.mkdir(emailMalwarePath + str(fam)+ '/')

    email.analyze(firstTime, settings.COMMON_MALWARE_FAMILIES)
    firstTime = False
    
##VECTOR DE ATAQUE: NAVEGACION
if(run_options["navigation"] == True):

#### NAVEGACION ENTRANTE
    print('')
    print('')
    print('')
    print(colored('###################################################','cyan',attrs=['bold']))
    print(colored("############### INCOMING NAVIGATION ###############", 'cyan', attrs=['bold']))
    print(colored('###################################################','cyan',attrs=['bold']))
    print('')
    print('')
    print('')
    in_navigation.analyze()


#### NAVEGACION SALIENTE
    print('')
    print('')
    print('')
    print(colored('###################################################','cyan',attrs=['bold']))
    print(colored("############### OUTGOING NAVIGATION ###############", 'cyan', attrs=['bold']))
    print(colored('###################################################','cyan',attrs=['bold']))
    print('')
    print('')
    print('')
    out_navigation.analyze()

##VECTOR DE ATAQUE: ENDPOINT
if(run_options["endpoint"] == True):
    print('')
    print('')
    print('')
    print(colored('###################################################','cyan',attrs=['bold']))
    print(colored('#################### ENDPOINT #####################','cyan', attrs=['bold']))
    print(colored('###################################################','cyan', attrs=['bold']))
    print('')
    print('')
    print('')

    #Creación de la carpeta malware
    endpointMalwarePath = str(settings.DIRECTORY_PATH)+ '/attacks/endpoint/malware/'
    if os.path.exists(endpointMalwarePath):
        shutil.rmtree(endpointMalwarePath)
    os.mkdir(endpointMalwarePath)

    for fam in settings.COMMON_MALWARE_FAMILIES :
        os.mkdir(endpointMalwarePath + str(fam)+ '/')

    endpoint.analyze(firstTime, settings.COMMON_MALWARE_FAMILIES)
    firstTime = False


clear()



