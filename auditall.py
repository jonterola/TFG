import sys, getopt, re
from attacks.email import email
from attacks.navigation import in_navigation, out_navigation
from attacks.endpoint import endpoint
from termcolor import colored


arguments = sys.argv[1:]

short_options = "he:np"
long_options = ["help","email=","navigation","endpoint"]

run_options = {
    "email" : False,
    "navigation" : False,
    "endpoint" : False
}

##Familias de malware mas comunes. Serán utilizadas posteriormente para recopilar y categorizar las muestras.
COMMON_MALWARE_FAMILIES = ["AgentTesla","ArkeyStealer","AsyncRAT","CobaltStrike","CoinMiner",
"DCRat","Formbook","Gafgyt","Heodo","Loki","Mirai","Quakbot","RacconStealer","RedLineStealer","RemcosRAT"
,"SnakeKeylogger","Tsunami"]


##Depuracion de los argumentos del comando

try:
    arguments, values = getopt.getopt(arguments, short_options, long_options)
except getopt.error as err:
    print (str(err))
    sys.exit(2)

if(len(arguments) == 0):
    sys.exit("Usage: python auditall.py [--help] [--email] \"email@target.com\" [--navigation] [--endpoint]")


if (("-h","") in arguments or ("--help", "") in arguments) and len(arguments) > 1:
    sys.exit("Usage: python auditall.py [--help] [--email] \"email@target.com\" [--navigation] [--endpoint]")


if (("-h","") not in arguments and ("--help", "") not in arguments) and len(arguments) > 4 :
    sys.exit("Usage: python auditall.py [--help] [--email] \"email@target.com\" [--navigation] [--endpoint]")


##Obtencion de los valores de los argumentos
for current_argument, current_value in arguments:
    if current_argument in ("-h", "--help"):
        print ('''Usage: python auditall.py [--help] [--email] \"email@target.com\" [--navigation] [--endpoint]
        
        ARGUMENT             DESC
        ---------------------------
        -h / --help      
        -e / --email         Scan the target email's security towards malicious mails 
        -n / --navigation    Scan incoming and outgoing navigation of the local host
        -p / --endpoint      Scan endpoint security of the local host'''
        )
        sys.exit()
    elif current_argument in ("-e", "--email"):
        if(not re.match("^\w+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}$",current_value)):
            sys.exit("\'--email\' value must have the following FORMAT: \'XXXX@YYYY.ZZZ\'")

        run_options["email"] = True
        target_email = current_value

    elif current_argument in ("-n", "--navigation"):
        run_options["navigation"] = True

    elif current_argument in ("-p", "--endpoint"):
        run_options["endpoint"] = True
    
    else:
        sys.exit("Unknown argument: \'" + current_argument + "\'")

##Si firstTime = True  ==> es necesario recopilar malware de la BD
##             = False ==> no hacer llamadas a la BD 
firstTime = True

##VECTOR DE ATAQUE: EMAIL
if(run_options["email"] == True):
    print("TARGET: "+ target_email)
    email.analyze(firstTime, COMMON_MALWARE_FAMILIES)
    firstTime = False
    print('')
    print('')
    print('')
    print("###################################################")
    print("###################### EMAIL ######################")
    print("###################################################")
    print('')
    print('')
    print('')

##VECTOR DE ATAQUE: NAVEGACION
if(run_options["navigation"] == True):

#### NAVEGACION ENTRANTE
    in_navigation.analyze(firstTime, COMMON_MALWARE_FAMILIES)
    firstTime = False

    print('')
    print('')
    print('')
    print("###################################################")
    print("############### INCOMING NAVIGATION ###############")
    print("###################################################")
    print('')
    print('')
    print('')

#### NAVEGACION SALIENTE
    out_navigation.analyze(COMMON_MALWARE_FAMILIES)

    print('')
    print('')
    print('')
    print("###################################################")
    print("############### OUTGOING NAVIGATION ###############")
    print("###################################################")
    print('')
    print('')
    print('')

##VECTOR DE ATAQUE: ENDPOINT
if(run_options["endpoint"] == True):
    endpoint.analyze(firstTime, COMMON_MALWARE_FAMILIES)
    firstTime = False
    print('')
    print('')
    print('')
    print("###################################################")
    print("#################### ENDPOINT #####################")
    print("###################################################")
    print('')
    print('')
    print('')