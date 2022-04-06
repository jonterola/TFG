##ARCHIVO CON LAS VARIABLES GLOBALES

import pathlib

def init():
    ##Path del directorio principal del proyecto
    global DIRECTORY_PATH
    DIRECTORY_PATH = pathlib.Path().resolve()

    ##Familias de malware mas comunes. Serán utilizadas posteriormente para recopilar y categorizar las muestras.
    global COMMON_MALWARE_FAMILIES
    COMMON_MALWARE_FAMILIES = ["AgentTesla","ArkeyStealer"]#,"AsyncRAT","CobaltStrike","CoinMiner",
    #"DCRat","Formbook","Gafgyt","Heodo","Loki","Mirai","Quakbot","RacconStealer","RedLineStealer","RemcosRAT"
    #,"SnakeKeylogger","Tsunami"]

    ##Diccionario con todos los hashes/filetype de cada muestra agrupado por familias
    global MALWAREDICT
    MALWAREDICT = {}

    for fam in COMMON_MALWARE_FAMILIES:
        MALWAREDICT[fam] = {}

    ##Diccionario con todas las URL maliciosas agrupado por familias
    global URLDICT
    URLDICT = {}

    for fam in COMMON_MALWARE_FAMILIES:
        URLDICT[fam] = {}

    global SENDER
    SENDER = {"mail" : "tfg.auditall@gmail.com",
              "pass" : "auditingThings22"}

