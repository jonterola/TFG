import pathlib
from cryptography.fernet import Fernet

DIRECTORY_PATH = pathlib.Path().resolve()

##Encriptar muestra malware
def encrypt(malwareContent):
    keyPath = str(DIRECTORY_PATH) + '/malcrypto/clave.key'
    with open(keyPath, 'rb') as key:
        clave = key.read()
    f = Fernet(clave)
    return f.encrypt(malwareContent)