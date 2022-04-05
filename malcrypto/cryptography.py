import pathlib, settings
from cryptography.fernet import Fernet



##Encriptar muestra malware
def encrypt(malwareContent):
    keyPath = str(settings.DIRECTORY_PATH) + '/malcrypto/clave.key'
    with open(keyPath, 'rb') as key:
        clave = key.read()
    f = Fernet(clave)
    return f.encrypt(malwareContent)


##Desencriptar muestra malware
def decrypt(encryptedContent):
    keyPath = str(settings.DIRECTORY_PATH) + '/malcrypto/clave.key'
    with open(keyPath, 'rb') as key:
        clave = key.read()
    f = Fernet(clave)
    return f.decrypt(encryptedContent)