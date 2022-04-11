import smtplib, imaplib, email, time, re, sys, settings, json, pyzipper

#from attr import attrs
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from malcrypto import cryptography
from attacks import crawler
from termcolor import colored




##EMAIL##

## Address. Example: hello@gmail.com
ADDRESS = "pruebas.auditall@gmail.com"
## Password.
PASSWORD = "EwX6kBYBPxkTtAR"




def analyze(firstTime, COMMON_MALWARE_FAMILIES):
    if firstTime == True:
        for malware in COMMON_MALWARE_FAMILIES:
            crawler.getMalware(malware)
            
    if(not re.match("^\w+(\.?\w+)?@[a-zA-Z_]+?\.[a-zA-Z]{2,3}$",ADDRESS)):
        sys.exit("Email ADDRESS value must have the following FORMAT: \'XXXX@YYYY.ZZZ\'")

    host = ''
    port = ''
    if ADDRESS.endswith('@gmail.com'):
        host = 'smtp.gmail.com'
        port = '587'
        print('')
        print('GMAIL account detected.')
        print('')
    
    elif ADDRESS.endswith('@outlook.com') or ADDRESS.endswith('@hotmail.com'):
        host = 'smtp-mail.outlook.com'
        port = '587'
        print('')
        print('OUTLOOK account detected.')
        print('')

    else:
        service = askService()
        if service == 'N':
            print('')
            print('Ending EMAIL analysis.')
            print('')
            return
        elif service == 'G':
            print('')
            print('Starting GMAIL analysis.')
            print('')
            host = 'smtp.gmail.com'
            port = '587'
            
        elif service == 'O':
            print('')
            print('Starting OUTLOOK analysis.')
            print('')
            host = 'smtp-mail.outlook.com'
            port = '587'

    if host == 'smtp.gmail.com':
        imap = imaplib.IMAP4_SSL('imap.gmail.com')
    else:
        imap = imaplib.IMAP4_SSL('imap-mail.outlook.com')

    try: 
        imap.login(ADDRESS, PASSWORD)
        print('')
        print('User ' + ADDRESS + ' logged in successfully.')
        print('')
    except:
        print('')
        print('Login for the user ' + ADDRESS + ' was denied. Please check your credentials.')
        print('')
        return

    for fam in COMMON_MALWARE_FAMILIES:
        print('')
        print(colored(str(fam).upper() + ':','white',attrs=['underline','bold']))
        print('')
        for mal in settings.MALWAREDICT[fam]:
            if send_mail(fam, mal, 'smtp.gmail.com', '587') == 0:
                time.sleep(1)
                emailStatus = check_inbox(imap)

                if(emailStatus == 'inbox'):
                    settings.MALWAREDICT[fam][mal][2] = 'inbox'
                elif(emailStatus == 'spam'):
                    settings.MALWAREDICT[fam][mal][2] = 'spam'

    dict2json()

    print('')
    print(colored('Results stored in: ','white', attrs=['underline', 'bold']) + '' +
    str(settings.DIRECTORY_PATH) + '/docs/email.json')
    print('')

def askService():
    print('')
    print('Email service not detected. Which service are you using?')
    print('Gmail [G] / Outlook [O] / None [N]')
    answer = input()

    if answer.lower() == 'Gmail'.lower() or 'G'.lower() :
        return 'G'
    if answer.lower() == 'Outlook'.lower() or 'O'.lower() :
        return 'O'
    if answer.lower() == 'None'.lower() or 'N'.lower() :
        return 'N'

    askService()


def send_mail(family, hash, host, port):
    status = 0

    s = smtplib.SMTP(host=host, port=port)
    s.starttls()
    s.login(settings.SENDER['mail'], settings.SENDER['pass'])

    msg = MIMEMultipart()
    msg['From'] = settings.SENDER['mail']
    msg['To'] = ADDRESS
    msg['Subject'] = "HASH: " + hash + " | DOCTYPE: " + settings.MALWAREDICT[family][hash][0]

    msg.attach(MIMEText('''
    Hello,
    
    This message has been sent by AuditAll, a tool designed for analyzing the security level of an email account.

    There is a malware sample attached to this email so please, DON'T DOWNLOAD IT!!

    AuditAll
    '''))

    filename = str(hash) + '.' + str(settings.MALWAREDICT[family][hash][0])
    filecontent = decryptFile(family, hash)
    
    part = MIMEApplication(
        filecontent,
        Name=filename
    )
    # After the file is closed
    part['Content-Disposition'] = 'attachment; filename="%s"' % filename
    msg.attach(part)
    try:
        s.send_message(msg)
    except Exception as e:
        print(colored('[\u2713] Message with HASH: ' + str(hash) + ' | DOCTYPE: ' + str(settings.MALWAREDICT[family][hash][0]) + ' has been blocked.','green',attrs=['bold']))
        status = -1
    s.close()
    return status


def check_inbox(imap, malhash):  
    ##GET LAST EMAIL IN INBOX
    inbox = imap.select('INBOX', readonly=True)
    email_num = inbox[1][0].decode('utf-8')
    typ, msg_data = imap.fetch(email_num,'(RFC822)')
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])
            if str(msg['subject']).startswith('HASH: ' + str(malhash)):
                print(colored('[X] Message with ' + str(msg['subject']) + ' has arrived to INBOX.','red',attrs=['bold']))
                return 'inbox'

    ##GET LAST EMAIL IN SPAM
    spam = imap.select('SPAM', readonly=True)
    email_num = spam[1][0].decode('utf-8')
    typ, msg_data = imap.fetch(email_num,'(RFC822)')
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])
            if str(msg['subject']).startswith('HASH: ' + str(malhash)):
                print(colored('[*] Message with ' + str(msg['subject']) + ' has arrived to SPAM.','yellow', attrs=['bold']))
                return 'spam'

    print('[\u2713] Message with HASH: ' + str(malhash) + ' | DOCTYPE: ' + str(settings.MALWAREDICT[family][hash][0]) + ' has been blocked.')
    return 'None'
    

##Generar json a partir de la informacion recopilada durante la ejecucion 
def dict2json():
    dictionary = settings.MALWAREDICT
    jsonPath = str(settings.DIRECTORY_PATH) + '/docs/email.json'
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
                            "emailstatus": "{3}"
                        }},
                        {{
                            '''  
            
            with open(jsonPath, 'a') as f:
                f.write(jsonString.format(mal[4],mal[0],mal[3],mal[2]))
        
    ##Ultimo elemento
    jsonString = '''"hash": "{0}",
                            "filetype": "{1}",
                            "malfamily": "{2}",
                            "emailstatus": "{3}"
                        }}
            ]   
    }}'''
    
    with open(jsonPath, 'a') as f:
        f.write(jsonString.format(malList[-1][4], malList[-1][0], malList[-1][3], malList[-1][2]))   


def decryptFile(family, hash):

    with open(str(settings.DIRECTORY_PATH) + '/malsamples/' + family + '/' + hash + '.zip', 'rb') as f:
        encryptedMalware = f.read()
        decryptedMalware = cryptography.decrypt(encryptedMalware)

    with open(str(settings.DIRECTORY_PATH) + '/attacks/email/malware/' + family + '/' + hash + '.zip', 'wb') as f:
        f.write(decryptedMalware)

    with pyzipper.AESZipFile(str(settings.DIRECTORY_PATH) + '/attacks/email/malware/' + family + '/' + hash + '.zip') as f:
        f.pwd = b'infected'
        malware = f.read(hash + '.' + settings.MALWAREDICT[family][hash][0])

    return malware