import smtplib, re, sys, settings
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

from attacks import crawler
from termcolor import colored


#import win32com.client

##EMAIL##

## Address. Example: hello@gmail.com
ADDRESS = "pruebas.auditall@outlook.com"
## Password.
PASSWORD = "EwX6kBYBPxkTtAR"




def analyze(firstTime, COMMON_MALWARE_FAMILIES):
    if firstTime == True:
        for malware in COMMON_MALWARE_FAMILIES:
            crawler.getMalware(malware)

    print("TODO")
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

    for fam in COMMON_MALWARE_FAMILIES:
        ##PRUEBAS. HAY QUE CAMBIAR A SAMPLES DE VERDAD
        print('')
        print(str(fam).upper() + ':')
        print('')
        send_mail(ADDRESS, None, host, port)

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


def send_mail(send_to, files, host, port):
    s = smtplib.SMTP(host=host, port=port)
    s.starttls()
    s.login(settings.SENDER['mail'], settings.SENDER['pass'])

    msg = MIMEMultipart()
    msg['From'] = settings.SENDER['mail']
    msg['To'] = ADDRESS
    msg['Subject'] = "HASH | TIPO"

    msg.attach(MIMEText('ESTO ES UN TEXTO DE PRUEBA, NO ME MANDES A SPAM POR FAVOR.'))

    # for f in files or []:
    #     with open(f, "rb") as fil:
    #         part = MIMEApplication(
    #             fil.read(),
    #             Name=basename(f)
    #         )
    #     # After the file is closed
    #     part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
    #     msg.attach(part)
    file = str(settings.DIRECTORY_PATH) + '/hola.doc'
    with open(file, "rb") as fil:
        part = MIMEApplication(
            fil.read(),
            Name=basename(file)
        )
    # After the file is closed
    part['Content-Disposition'] = 'attachment; filename="%s"' % basename(file)
    msg.attach(part)
    try:
        s.send_message(msg)
    except:
        print('[\u2713] Message with HASH : asdfasdfasfa and DOCTYPE : EXE has been blocked.')
    s.close()