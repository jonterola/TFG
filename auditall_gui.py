import PySimpleGUI as sg

def run() :

    # ----------- Create the 3 layouts this Window will display -----------
    initialLayout = [[sg.Text('AuditAll')],
            [sg.Text('Selecciona uno de los siguientes vectores de ataque:')],
            [sg.Button('Correo electrónico')],
            [sg.Button('Navegación entrante')],
            [sg.Button('Navegación saliente')],
            [sg.Button('Endpoint')]]

    # EMAIL LAYOUTS
    emailLayout = [[sg.Text('Correo electrónico')],
            [sg.Input(key='emailInput')],
            [sg.Button('Analizar'), sg.Button('Volver')]]
    
    emailResultsLayout = [[sg.Text('EMAIL RESULTS')],
            [sg.Button('Volver')]]

    #IN NAVIGATION LAYOUTS
    inNavigationLayout = [[sg.Text('IN NAVIGATION')],
            [sg.Button('Volver')]]
    
    inNavigationResultsLayout = [[sg.Text('IN NAVIGATION RESULTS')]]
    
    #OUT NAVIGATION LAYOUTS
    outNavigationLayout = [[sg.Text('OUT NAVIGATION')],
            [sg.Button('Volver')]]
    
    outNavigationResultsLayout = [[sg.Text('OUT NAVIGATION RESULTS')]]

    #ENDPOINT LAYOUTS
    endpointLayout = [[sg.Text('ENDPOINT')],
            [sg.Button('Volver')]]

    endpointResultsLayout = [[sg.Text('ENDPOINT RESULTS')]]


    layout = [[sg.Column(initialLayout, key='initial'), sg.Column(emailLayout, visible=False, key='email'), sg.Column(emailResultsLayout, visible=False, key='emailResults'), sg.Column(inNavigationLayout, visible=False, key='innav'),
               sg.Column(outNavigationLayout, visible=False, key='outnav'), sg.Column(endpointLayout, visible=False, key='endpoint')]]

    window = sg.Window('AuditAll', layout)

    layout = 'initial'  # The currently visible layout

    while True:
        event, values = window.read()
        print(event, values)
        if event is None:
            break
        if event == 'Correo electrónico':
            print("HOLAAAAAAA")
            window[layout].update(visible=False)
            layout = 'email'
            window['email'].update(visible=True)
        elif event == 'Navegación entrante':
            window[layout].update(visible=False)
            layout = 'innav'
            window['innav'].update(visible=True)
        elif event == 'Navegación saliente':
            window[layout].update(visible=False)
            layout = 'outnav'
            window['outnav'].update(visible=True)
        elif event == 'Endpoint':
            window[layout].update(visible=False)
            layout = 'endpoint'
            window['endpoint'].update(visible=True)
        elif event == 'Analizar':
            window[layout].update(visible=False)
            layout = 'emailResults'
            window['emailResults'].update(visible=True)
        elif event.find("Volver") != -1:
            window[layout].update(visible=False)
            layout = 'initial'
            window['initial'].update(visible=True)
    window.close()

    