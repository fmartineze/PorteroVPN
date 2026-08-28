; Instalador de Portero VPN (Inno Setup). OpenVPN Community no se comprueba
; ni se instala aqui: la propia app lo detecta al arrancar y lo descarga,
; verifica (firma GPG) e instala bajo peticion desde la pantalla de
; Conexiones (ver `src/openvpn_install.rs`), asi siempre coge la version
; publicada en ese momento en vez de quedar fija a la que hubiera al generar
; este instalador. Firma de codigo pendiente (SmartScreen avisara hasta que
; se firme, ver seccion 10 del plan de arquitectura).
;
; Si incluye Vulkan por software (Lavapipe/Mesa3D, ver [Files] y
; `src/gpu_fallback.rs`) como red de seguridad para equipos sin ningun
; backend grafico real (ni GPU, ni WARP) -- a diferencia de OpenVPN, esto si
; se empaqueta, porque es una dependencia tecnica de la propia GUI, no algo
; que el usuario deba instalar el mismo.
;
; Compilar (tras generar los .exe de release, ver "Empaquetado" en el
; README o preguntar a Claude): desde esta carpeta,
;   "C:\Users\<usuario>\AppData\Local\Programs\Inno Setup 6\ISCC.exe" portero-vpn.iss
; El instalador resultante queda en installer\output\PorteroVPN-Setup.exe.

#define AppVersion "0.2.0"

[Setup]
AppId={{67CC109E-AD6C-4033-9EBD-26D3C1EDEC68}
AppName=Portero VPN
AppVersion={#AppVersion}
AppPublisher=Portero VPN
DefaultDirName={autopf}\PorteroVPN
DefaultGroupName=Portero VPN
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\portero-vpn.exe
OutputDir=output
OutputBaseFilename=PorteroVPN-Setup
Compression=lzma2/max
SolidCompression=yes
SetupIconFile=app_icon.ico
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Requiere administrador: registrar el servicio de Windows (PorteroVPNSvc)
; no se puede hacer sin privilegios elevados, asi que se piden una vez para
; todo el instalador en vez de una segunda vez a mitad de la instalacion.
PrivilegesRequired=admin
; Mismo nombre que el mutex de instancia unica (`single_instance.rs`):
; Inno Setup detecta si la app esta corriendo y ofrece cerrarla antes de
; instalar/desinstalar, en vez de fallar al intentar sobrescribir el .exe.
AppMutex=PorteroVPN_SingleInstance_9F1E9E2B-3B7B-4E88-9F1B-6C8E9E7F2B10
MinVersion=10.0
; Con dos idiomas declarados, Inno muestra por defecto un dialogo de
; seleccion antes del asistente. Se desactiva: elige solo segun el idioma
; de Windows, igual que hace la propia aplicacion en su primer arranque
; (ver `AppPreferences::bootstrap_default`).
ShowLanguageDialog=no

[Languages]
; `Default.isl` es el ingles que trae Inno; el resto viven en Languages\.
; El orden importa: si el idioma de Windows no casa con ninguno, Inno usa
; el primero de la lista, asi que el ingles va primero para que cualquier
; sistema no hispanohablante caiga ahi.
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[CustomMessages]
english.DesktopIcon=Create a desktop shortcut
spanish.DesktopIcon=Crear un acceso directo en el escritorio
english.ShortcutsGroup=Shortcuts:
spanish.ShortcutsGroup=Accesos directos:
english.UninstallEntry=Uninstall Portero VPN
spanish.UninstallEntry=Desinstalar Portero VPN
english.InstallingService=Installing the PorteroVPNSvc service...
spanish.InstallingService=Instalando el servicio PorteroVPNSvc...
english.RunApp=Run Portero VPN
spanish.RunApp=Ejecutar Portero VPN

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; GroupDescription: "{cm:ShortcutsGroup}"; Flags: checkedonce

[Files]
Source: "..\target\release\portero-vpn.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\portero-vpn-svc.exe"; DestDir: "{app}"; Flags: ignoreversion
; Vulkan por software (Lavapipe/Mesa3D), ultimo recurso cuando el equipo no
; tiene ningun backend grafico utilizable (ni GPU real, ni WARP) -- ver
; `src/gpu_fallback.rs`. Se instala siempre pero solo se usa si hace falta;
; en un equipo normal esta carpeta no se toca nunca.
Source: "..\assets\lavapipe\vulkan_lvp.dll"; DestDir: "{app}\lavapipe"; Flags: ignoreversion
Source: "..\assets\lavapipe\lvp_icd.x86_64.json"; DestDir: "{app}\lavapipe"; Flags: ignoreversion

[Icons]
Name: "{group}\Portero VPN"; Filename: "{app}\portero-vpn.exe"
Name: "{group}\{cm:UninstallEntry}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Portero VPN"; Filename: "{app}\portero-vpn.exe"; Tasks: desktopicon

[Run]
; El servicio se registra (y arranca) aqui, ya elevado por el propio
; instalador -- sin esto, la app se abriria con el boton CONECTAR
; desactivado hasta que el usuario fuera a Configuracion a instalarlo a
; mano. `CurStepChanged` (ver [Code]) ya se aseguro de que no quedase un
; registro antiguo a medias antes de este paso.
Filename: "{app}\portero-vpn-svc.exe"; Parameters: "install"; StatusMsg: "{cm:InstallingService}"; Flags: runhidden waituntilterminated
Filename: "{app}\portero-vpn.exe"; Description: "{cm:RunApp}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; `sc.exe` en vez de `portero-vpn-svc.exe uninstall`: no depende de que el
; propio ejecutable siga funcionando correctamente para poder desinstalarse
; a si mismo, y es lo que ya usa el paso previo a instalar (ver [Code]).
Filename: "{sys}\sc.exe"; Parameters: "stop PorteroVPNSvc"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete PorteroVPNSvc"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"

[Code]
// Parar y quitar cualquier registro anterior del servicio antes de copiar
// los ficheros nuevos: si ya estaba instalado y corriendo, su .exe estaria
// bloqueado (visto en la practica durante el desarrollo) y la copia
// fallaria. `sc delete` sobre un servicio que no existe simplemente falla
// en silencio, asi que es seguro llamarlo tambien en una instalacion nueva.
procedure StopAndRemoveOldService();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop PorteroVPNSvc', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete PorteroVPNSvc', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    StopAndRemoveOldService();
end;
