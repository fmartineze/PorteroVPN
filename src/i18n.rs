//! Traduccion de la interfaz (castellano / ingles).
//!
//! Las cadenas se compilan dentro del binario, sin fichero de traducciones
//! externo: uno cargado en tiempo de ejecucion seria una pieza mas que puede
//! faltar tras una instalacion, y el fallo apareceria en casa del usuario y no
//! aqui.
//!
//! `declare_messages!` genera un `enum Msg` y dos `match` exhaustivos, uno por
//! idioma. Esto no es decorativo: **si alguien anade una clave y olvida su
//! traduccion, el programa no compila**, asi que no hay forma de que quede una
//! cadena a medio traducir en produccion.
//!
//! El idioma vive en un atomico global en vez de viajar como parametro porque
//! los textos no se producen solo en la UI: `connection` y `checks` construyen
//! mensajes desde tareas de fondo que no ven el estado de la aplicacion, y
//! pasarles el idioma obligaria a tocar la firma de toda la cadena de llamadas.
//! Como egui repinta cada frame, escribir el atomico basta para que la interfaz
//! entera cambie de idioma al instante, sin reiniciar.
//!
//! Lo que NO se traduce: las lineas de log que emite `openvpn.exe`, las cadenas
//! de su management interface (`ENTER PASSWORD:`, `CONNECTED`, `AUTH_FAILED`...)
//! y los errores que llegan del sistema operativo o de WMI, que vienen en el
//! idioma que Windows les de.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    Es,
    En,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::Es, Lang::En];

    /// Nombre del idioma en el propio idioma, que es como se espera verlo en
    /// un selector: quien busca ingles busca "English", no "Ingles".
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::Es => "Espanol",
            Lang::En => "English",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Lang::En,
            _ => Lang::Es,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Lang::Es => 0,
            Lang::En => 1,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn current() -> Lang {
    Lang::from_u8(CURRENT.load(Ordering::Relaxed))
}

pub fn set_current(lang: Lang) {
    CURRENT.store(lang.as_u8(), Ordering::Relaxed);
}

/// Idioma de la interfaz de Windows, reducido a los dos que se soportan.
///
/// Se mira el identificador primario (los 10 bits bajos del LANGID) en vez de
/// la etiqueta completa: asi `es-ES`, `es-MX`, `es-AR` y el resto de variantes
/// regionales caen todas en castellano con una sola comparacion. Cualquier
/// otro idioma va a ingles.
///
/// Solo se consulta en el primer arranque, cuando todavia no hay
/// `preferences.toml`; a partir de ahi manda lo que el usuario tenga guardado.
pub fn detect_system_language() -> Lang {
    use windows::Win32::Globalization::GetUserDefaultUILanguage;

    /// `LANG_SPANISH` de winnt.h.
    const LANG_SPANISH: u16 = 0x0A;
    /// `PRIMARYLANGID`: los 10 bits bajos del LANGID.
    const PRIMARY_LANGID_MASK: u16 = 0x3FF;

    let langid = unsafe { GetUserDefaultUILanguage() };
    if langid & PRIMARY_LANGID_MASK == LANG_SPANISH {
        Lang::Es
    } else {
        Lang::En
    }
}

macro_rules! declare_messages {
    ($($(#[$meta:meta])* $key:ident => { es: $es:literal, en: $en:literal }),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Msg {
            $($(#[$meta])* $key,)*
        }

        impl Msg {
            pub fn text(self) -> &'static str {
                match current() {
                    Lang::Es => match self { $(Msg::$key => $es,)* },
                    Lang::En => match self { $(Msg::$key => $en,)* },
                }
            }
        }
    };
}

/// Atajo para `Msg::text()`, que es lo que se usa en cada widget.
pub fn t(msg: Msg) -> &'static str {
    msg.text()
}

declare_messages! {
    // --- Barra superior -----------------------------------------------
    NavConnections    => { es: "Conexiones",     en: "Connections" },
    NavImportOvpn     => { es: "Importar ovpn",  en: "Import ovpn" },
    NavSettingsTip    => { es: "Configuracion",  en: "Settings" },

    // --- Barra inferior -----------------------------------------------
    BtnConnect        => { es: "CONECTAR",           en: "CONNECT" },
    BtnDisconnect     => { es: "DESCONECTAR",        en: "DISCONNECT" },
    BtnCancelConnect  => { es: "CANCELAR CONEXION",  en: "CANCEL CONNECTION" },
    StatusCheckingSecurity => { es: "Comprobando seguridad...", en: "Checking security..." },
    StatusConnectionFailed => { es: "La conexion fallo",        en: "The connection failed" },
    StatusImportToStart    => {
        es: "Importa un perfil .ovpn para empezar",
        en: "Import an .ovpn profile to get started"
    },
    StatusChooseConnection => {
        es: "Elige una conexion de la lista",
        en: "Choose a connection from the list"
    },
    TipInstallService => {
        es: "Instala el servicio PorteroVPNSvc para poder conectar.",
        en: "Install the PorteroVPNSvc service before connecting."
    },
    TipInstallOpenVpn => {
        es: "Instala OpenVPN Community para poder conectar.",
        en: "Install OpenVPN Community before connecting."
    },
    TipChooseConnection => {
        es: "Elige una conexion de la lista.",
        en: "Choose a connection from the list."
    },

    // --- Pantalla de conexiones ---------------------------------------
    BannerServiceMissing => {
        es: "El servicio PorteroVPNSvc no esta instalado todavia: hace falta para poder conectar.",
        en: "The PorteroVPNSvc service is not installed yet: it is required in order to connect."
    },
    BtnInstallService => { es: "Instalar servicio", en: "Install service" },
    BannerOpenVpnMissing => {
        es: "OpenVPN Community no esta instalado todavia: hace falta para poder conectar.",
        en: "OpenVPN Community is not installed yet: it is required in order to connect."
    },
    BtnInstallOpenVpn => { es: "Instalar OpenVPN", en: "Install OpenVPN" },
    BtnRetry          => { es: "Reintentar",       en: "Retry" },
    NoProfilesYet     => {
        es: "Todavia no has importado ningun perfil .ovpn.",
        en: "You have not imported any .ovpn profile yet."
    },

    // --- Fila de perfil / tarjeta de conexion -------------------------
    RowChecking   => { es: "Comprobando...", en: "Checking..." },
    RowConnecting => { es: "Conectando...",  en: "Connecting..." },
    RowConnected  => { es: "Conectado",      en: "Connected" },
    RowError      => { es: "Error",          en: "Error" },

    SecurityChecksHeading => { es: "Comprobaciones de seguridad", en: "Security checks" },
    RunningSecurityChecks => {
        es: "Ejecutando comprobaciones de seguridad...",
        en: "Running security checks..."
    },
    SeeErrorNotice   => { es: "Ver el aviso de error.", en: "See the error notice." },
    BtnViewConnLog   => { es: "Ver log de conexion",    en: "View connection log" },

    // --- Modal de credenciales ----------------------------------------
    CredentialsTitle => { es: "Credenciales requeridas", en: "Credentials required" },
    FieldUsername    => { es: "Usuario:",     en: "Username:" },
    FieldPassword    => { es: "Contrasena:",  en: "Password:" },
    RememberOnDevice => {
        es: "Recordar credenciales en este equipo",
        en: "Remember credentials on this computer"
    },
    BtnConnectSmall  => { es: "Conectar", en: "Connect" },

    // --- Modal de error -----------------------------------------------
    ErrCannotConnectTitle => { es: "No se puede conectar",  en: "Cannot connect" },
    ErrAuthFailedTitle    => { es: "Autenticacion fallida", en: "Authentication failed" },
    ErrAuthFailedBody     => {
        es: "Usuario o contrasena incorrectos.",
        en: "Incorrect username or password."
    },
    ErrCertificateTitle   => { es: "Error de certificado", en: "Certificate error" },
    ErrRejectedTitle      => { es: "Conexion rechazada",   en: "Connection rejected" },
    ErrConnectionTitle    => { es: "Error de conexion",    en: "Connection error" },
    BtnClose              => { es: "Cerrar",               en: "Close" },

    // --- Importar / editar perfil -------------------------------------
    ImportTitle       => { es: "Importar perfil .ovpn", en: "Import .ovpn profile" },
    EditTitle         => { es: "Editar conexion",       en: "Edit connection" },
    FieldName         => { es: "Nombre:",               en: "Name:" },
    RememberForProfile => {
        es: "Recordar credenciales para este perfil",
        en: "Remember credentials for this profile"
    },
    BtnImport         => { es: "Importar",  en: "Import" },
    BtnCancel         => { es: "Cancelar",  en: "Cancel" },
    BtnSave           => { es: "Guardar",   en: "Save" },
    /// Nombre que se propone al importar cuando el fichero no tiene uno usable.
    DefaultProfileName => { es: "Perfil", en: "Profile" },

    // --- Ventana de log -----------------------------------------------
    LogWindowTitle   => { es: "Log de conexion", en: "Connection log" },
    NoActiveConn     => {
        es: "No hay ninguna conexion activa.",
        en: "There is no active connection."
    },
    BtnCopyAll       => { es: "Copiar todo",           en: "Copy all" },
    BtnOpenLogsDir   => { es: "Abrir carpeta de logs", en: "Open logs folder" },

    // --- Primer arranque ----------------------------------------------
    WelcomeTitle => { es: "Bienvenido a Portero VPN", en: "Welcome to Portero VPN" },
    WelcomeBody  => {
        es: "Antes de continuar, define la contrasena que protegera la seccion de Configuracion.",
        en: "Before continuing, set the password that will protect the Settings section."
    },
    FieldConfirmPadded => { es: "Confirmar:  ", en: "Confirm:  " },
    BtnDefinePassword  => { es: "Definir contrasena", en: "Set password" },
    ErrPasswordTooShort => {
        es: "La contrasena debe tener al menos 8 caracteres.",
        en: "The password must be at least 8 characters long."
    },
    ErrPasswordsDiffer => {
        es: "Las contrasenas no coinciden.",
        en: "The passwords do not match."
    },
    ErrPasswordHash => {
        es: "No se pudo generar el hash de la contrasena.",
        en: "The password hash could not be generated."
    },

    // --- Puerta de Configuracion --------------------------------------
    SettingsLockedTitle => { es: "Configuracion protegida", en: "Protected settings" },
    SettingsLockedBody  => {
        es: "Introduce la contrasena de configuracion para continuar.",
        en: "Enter the settings password to continue."
    },
    BtnEnter            => { es: "Entrar", en: "Enter" },
    ErrWrongPassword    => { es: "Contrasena incorrecta.", en: "Incorrect password." },
    ErrNoPasswordSet    => {
        es: "No hay contrasena de configuracion definida.",
        en: "No settings password has been set."
    },

    // --- Configuracion -------------------------------------------------
    SettingsApplication => { es: "Aplicacion", en: "Application" },
    MinimizeOnConnect => {
        es: "Minimizar el panel al conectar correctamente",
        en: "Minimize the panel on a successful connection"
    },
    FieldLanguage     => { es: "Idioma:", en: "Language:" },
    ChecksIntro       => {
        es: "Marca que comprobaciones deben cumplirse para poder conectar.",
        en: "Tick which checks must pass before a connection is allowed."
    },

    // --- Configuracion: reintentos ------------------------------------
    SettingsConnection => { es: "Conexion", en: "Connection" },
    RetryIntro         => {
        es: "Si el servidor rechaza las credenciales, la aplicacion vuelve a \
             intentarlo sola antes de avisarte.",
        en: "If the server rejects the credentials, the application retries on \
             its own before telling you."
    },
    FieldRetryAttempts => { es: "Reintentos:",          en: "Retries:" },
    FieldRetryDelay    => { es: "Espera entre ellos:",  en: "Wait between them:" },
    RetryDisabledHint  => {
        es: "Con 0 reintentos, un rechazo de credenciales se avisa al momento.",
        en: "With 0 retries, a rejected login is reported straight away."
    },
    ChangePasswordSection => {
        es: "Cambiar contrasena de configuracion",
        en: "Change the settings password"
    },
    FieldCurrent      => { es: "Actual:",    en: "Current:" },
    FieldNew          => { es: "Nueva:",     en: "New:" },
    FieldConfirm      => { es: "Confirmar:", en: "Confirm:" },
    BtnSaveNewPassword => {
        es: "Guardar nueva contrasena",
        en: "Save new password"
    },
    ErrNewPasswordTooShort => {
        es: "La nueva contrasena debe tener al menos 8 caracteres.",
        en: "The new password must be at least 8 characters long."
    },
    ErrCurrentPasswordWrong => {
        es: "La contrasena actual no es correcta.",
        en: "The current password is not correct."
    },

    // --- Control del servicio -----------------------------------------
    ServiceHeading        => {
        es: "Servicio del sistema (PorteroVPNSvc)",
        en: "System service (PorteroVPNSvc)"
    },
    ServiceNotInstalled   => { es: "No instalado",            en: "Not installed" },
    ServiceStopped        => { es: "Instalado, detenido",     en: "Installed, stopped" },
    ServiceRunning        => { es: "Instalado y en ejecucion", en: "Installed and running" },
    ServiceTransitioning  => { es: "Cambiando de estado...",  en: "Changing state..." },
    FieldStatus           => { es: "Estado:",    en: "Status:" },
    BtnRefresh            => { es: "Actualizar", en: "Refresh" },
    ServiceExplanation    => {
        es: "Este servicio es el unico componente que corre con privilegios de administrador: \
             solo arranca y detiene openvpn.exe cuando la GUI se lo pide. Instalarlo, reinstalarlo o \
             quitarlo pide confirmacion de administrador (UAC) cada vez.",
        en: "This service is the only component that runs with administrator privileges: it merely \
             starts and stops openvpn.exe when the GUI asks it to. Installing, reinstalling or \
             removing it asks for administrator confirmation (UAC) every time."
    },
    BtnInstall   => { es: "Instalar",    en: "Install" },
    BtnReinstall => { es: "Reinstalar",  en: "Reinstall" },
    BtnUninstall => { es: "Desinstalar", en: "Uninstall" },

    // --- Icono de bandeja ---------------------------------------------
    TrayPanel => { es: "Panel",  en: "Panel" },
    TrayQuit  => { es: "Cerrar", en: "Close" },

    // --- Comprobaciones de seguridad ----------------------------------
    CheckAntivirusName => {
        es: "Antivirus activo (Centro de seguridad de Windows)",
        en: "Antivirus active (Windows Security Center)"
    },
    CheckBitLockerName => {
        es: "BitLocker activo en el disco del sistema",
        en: "BitLocker enabled on the system drive"
    },
    ReasonAntivirusInactive => {
        es: "Se requiere tener Antivirus activo para poder conectar. Si acabas de reactivarlo, \
             espera unos segundos: Windows puede tardar en reflejar el cambio.",
        en: "An active antivirus is required in order to connect. If you have just re-enabled it, \
             wait a few seconds: Windows can take a moment to reflect the change."
    },
    ReasonBitLockerOff => {
        es: "Se requiere tener BitLocker activo en el disco del sistema para poder conectar.",
        en: "BitLocker must be enabled on the system drive in order to connect."
    },
    ReasonBitLockerUnavailable => {
        es: "BitLocker no esta disponible o no esta configurado en este equipo.",
        en: "BitLocker is unavailable or not configured on this computer."
    },
    CheckFirewallName => {
        es: "Cortafuegos activo (Centro de seguridad de Windows)",
        en: "Firewall active (Windows Security Center)"
    },
    ReasonFirewallInactive => {
        es: "Se requiere tener un cortafuegos activo para poder conectar.",
        en: "An active firewall is required in order to connect."
    },
    // El nombre dice "exige" y no "tiene": lo que se lee es la bandera
    // UF_PASSWD_NOTREQD de la cuenta, que indica si Windows le permite tener
    // la contrasena en blanco. Una cuenta puede tener contrasena y aun asi
    // estar marcada asi (visto en la practica), y prometer "tiene contrasena"
    // seria mentir sobre lo que se comprueba.
    CheckWindowsPasswordName => {
        es: "La cuenta de Windows exige contrasena",
        en: "The Windows account requires a password"
    },
    ReasonWindowsPasswordMissing => {
        es: "Esta cuenta de Windows admite contrasena en blanco: se le puede \
             quitar la contrasena sin que nada lo impida. Marca la cuenta como \
             que requiere contrasena antes de conectar.",
        en: "This Windows account allows a blank password: it can be left with \
             no password at all. Mark the account as requiring a password \
             before connecting."
    },

    // --- Instalacion de OpenVPN ---------------------------------------
    InstallSearching => {
        es: "Buscando la ultima version de OpenVPN...",
        en: "Looking for the latest OpenVPN version..."
    },
    InstallRunningMsi => {
        es: "Instalando OpenVPN (te pedira permisos de administrador)...",
        en: "Installing OpenVPN (it will ask for administrator permission)..."
    },

    // --- Conexion ------------------------------------------------------
    /// Estado que se muestra en el primer intento, antes de que openvpn.exe
    /// reporte uno propio. En mayusculas para que case con los suyos.
    ConnStarting => { es: "ARRANCANDO", en: "STARTING" },
    ErrOpenVpnNoResponseAfterHold => {
        es: "openvpn.exe no respondio tras el hold release",
        en: "openvpn.exe did not respond after the hold release"
    },
    ErrOpenVpnClosedDuringStartup => {
        es: "openvpn.exe cerro la conexion durante el arranque",
        en: "openvpn.exe closed the connection during startup"
    },
    OutcomeOk => { es: "ok", en: "ok" },

    // Detalles tecnicos de bajo nivel. No se muestran solos, pero acaban
    // incrustados en un mensaje de usuario ("no se pudo completar la conexion
    // tras 4 intentos: <detalle>"), asi que dejarlos sin traducir produciria
    // avisos a medias en ingles y castellano.
    ErrOpenVpnClosedConnection => {
        es: "openvpn.exe cerro la conexion",
        en: "openvpn.exe closed the connection"
    },
    ErrClosedAfterPassword => {
        es: "conexion cerrada justo despues de enviar la contrasena",
        en: "connection closed right after sending the password"
    },
    ErrClosedDuringHandshake => {
        es: "conexion cerrada durante el handshake",
        en: "connection closed during the handshake"
    },
    ErrStoredCredentialsFormat => {
        es: "formato de credenciales guardadas invalido",
        en: "invalid stored credentials format"
    },
}

// ---------------------------------------------------------------------------
// Mensajes con parametros. No caben en la macro (cada uno compone un `String`
// distinto), asi que van sueltos pero con la misma regla: los dos idiomas
// juntos, para que no se pueda anadir uno y olvidar el otro.
// ---------------------------------------------------------------------------

pub fn connecting_with_state(state: &str) -> String {
    match current() {
        Lang::Es => format!("Conectando... ({state})"),
        Lang::En => format!("Connecting... ({state})"),
    }
}

pub fn connected_to(name: &str) -> String {
    match current() {
        Lang::Es => format!("Conectado a {name}"),
        Lang::En => format!("Connected to {name}"),
    }
}

pub fn ready_to_connect(name: &str) -> String {
    match current() {
        Lang::Es => format!("Listo para conectar: {name}"),
        Lang::En => format!("Ready to connect: {name}"),
    }
}

pub fn connecting_to(name: &str) -> String {
    match current() {
        Lang::Es => format!("Conectando a {name}"),
        Lang::En => format!("Connecting to {name}"),
    }
}

pub fn service_not_responding(detail: &str) -> String {
    match current() {
        Lang::Es => format!("El servicio PorteroVPNSvc esta instalado pero no responde: {detail}"),
        Lang::En => format!("The PorteroVPNSvc service is installed but not responding: {detail}"),
    }
}

pub fn openvpn_install_failed(detail: &str) -> String {
    match current() {
        Lang::Es => format!("No se pudo instalar OpenVPN: {detail}"),
        Lang::En => format!("OpenVPN could not be installed: {detail}"),
    }
}

pub fn downloading_openvpn(version: &str) -> String {
    match current() {
        Lang::Es => format!("Descargando OpenVPN {version} y verificando su firma..."),
        Lang::En => format!("Downloading OpenVPN {version} and verifying its signature..."),
    }
}

pub fn local_ip(value: &str) -> String {
    match current() {
        Lang::Es => format!("IP local: {value}"),
        Lang::En => format!("Local IP: {value}"),
    }
}

pub fn server_ip(value: &str) -> String {
    match current() {
        Lang::Es => format!("Servidor: {value}"),
        Lang::En => format!("Server: {value}"),
    }
}

pub fn connected_time(seconds: u64) -> String {
    match current() {
        Lang::Es => format!("Tiempo conectado: {seconds}s"),
        Lang::En => format!("Connected for: {seconds}s"),
    }
}

pub fn traffic(received: &str, sent: &str) -> String {
    match current() {
        Lang::Es => format!("Trafico: {received} recibidos / {sent} enviados"),
        Lang::En => format!("Traffic: {received} received / {sent} sent"),
    }
}

pub fn vpn_asks_credentials(context: &str) -> String {
    match current() {
        Lang::Es => format!("La conexion VPN pide usuario y contrasena ({context})."),
        Lang::En => format!("The VPN connection is asking for a username and password ({context})."),
    }
}

pub fn certificate_not_verified(detail: &str) -> String {
    match current() {
        Lang::Es => format!("No se pudo verificar el certificado del servidor: {detail}"),
        Lang::En => format!("The server certificate could not be verified: {detail}"),
    }
}

pub fn server_rejects_repeatedly(attempts: u32) -> String {
    match current() {
        Lang::Es => format!("El servidor rechaza la conexion repetidamente (intentos: {attempts})."),
        Lang::En => format!("The server keeps rejecting the connection (attempts: {attempts})."),
    }
}

pub fn file_label(path: &str) -> String {
    match current() {
        Lang::Es => format!("Archivo: {path}"),
        Lang::En => format!("File: {path}"),
    }
}

pub fn imported_but_credentials_failed(detail: &str) -> String {
    match current() {
        Lang::Es => format!("Perfil importado, pero no se pudieron guardar las credenciales: {detail}"),
        Lang::En => format!("Profile imported, but the credentials could not be saved: {detail}"),
    }
}

pub fn could_not_import_profile(detail: &str) -> String {
    match current() {
        Lang::Es => format!("No se pudo importar el perfil: {detail}"),
        Lang::En => format!("The profile could not be imported: {detail}"),
    }
}

pub fn could_not_save_credentials(detail: &str) -> String {
    match current() {
        Lang::Es => format!("No se pudieron guardar las credenciales: {detail}"),
        Lang::En => format!("The credentials could not be saved: {detail}"),
    }
}

pub fn could_not_save_profile(detail: &str) -> String {
    match current() {
        Lang::Es => format!("No se pudo guardar el perfil: {detail}"),
        Lang::En => format!("The profile could not be saved: {detail}"),
    }
}

pub fn could_not_load_profile(detail: &str) -> String {
    match current() {
        Lang::Es => format!("No se pudo cargar el perfil: {detail}"),
        Lang::En => format!("The profile could not be loaded: {detail}"),
    }
}

pub fn could_not_save_password(detail: &str) -> String {
    match current() {
        Lang::Es => format!("No se pudo guardar la contrasena: {detail}"),
        Lang::En => format!("The password could not be saved: {detail}"),
    }
}

pub fn retrying(attempt: u32, max: u32) -> String {
    match current() {
        Lang::Es => format!("REINTENTANDO ({attempt}/{max})"),
        Lang::En => format!("RETRYING ({attempt}/{max})"),
    }
}

pub fn could_not_prepare_connection(detail: &str) -> String {
    match current() {
        Lang::Es => format!("no se pudo preparar la conexion: {detail}"),
        Lang::En => format!("the connection could not be prepared: {detail}"),
    }
}

pub fn could_not_talk_to_openvpn(detail: &str) -> String {
    match current() {
        Lang::Es => format!("no se pudo hablar con openvpn.exe: {detail}"),
        Lang::En => format!("could not talk to openvpn.exe: {detail}"),
    }
}

pub fn could_not_connect_after_attempts(attempts: u32, detail: &str) -> String {
    match current() {
        Lang::Es => format!("no se pudo completar la conexion tras {attempts} intentos: {detail}"),
        Lang::En => format!("the connection could not be completed after {attempts} attempts: {detail}"),
    }
}

pub fn retrying_auth(attempt: u32, max: u32) -> String {
    match current() {
        Lang::Es => format!("Reintentando autenticacion ({attempt}/{max})"),
        Lang::En => format!("Retrying authentication ({attempt}/{max})"),
    }
}

pub fn password_rejected_by_mgmt(response: &str) -> String {
    match current() {
        Lang::Es => format!("la management interface no acepto la contrasena (respuesta: {response})"),
        Lang::En => format!("the management interface rejected the password (response: {response})"),
    }
}

pub fn could_not_check(reason: &str) -> String {
    match current() {
        Lang::Es => format!("no se pudo comprobar ({reason})"),
        Lang::En => format!("could not be checked ({reason})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `CURRENT` es estado global del proceso y los tests corren en paralelo:
    /// sin este cerrojo, uno que cambie el idioma le estropea la lectura a
    /// otro. Mismo patron que usa `storage::tests` con su directorio de datos.
    static LANG_LOCK: Mutex<()> = Mutex::new(());

    fn with_lang<T>(lang: Lang, body: impl FnOnce() -> T) -> T {
        let _guard = LANG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = current();
        set_current(lang);
        let result = body();
        set_current(previous);
        result
    }

    #[test]
    fn same_key_yields_different_text_per_language() {
        let es = with_lang(Lang::Es, || t(Msg::BtnConnect));
        let en = with_lang(Lang::En, || t(Msg::BtnConnect));
        assert_eq!(es, "CONECTAR");
        assert_eq!(en, "CONNECT");
    }

    #[test]
    fn parameterised_messages_follow_the_current_language() {
        let es = with_lang(Lang::Es, || connected_to("Home VPN"));
        let en = with_lang(Lang::En, || connected_to("Home VPN"));
        assert_eq!(es, "Conectado a Home VPN");
        assert_eq!(en, "Connected to Home VPN");
    }

    #[test]
    fn language_roundtrips_through_toml() {
        for lang in Lang::ALL {
            let encoded = toml::to_string(&Wrapper { language: lang }).unwrap();
            let decoded: Wrapper = toml::from_str(&encoded).unwrap();
            assert_eq!(decoded.language, lang);
        }
    }

    #[derive(Serialize, Deserialize)]
    struct Wrapper {
        language: Lang,
    }
}
