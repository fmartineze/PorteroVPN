//! PorteroVPNSvc: servicio Windows minimo cuya responsabilidad es lanzar y
//! matar procesos `openvpn.exe` bajo peticion de la GUI de Portero VPN, que
//! corre en sesion de usuario sin privilegios.
//!
//! No parsea perfiles .ovpn, no gestiona politica de seguridad ni
//! credenciales: solo recibe `StartProfile{profile_path, mgmt_port}` /
//! `StopProfile{pid}` por un named pipe local y ejecuta `CreateProcess`
//! sobre openvpn.exe. Esto mantiene minima la superficie de codigo
//! corriendo como LocalSystem.
//!
//! Unica excepcion: `QueryBitLocker`, una consulta WMI de solo lectura
//! sobre el estado de BitLocker del volumen de arranque. Va aqui (y no como
//! consulta directa desde la GUI) porque ese namespace WMI esta restringido
//! por defecto a Administradores; el servicio no interpreta el resultado
//! (obligatorio o no sigue siendo decision de `policy.toml`, evaluada en la
//! GUI), solo lo informa.

mod pipe_security;

use std::ffi::OsString;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::process::Command;
use tokio::sync::watch;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use svc_ipc::{IpcRequest, IpcResponse, PIPE_NAME, SERVICE_NAME};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Se invoca de dos formas muy distintas: (a) sin argumentos, por el SCM,
/// como el arranque normal del servicio; (b) con `install`/`uninstall`/
/// `reinstall`, lanzado por la GUI via ShellExecute con "runas" para pedir
/// elevacion (plan, seccion 6: apartado Configuracion/Seguridad). El propio
/// binario del servicio hace de instalador porque ya sabe cual es su ruta.
fn main() -> windows_service::Result<()> {
    init_logging();

    match std::env::args().nth(1).as_deref() {
        Some("install") => exit_with_result(install_service()),
        Some("uninstall") => exit_with_result(uninstall_service()),
        Some("reinstall") => exit_with_result(uninstall_service().and_then(|()| install_service())),
        _ => service_dispatcher::start(SERVICE_NAME, ffi_service_main),
    }
}

fn exit_with_result(result: Result<()>) -> windows_service::Result<()> {
    if let Err(e) = result {
        tracing::error!("operacion de instalacion fallo: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

fn install_service() -> Result<()> {
    use windows_service::service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
        .context("no se pudo conectar con el Service Control Manager (hace falta una consola elevada)")?;
    let executable_path =
        std::env::current_exe().context("no se pudo determinar la ruta de este ejecutable")?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Portero VPN Service"),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = manager
        .create_service(&service_info, ServiceAccess::START | ServiceAccess::CHANGE_CONFIG)
        .context("CreateService fallo")?;
    let _ = service.set_description(
        "Lanza y controla openvpn.exe bajo peticion de la GUI de Portero VPN. No procesa perfiles ni credenciales.",
    );
    service
        .start(&[] as &[&std::ffi::OsStr])
        .context("el servicio se registro pero no se pudo arrancar")?;

    tracing::info!("PorteroVPNSvc instalado y arrancado");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("no se pudo conectar con el Service Control Manager (hace falta una consola elevada)")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)
        .context("el servicio no esta instalado")?;

    if service.query_status().context("no se pudo consultar el estado del servicio")?.current_state
        != ServiceState::Stopped
    {
        service.stop().context("no se pudo detener el servicio")?;
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(250));
            if matches!(service.query_status().map(|s| s.current_state), Ok(ServiceState::Stopped)) {
                break;
            }
        }
    }

    service.delete().context("no se pudo eliminar el servicio")?;
    tracing::info!("PorteroVPNSvc desinstalado");
    Ok(())
}

fn init_logging() {
    // El servicio no tiene consola: se registra en ProgramData junto al
    // resto de datos de la app, con rotacion diaria.
    let log_dir = std::env::var("ProgramData")
        .map(|p| format!(r"{p}\PorteroVPN\logs"))
        .unwrap_or_else(|_| r"C:\ProgramData\PorteroVPN\logs".to_string());
    let _ = std::fs::create_dir_all(&log_dir);

    // `rolling::daily` entra en panico si no puede abrir el fichero (p.ej.
    // permisos heredados de un arranque anterior con otro usuario/elevacion);
    // con el builder se degrada a "sin log a fichero" en vez de tumbar el
    // servicio por esto.
    match tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("portero-vpn-svc.log")
        // Sin esto, un fichero de log tecnico nuevo cada dia se acumulaba
        // para siempre; se conservan como mucho los ultimos 10.
        .max_log_files(10)
        .build(&log_dir)
    {
        Ok(file_appender) => {
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            // El guard debe vivir mientras el proceso este vivo para no perder logs
            // en buffer; lo filtramos deliberadamente.
            std::mem::forget(guard);
            let _ = tracing_subscriber::fmt()
                .with_writer(non_blocking)
                .with_ansi(false)
                .try_init();
        }
        Err(_) => {
            let _ = tracing_subscriber::fmt().with_ansi(false).try_init();
        }
    }
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("PorteroVPNSvc fallo: {e:#}");
    }
}

fn run_service() -> windows_service::Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let rt = tokio::runtime::Runtime::new().expect("no se pudo crear el runtime tokio");
    rt.block_on(async move {
        if let Err(e) = pipe_server(shutdown_rx).await {
            tracing::error!("pipe_server termino con error: {e:#}");
        }
    });

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

async fn pipe_server(mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
    let sa = pipe_security::authenticated_users_security_attributes()
        .context("no se pudo construir el descriptor de seguridad del pipe")?;

    // Se crea la primera instancia antes de entrar en el bucle; cada
    // aceptacion prepara inmediatamente la siguiente instancia para no
    // dejar huecos donde un cliente no pueda conectar.
    let mut server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(PIPE_NAME, &sa as *const _ as *mut _)
    }
    .context("no se pudo crear la primera instancia del named pipe")?;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::info!("Senal de parada recibida, cerrando servicio");
                    break;
                }
            }
            connect_result = server.connect() => {
                connect_result.context("fallo al aceptar conexion en el named pipe")?;

                let next_server = unsafe {
                    ServerOptions::new().create_with_security_attributes_raw(PIPE_NAME, &sa as *const _ as *mut _)
                }
                .context("no se pudo preparar la siguiente instancia del named pipe")?;
                let connected = std::mem::replace(&mut server, next_server);

                tokio::spawn(async move {
                    if let Err(e) = handle_client(connected).await {
                        tracing::warn!("cliente IPC desconectado con error: {e:#}");
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_client(pipe: tokio::net::windows::named_pipe::NamedPipeServer) -> Result<()> {
    let (read_half, mut write_half) = tokio::io::split(pipe);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // cliente cerro la conexion
        }

        let request: IpcRequest = match serde_json::from_str(line.trim_end()) {
            Ok(r) => r,
            Err(e) => {
                let resp = IpcResponse::Error { message: format!("peticion invalida: {e}") };
                send_response(&mut write_half, &resp).await?;
                continue;
            }
        };

        tracing::info!(?request, "peticion IPC recibida");
        let response = handle_request(request).await;
        tracing::info!(?response, "respondiendo por el pipe");
        send_response(&mut write_half, &response).await?;
        tracing::info!("respuesta enviada");
    }

    Ok(())
}

async fn send_response(
    write_half: &mut (impl tokio::io::AsyncWrite + Unpin),
    response: &IpcResponse,
) -> Result<()> {
    let mut payload = serde_json::to_string(response)?;
    payload.push('\n');
    write_half.write_all(payload.as_bytes()).await?;
    write_half.flush().await?;
    Ok(())
}

async fn handle_request(request: IpcRequest) -> IpcResponse {
    match request {
        IpcRequest::Ping => IpcResponse::Pong,
        IpcRequest::StartProfile { profile_path, passfile_path, mgmt_port } => {
            match start_openvpn(&profile_path, &passfile_path, mgmt_port).await {
                Ok(pid) => {
                    IpcResponse::Started { pid }
                }
                Err(e) => {
                    tracing::error!("fallo al arrancar openvpn.exe: {e:#}");
                    IpcResponse::Error { message: e.to_string() }
                }
            }
        }
        IpcRequest::StopProfile { pid } => match stop_openvpn(pid).await {
            Ok(()) => IpcResponse::Stopped,
            Err(e) => IpcResponse::Error { message: e.to_string() },
        },
        IpcRequest::QueryBitLocker => {
            let status = tokio::task::spawn_blocking(query_bitlocker_status).await.unwrap_or_else(|e| {
                tracing::error!("tarea WMI de BitLocker abortada: {e}");
                svc_ipc::BitLockerVolumeStatus::Unavailable
            });
            IpcResponse::BitLockerStatus(status)
        }
        IpcRequest::StartWireGuardTunnel { config, tunnel_name } => {
            match start_wireguard_tunnel(&config, &tunnel_name).await {
                Ok(()) => IpcResponse::WireGuardStarted,
                Err(e) => {
                    tracing::error!("fallo al levantar el tunel de WireGuard: {e:#}");
                    IpcResponse::Error { message: e.to_string() }
                }
            }
        }
        IpcRequest::StopWireGuardTunnel { tunnel_name } => {
            match stop_wireguard_tunnel(&tunnel_name).await {
                Ok(()) => IpcResponse::Stopped,
                Err(e) => IpcResponse::Error { message: e.to_string() },
            }
        }
        IpcRequest::QueryWireGuardStatus { tunnel_name } => {
            match query_wireguard_status(&tunnel_name).await {
                Ok(status) => IpcResponse::WireGuardStatus(status),
                Err(e) => IpcResponse::Error { message: e.to_string() },
            }
        }
    }
}

const BITLOCKER_NAMESPACE: &str = r"root\cimv2\security\MicrosoftVolumeEncryption";
/// Se asume que el volumen de arranque es `C:` -- el caso inmensamente
/// mayoritario en Windows. Cubrir un volumen de arranque en otra letra
/// exigiria una segunda consulta WMI (`Win32_OperatingSystem.SystemDrive`,
/// en el namespace `root\cimv2` normal) solo para ese caso raro; no
/// compensa la complejidad extra para el uso personal al que apunta este
/// proyecto (ver plan de arquitectura, "Escenario de despliegue").
const SYSTEM_DRIVE: &str = "C:";

#[derive(serde::Deserialize)]
struct RawEncryptableVolume {
    #[serde(rename = "ProtectionStatus")]
    protection_status: u32,
}

/// Sincrono (llamadas COM): se ejecuta en `spawn_blocking` desde
/// `handle_request`, igual que la consulta de antivirus en el lado de la
/// GUI (`checks::antivirus::query_antivirus_status`).
fn query_bitlocker_status() -> svc_ipc::BitLockerVolumeStatus {
    use svc_ipc::BitLockerVolumeStatus;

    let com_con = match wmi::COMLibrary::new() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "no se pudo inicializar COM para consultar BitLocker");
            return BitLockerVolumeStatus::Unavailable;
        }
    };

    // Fallar al conectar con este namespace es el caso normal en Windows
    // Home, donde BitLocker no esta disponible como funcion del sistema:
    // no es un error real, es la respuesta ("no protegido, no puede
    // estarlo").
    let wmi_con = match wmi::WMIConnection::with_namespace_path(BITLOCKER_NAMESPACE, com_con) {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(error = %e, "namespace WMI de BitLocker no disponible (normal en Windows Home)");
            return BitLockerVolumeStatus::Unavailable;
        }
    };

    let query = format!("SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = '{SYSTEM_DRIVE}'");
    let results: Vec<RawEncryptableVolume> = match wmi_con.raw_query(&query) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "fallo la consulta WMI de BitLocker");
            return BitLockerVolumeStatus::Unavailable;
        }
    };

    match results.first() {
        Some(volume) if volume.protection_status == 1 => BitLockerVolumeStatus::Protected,
        Some(_) => BitLockerVolumeStatus::NotProtected,
        None => BitLockerVolumeStatus::Unavailable,
    }
}

async fn start_openvpn(profile_path: &str, passfile_path: &str, mgmt_port: u16) -> Result<u32> {
    let openvpn_exe = svc_ipc::openvpn_path::locate_openvpn_exe()
        .context("no se encontro openvpn.exe; instala OpenVPN Community")?;

    // El servicio no tiene consola (LocalSystem, sin sesion interactiva), asi
    // que stdout/stderr heredados de openvpn.exe no van a ningun sitio util:
    // si falla antes de que la management interface este arriba (p.ej. no
    // encuentra el adaptador TAP/Wintun, o el .ovpn tiene un error), ese
    // motivo se perdia sin dejar rastro. `--log` hace que openvpn escriba su
    // propia salida de diagnostico a fichero, con o sin management interface.
    let log_path = format!("{passfile_path}.log");

    // Los argumentos de arranque de la management interface (hold,
    // query-passwords y signal) se documentan y justifican en el plan de
    // arquitectura, seccion 3: la GUI controla el resto del flujo hablando
    // directamente con el socket 127.0.0.1:mgmt_port una vez el proceso vive.
    let mut command = Command::new(openvpn_exe);
    command
        .arg("--config").arg(profile_path)
        .arg("--management").arg("127.0.0.1").arg(mgmt_port.to_string()).arg(passfile_path)
        .arg("--management-hold")
        .arg("--management-query-passwords")
        .arg("--management-signal")
        .arg("--log").arg(&log_path)
        // ATENCION: estos dos flags NO son la solucion de ningun problema,
        // pese a lo que decia el comentario anterior aqui. Se anadieron
        // persiguiendo la teoria de que el arranque se colgaba en silencio
        // por el driver DCO de openvpn 2.7, o por faltar wintun.dll en
        // OpenVPN\bin. Ambas resultaron ser un espejismo: lo que colgaba de
        // verdad era el prompt `ENTER PASSWORD:` de la management interface,
        // que llega SIN salto de linea final y dejaba a la GUI esperando
        // para siempre un '\n' que nunca llegaba (arreglado en
        // `mgmt::client::wait_for_enter_password_prompt`). Lo que hacia que
        // una conexion sana pareciera colgada en el log era que la
        // verbosidad por defecto de `--log` no imprime la linea
        // "MANAGEMENT: TCP Socket listening"; y openvpn 2.7 elimino Wintun
        // por completo, asi que su aviso de obsolescencia es solo ruido.
        //
        // Se dejan puestos porque son inofensivos y el TAP-Windows6 clasico
        // esta instalado igualmente, pero no hay que tratarlos como
        // imprescindibles ni volver a perseguir esas dos teorias.
        .arg("--windows-driver").arg("tap-windows6")
        .arg("--disable-dco")
        .kill_on_drop(false);

    let child = command.spawn().context("CreateProcess sobre openvpn.exe fallo")?;
    let pid = child.id().context("el proceso openvpn.exe no expuso un pid")?;

    tracing::info!(pid, mgmt_port, "openvpn.exe arrancado");
    Ok(pid)
}

async fn stop_openvpn(pid: u32) -> Result<()> {
    // La GUI ya intento un cierre limpio via `signal SIGTERM` sobre la
    // management interface antes de llegar aqui; esto es el ultimo recurso
    // si el proceso no respondio a tiempo (ver plan, seccion 3).
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
            .context("no se pudo abrir el proceso a terminar")?;
        let result = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
        result.context("TerminateProcess fallo")?;
    }

    tracing::info!(pid, "openvpn.exe terminado a la fuerza");
    Ok(())
}

// ---------------------------------------------------------------------------
// WireGuard
//
// A diferencia de OpenVPN, aqui no se lanza ni se vigila ningun proceso: se le
// pide a `wireguard.exe` que registre el tunel como servicio propio de Windows
// y el se encarga del resto. Lo que si hace falta es poder consultar su estado,
// y para eso cada tunel expone un named pipe restringido a Administradores --
// el mismo motivo por el que `QueryBitLocker` vive aqui y no en la GUI.
// ---------------------------------------------------------------------------

/// Cuanto esperar a que `wireguard.exe` termine de instalar o quitar un tunel.
/// Es una operacion sobre el Service Control Manager, rapida; si se pasa de
/// aqui es que algo va mal y conviene devolver el error en vez de dejar a la
/// GUI esperando.
const WIREGUARD_CLI_TIMEOUT: Duration = Duration::from_secs(30);

async fn run_wireguard_cli(args: &[&str]) -> Result<()> {
    let exe = svc_ipc::wireguard_path::locate_wireguard_exe()
        .context("no se encontro wireguard.exe; instala WireGuard para Windows")?;

    let output = tokio::time::timeout(WIREGUARD_CLI_TIMEOUT, Command::new(exe).args(args).output())
        .await
        .context("wireguard.exe no respondio a tiempo")?
        .context("no se pudo ejecutar wireguard.exe")?;

    if !output.status.success() {
        // wireguard.exe escribe el motivo en stderr; sin esto el usuario solo
        // veria un codigo de salida.
        let detalle = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "wireguard.exe fallo ({}): {}",
            output.status,
            if detalle.is_empty() { "sin detalle" } else { &detalle }
        );
    }
    Ok(())
}

/// Directorio propio del servicio para las configuraciones de WireGuard.
///
/// **Fuera del arbol de datos de la GUI a proposito.** La GUI abre permisos de
/// `BUILTIN\Users` sobre todo lo que hay bajo `%ProgramData%\PorteroVPN\`
/// (ver `storage::acl`, que lo hace recursivamente en cada arranque), asi que
/// un `.conf` con la clave privada dentro de ese arbol quedaria legible por
/// cualquier usuario del equipo -- y volveria a quedarlo tras cada reparacion
/// de permisos, aunque se restringiera al crearlo.
fn wireguard_config_dir() -> std::path::PathBuf {
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    std::path::PathBuf::from(program_data).join("PorteroVPNSvc")
}

fn wireguard_config_path(tunnel_name: &str) -> std::path::PathBuf {
    // El nombre del fichero ES el nombre del tunel: `wireguard.exe` bautiza con
    // el el tunel y su adaptador de red.
    wireguard_config_dir().join(format!("{tunnel_name}.conf"))
}

/// Deja el fichero accesible solo a SYSTEM y Administradores.
///
/// Se usa `icacls` por el mismo motivo que en `storage::acl` del crate
/// principal: manipular DACLs a mano resulto fragil, y esta es la herramienta
/// estandar para exactamente esto. `/inheritance:r` corta la herencia del
/// directorio antes de conceder, o los permisos heredados seguirian valiendo.
fn restrict_to_administrators(path: &std::path::Path) -> Result<()> {
    /// SIDs bien conocidos, en vez de nombres: "Administradores" cambia con el
    /// idioma del sistema.
    const SYSTEM_SID: &str = "*S-1-5-18";
    const ADMINISTRATORS_SID: &str = "*S-1-5-32-544";

    let output = std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{SYSTEM_SID}:F"))
        .arg("/grant:r")
        .arg(format!("{ADMINISTRATORS_SID}:F"))
        .output()
        .context("no se pudo ejecutar icacls sobre la configuracion del tunel")?;

    anyhow::ensure!(
        output.status.success(),
        "icacls fallo sobre la configuracion del tunel: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

async fn start_wireguard_tunnel(config: &str, tunnel_name: &str) -> Result<()> {
    anyhow::ensure!(
        svc_ipc::wireguard_path::is_ours(tunnel_name),
        "nombre de tunel inesperado: {tunnel_name}"
    );

    // Si quedo uno anterior con el mismo nombre (cuelgue de la GUI, reconectar
    // sin desconectar), instalar encima falla. Se retira primero; que no exista
    // no es un error.
    let _ = run_wireguard_cli(&["/uninstalltunnelservice", tunnel_name]).await;

    let dir = wireguard_config_dir();
    std::fs::create_dir_all(&dir).context("no se pudo crear el directorio de configuraciones")?;
    let path = wireguard_config_path(tunnel_name);
    std::fs::write(&path, config).context("no se pudo escribir la configuracion del tunel")?;
    // Antes de instalar nada: en cuanto exista el servicio, el fichero es la
    // clave del tunel.
    restrict_to_administrators(&path)?;

    run_wireguard_cli(&["/installtunnelservice", &path.to_string_lossy()]).await?;

    // `/installtunnelservice` deja el servicio del tunel en arranque
    // AUTOMATICO. Eso significaria que tras un reinicio la VPN se levanta sola
    // **sin pasar por las comprobaciones de seguridad**, que es justo lo que
    // esta aplicacion existe para impedir. Se pasa a arranque manual: el tunel
    // solo sube cuando la GUI lo pide, y solo lo pide si los checks pasan.
    if let Err(e) = set_tunnel_start_type_manual(tunnel_name).await {
        // No es motivo para tumbar la conexion, pero si para dejar constancia:
        // el tunel quedaria en automatico y volveria solo tras un reinicio.
        tracing::error!(error = %e, tunnel_name, "no se pudo pasar el tunel a arranque manual");
    }

    tracing::info!(tunnel_name, "tunel de WireGuard levantado");
    Ok(())
}

/// Nombre con el que el Service Control Manager registra un tunel de
/// WireGuard.
fn tunnel_service_name(tunnel_name: &str) -> String {
    format!("WireGuardTunnel${tunnel_name}")
}

/// Estado del servicio del tunel, en texto, para poder explicar por que no se
/// pudo abrir su pipe.
fn tunnel_service_state(tunnel_name: &str) -> String {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        Ok(manager) => manager,
        Err(e) => return format!("en estado desconocido (no se pudo abrir el SCM: {e})"),
    };
    let service = match manager.open_service(tunnel_service_name(tunnel_name), ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(e) => return format!("sin registrar o inaccesible ({e})"),
    };
    match service.query_status() {
        Ok(status) => format!("en estado {:?}", status.current_state),
        Err(e) => format!("en estado desconocido ({e})"),
    }
}

async fn set_tunnel_start_type_manual(tunnel_name: &str) -> Result<()> {
    let output = Command::new("sc")
        .arg("config")
        .arg(tunnel_service_name(tunnel_name))
        // El espacio tras `start=` es obligatorio en la sintaxis de sc.exe.
        .arg("start=")
        .arg("demand")
        .output()
        .await
        .context("no se pudo ejecutar sc.exe")?;

    anyhow::ensure!(
        output.status.success(),
        "sc config fallo: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    Ok(())
}

async fn stop_wireguard_tunnel(tunnel_name: &str) -> Result<()> {
    anyhow::ensure!(
        svc_ipc::wireguard_path::is_ours(tunnel_name),
        "nombre de tunel inesperado: {tunnel_name}"
    );
    let result = run_wireguard_cli(&["/uninstalltunnelservice", tunnel_name]).await;

    // La configuracion se borra aunque quitar el tunel haya fallado: es la
    // clave privada del par y no tiene por que sobrevivir a la conexion.
    let path = wireguard_config_path(tunnel_name);
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, path = %path.display(), "no se pudo borrar la configuracion del tunel");
        }
    }

    result?;
    tracing::info!(tunnel_name, "tunel de WireGuard retirado");
    Ok(())
}

/// Ruta del pipe de estado de un tunel. Lo expone el propio servicio del tunel
/// que crea WireGuard, bajo el prefijo protegido de Administradores.
fn tunnel_pipe_path(tunnel_name: &str) -> String {
    format!(r"\\.\pipe\ProtectedPrefix\Administrators\WireGuard\{tunnel_name}")
}

async fn query_wireguard_status(tunnel_name: &str) -> Result<svc_ipc::WireGuardTunnelStatus> {
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::ClientOptions;

    anyhow::ensure!(
        svc_ipc::wireguard_path::is_ours(tunnel_name),
        "nombre de tunel inesperado: {tunnel_name}"
    );

    let path = tunnel_pipe_path(tunnel_name);
    let mut pipe = match ClientOptions::new().open(&path) {
        Ok(pipe) => pipe,
        Err(e) => {
            // Sin el codigo del sistema y el estado del servicio, este fallo es
            // mudo: "no se pudo abrir" no distingue entre la ruta equivocada,
            // el tunel que no llego a arrancar y un permiso denegado. Costo una
            // tarde averiguarlo a mano.
            let service_state = tunnel_service_state(tunnel_name);
            anyhow::bail!(
                "no se pudo abrir el pipe de estado del tunel en {path}: {e} (codigo {code:?}); \
                 el servicio del tunel esta {service_state}",
                code = e.raw_os_error(),
            );
        }
    };

    // API de espacio de usuario de WireGuard: `get=1` seguido de linea en
    // blanco, y responde con pares clave=valor hasta un `errno=`.
    pipe.write_all(b"get=1\n\n").await.context("no se pudo pedir el estado del tunel")?;

    let mut raw = String::new();
    pipe.read_to_string(&mut raw).await.context("no se pudo leer el estado del tunel")?;

    parse_tunnel_status(&raw).context("respuesta del tunel ilegible")
}

/// Convierte la respuesta de `get=1` en el estado que entiende la GUI.
///
/// Separado de la lectura del pipe a proposito: asi se puede probar con
/// respuestas reales capturadas, sin WireGuard instalado ni tunel levantado.
fn parse_tunnel_status(raw: &str) -> Result<svc_ipc::WireGuardTunnelStatus> {
    let mut last_handshake_epoch: Option<u64> = None;
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut errno: Option<i64> = None;

    for line in raw.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        match key {
            // Puede haber varios pares: se queda el handshake mas reciente y se
            // suman los contadores, que es lo que tiene sentido mostrar como
            // estado del tunel.
            "last_handshake_time_sec" => {
                if let Ok(secs) = value.parse::<u64>() {
                    if secs > 0 {
                        last_handshake_epoch = Some(last_handshake_epoch.map_or(secs, |p| p.max(secs)));
                    }
                }
            }
            "rx_bytes" => rx_bytes += value.parse::<u64>().unwrap_or(0),
            "tx_bytes" => tx_bytes += value.parse::<u64>().unwrap_or(0),
            "errno" => errno = value.parse::<i64>().ok(),
            _ => {}
        }
    }

    match errno {
        Some(0) => {}
        Some(other) => anyhow::bail!("el tunel devolvio errno={other}"),
        None => anyhow::bail!("el tunel no devolvio errno"),
    }

    // El handshake viene como epoch absoluto; a la GUI le sirve mas la
    // antiguedad. `saturating_sub` porque un reloj movido hacia atras no debe
    // producir una antiguedad enorme por desbordamiento.
    let last_handshake_secs_ago = last_handshake_epoch.map(|epoch| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|now| now.as_secs().saturating_sub(epoch))
            .unwrap_or(0)
    });

    Ok(svc_ipc::WireGuardTunnelStatus { last_handshake_secs_ago, rx_bytes, tx_bytes })
}

#[cfg(test)]
mod tests {
    use super::parse_tunnel_status;

    fn epoch_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn parses_a_tunnel_that_has_never_completed_a_handshake() {
        // Recien levantado, WireGuard devuelve 0: no significa "hace mucho"
        // sino "todavia ninguno". El handshake no ocurre hasta que hay trafico
        // que enviar, asi que este es el estado normal al arrancar.
        let raw = "private_key=00\npublic_key=aa\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\nrx_bytes=0\ntx_bytes=148\nerrno=0\n";
        let status = parse_tunnel_status(raw).expect("deberia parsear");

        assert_eq!(status.last_handshake_secs_ago, None);
        assert_eq!(status.rx_bytes, 0);
        assert_eq!(status.tx_bytes, 148);
        assert!(!status.is_alive());
    }

    #[test]
    fn a_recent_handshake_counts_as_alive() {
        let raw = format!(
            "public_key=aa\nlast_handshake_time_sec={}\nrx_bytes=4096\ntx_bytes=2048\nerrno=0\n",
            epoch_now() - 5
        );
        let status = parse_tunnel_status(&raw).expect("deberia parsear");

        assert!(status.last_handshake_secs_ago.unwrap() <= 10);
        assert!(status.is_alive());
        assert_eq!(status.rx_bytes, 4096);
    }

    #[test]
    fn an_old_handshake_is_not_alive() {
        let raw = format!(
            "last_handshake_time_sec={}\nrx_bytes=0\ntx_bytes=0\nerrno=0\n",
            epoch_now() - 400
        );
        let status = parse_tunnel_status(&raw).expect("deberia parsear");

        assert!(status.last_handshake_secs_ago.unwrap() >= 400);
        assert!(!status.is_alive(), "400 s supera el umbral de 180 que aplica WireGuard");
    }

    /// Con varios pares se muestra el handshake mas reciente y la suma de los
    /// contadores.
    #[test]
    fn several_peers_are_aggregated() {
        let now = epoch_now();
        let raw = format!(
            "public_key=aa\nlast_handshake_time_sec={}\nrx_bytes=100\ntx_bytes=200\npublic_key=bb\nlast_handshake_time_sec={}\nrx_bytes=50\ntx_bytes=25\nerrno=0\n",
            now - 300,
            now - 10
        );
        let status = parse_tunnel_status(&raw).expect("deberia parsear");

        assert!(status.last_handshake_secs_ago.unwrap() <= 15, "deberia ganar el mas reciente");
        assert_eq!(status.rx_bytes, 150);
        assert_eq!(status.tx_bytes, 225);
    }

    #[test]
    fn an_error_from_the_tunnel_is_reported() {
        assert!(parse_tunnel_status("errno=1\n").is_err());
        assert!(
            parse_tunnel_status("rx_bytes=0\n").is_err(),
            "sin errno no se puede confiar en la respuesta"
        );
    }
}
