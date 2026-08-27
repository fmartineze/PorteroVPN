//! Orquestador del flujo de conexion completo (plan, seccion 3 y 7):
//! checks de seguridad -> arranque via `PorteroVPNSvc` -> credenciales y
//! monitorizacion por la management interface -> cierre limpio. Corre en
//! el runtime de tokio en segundo plano y notifica a la UI via canal.

use std::fs::File;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::checks::{run_pre_connect_checks, CheckContext, CheckOutcome, CheckRegistry, CheckRunResult, WmiDataSource};
use crate::credentials::Credentials;
use crate::mgmt::protocol::{ConnectionStatus, ConnectionTracker, ManagementEvent};
use crate::mgmt::ManagementClient;
use crate::storage::{self, ProfileMeta, SecurityPolicy};
use crate::svc_client::SvcClient;

#[derive(Debug, Clone)]
pub enum AppEvent {
    ChecksStarted,
    CheckResult(CheckRunResult),
    /// Un check obligatorio fallo (o fue indeterminado): no se llega a
    /// arrancar openvpn.exe.
    ChecksFailed(String),
    Connecting { last_state: String },
    NeedsCredentials { context: String },
    LogLine(String),
    ByteCount { bytes_in: u64, bytes_out: u64 },
    Connected { local_ip: Option<String>, remote_ip: Option<String> },
    AuthFailed,
    CertificateError(String),
    ReconnectLoop(u32),
    Disconnected,
    Error(String),
}

/// Extremos que la UI usa para interactuar con una conexion en curso.
pub struct ConnectionHandle {
    pub credentials_tx: mpsc::Sender<Credentials>,
    pub cancel_tx: watch::Sender<bool>,
}

/// Lanza el flujo de conexion completo en una tarea de tokio y devuelve el
/// canal de eventos (para la UI) y el handle de control (para pedir
/// credenciales/cancelar desde la UI).
pub fn spawn_connection(
    profile: ProfileMeta,
    policy: SecurityPolicy,
    registry: Arc<CheckRegistry>,
    wmi: Arc<dyn WmiDataSource>,
    stored_credentials: Option<Credentials>,
) -> (mpsc::UnboundedReceiver<AppEvent>, ConnectionHandle) {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let (credentials_tx, credentials_rx) = mpsc::channel(1);
    let (cancel_tx, cancel_rx) = watch::channel(false);

    tokio::spawn(run_connection(
        profile,
        policy,
        registry,
        wmi,
        stored_credentials,
        events_tx,
        credentials_rx,
        cancel_rx,
    ));

    (events_rx, ConnectionHandle { credentials_tx, cancel_tx })
}

enum ExitReason {
    Cancelled,
    Eof,
    AuthFailed,
    CertificateError,
    ReconnectLoop,
    Error,
}

/// Cuantas veces reintentar todo el arranque (puerto, passfile, spawn de
/// openvpn.exe nuevo) si un intento se queda colgado sin progresar tras el
/// hold release -- visto en la practica: desconectar y volver a conectar a
/// mano, repitiendo, a veces hacia falta varias veces antes de que un
/// intento fresco funcionase. Con esto la app hace ese mismo "reintentar
/// desde cero" sola en vez de que el usuario tenga que hacerlo a mano.
const MAX_CONNECT_ATTEMPTS: u32 = 4;

/// Cuanto esperar, tras el hold release, a que llegue el primer evento con
/// significado real (un `>STATE:` que no sea ruido, `>PASSWORD:`, etc.)
/// antes de dar el intento por colgado y empezar uno nuevo desde cero.
const ATTEMPT_STALL_TIMEOUT: Duration = Duration::from_secs(6);

/// Cuantos ficheros de log de conexion conservar como maximo bajo
/// `logs\connections\` (ver `open_connection_log_file`): sin limite se
/// acumulaba uno por cada intento de conexion para siempre.
const MAX_CONNECTION_LOG_FILES: usize = 10;

/// Cuantas veces reintentar una conexion entera (arranque + credenciales)
/// desde cero cuando el servidor rechaza la autenticacion, antes de dar el
/// fallo por definitivo y mostrarselo al usuario. Se ha visto en la
/// practica que el mismo usuario/contrasena, que el servidor VPN rechaza de
/// forma intermitente, funciona a los pocos segundos sin cambiar nada -- asi
/// que merece la pena reintentar solo antes de molestar al usuario.
const AUTH_FAILED_MAX_RETRIES: u32 = 3;

/// Espera entre cada reintento automatico tras un fallo de autenticacion
/// (ver `AUTH_FAILED_MAX_RETRIES`).
const AUTH_FAILED_RETRY_DELAY: Duration = Duration::from_secs(3);

async fn run_connection(
    profile: ProfileMeta,
    policy: SecurityPolicy,
    registry: Arc<CheckRegistry>,
    wmi: Arc<dyn WmiDataSource>,
    stored_credentials: Option<Credentials>,
    events: mpsc::UnboundedSender<AppEvent>,
    mut credentials_rx: mpsc::Receiver<Credentials>,
    mut cancel_rx: watch::Receiver<bool>,
) {
    let _ = events.send(AppEvent::ChecksStarted);

    let ctx = CheckContext { wmi };
    let pre_connect = run_pre_connect_checks(&policy, &registry, &ctx).await;
    for result in &pre_connect.results {
        let _ = events.send(AppEvent::CheckResult(result.clone()));
    }
    if pre_connect.blocks_connection() {
        // Sin anteponer el nombre tecnico del check (p.ej. "Antivirus activo
        // (Centro de seguridad de Windows): "): el motivo por si solo ya
        // esta pensado para el usuario final, y con un unico check activo
        // hoy ese prefijo solo anadia ruido al modal de error.
        let reasons: Vec<String> =
            pre_connect.blocking_failures().map(|r| outcome_reason(&r.outcome)).collect();
        let _ = events.send(AppEvent::ChecksFailed(reasons.join("; ")));
        return;
    }

    // Persistencia en disco del log de conexion (plan, seccion 6): la
    // ventana de log en vivo la alimenta el mismo evento, ver
    // `forward_raw_event`. Un solo fichero para todos los intentos de esta
    // sesion (incluidos los que se abandonan por colgados).
    let mut log_file = open_connection_log_file(profile.id);

    // Credenciales conocidas para toda la conexion (guardadas o pedidas al
    // usuario la primera vez que hagan falta): se recuerdan aqui, fuera del
    // bucle de abajo, para que un reintento automatico tras un fallo de
    // autenticacion (ver `AUTH_FAILED_MAX_RETRIES`) pueda reutilizarlas sin
    // volver a interrumpir al usuario.
    let mut credentials = stored_credentials;
    let mut auth_retries_left = AUTH_FAILED_MAX_RETRIES;

    let exit_reason = 'connection: loop {
        let mut attempt = 0u32;
        let (mut client, pid, passfile_path, mut tracker, first_status) = loop {
            attempt += 1;
            let last_state = if attempt == 1 {
                "STARTING".to_string()
            } else {
                format!("REINTENTANDO ({attempt}/{MAX_CONNECT_ATTEMPTS})")
            };
            let _ = events.send(AppEvent::Connecting { last_state });

            match start_one_attempt(&profile, &events, log_file.as_mut(), &mut cancel_rx).await {
                Ok(ready) => break ready,
                Err(AttemptError::Cancelled) => return,
                Err(AttemptError::Fatal(msg)) => {
                    let _ = events.send(AppEvent::Error(msg));
                    return;
                }
                Err(AttemptError::Stalled(msg)) if attempt < MAX_CONNECT_ATTEMPTS => {
                    tracing::warn!(attempt, error = %msg, "intento de conexion colgado, reintentando desde cero");
                    continue;
                }
                Err(AttemptError::Stalled(msg)) => {
                    let _ = events.send(AppEvent::Error(format!(
                        "no se pudo completar la conexion tras {MAX_CONNECT_ATTEMPTS} intentos: {msg}"
                    )));
                    return;
                }
            }
        };
        tracing::info!(attempt, "arranque completado, procesando eventos");

        let mut pending_credentials = credentials.clone();

        // El primer estado con significado real ya se obtuvo dentro de
        // start_one_attempt (es lo que confirma que el intento no esta
        // colgado); se procesa aqui igual que cualquier otro para no
        // duplicar la logica de abajo.
        let mut pending_first_status = Some(first_status);

        let reason = loop {
            if let Some(status) = pending_first_status.take() {
                if let Some(reason) = handle_status(
                    status,
                    &events,
                    &mut client,
                    &mut pending_credentials,
                    &mut credentials_rx,
                    log_file.as_mut(),
                    &mut tracker,
                )
                .await
                {
                    break reason;
                }
                continue;
            }
            tokio::select! {
                changed = cancel_rx.changed() => {
                    if changed.is_ok() && *cancel_rx.borrow() {
                        break ExitReason::Cancelled;
                    }
                }
                event = client.read_event() => {
                    tracing::info!(?event, "evento de la management interface");
                    match event {
                        Ok(Some(ev)) => {
                            forward_raw_event(&events, log_file.as_mut(), &ev);

                            let Some(status) = tracker.observe(&ev) else { continue };
                            if let Some(reason) = handle_status(
                                status,
                                &events,
                                &mut client,
                                &mut pending_credentials,
                                &mut credentials_rx,
                                log_file.as_mut(),
                                &mut tracker,
                            )
                            .await
                            {
                                break reason;
                            }
                        }
                        Ok(None) => break ExitReason::Eof,
                        Err(e) => {
                            let _ = events.send(AppEvent::Error(e.to_string()));
                            break ExitReason::Error;
                        }
                    }
                }
            }
        };

        credentials = pending_credentials;

        if !matches!(reason, ExitReason::Eof) {
            let _ = client.signal_sigterm().await;
            let closed_cleanly = drain_until_closed(&mut client, Duration::from_secs(5)).await;
            if !closed_cleanly {
                let _ = SvcClient::stop_profile(pid).await;
            }
        }
        let _ = std::fs::remove_file(&passfile_path);

        // Fallo de autenticacion: en la practica, un servidor VPN que
        // rechaza de forma intermitente las mismas credenciales validas
        // (visto con el Synology remoto de este proyecto) suele aceptarlas
        // a los pocos segundos sin que el usuario cambie nada -- se
        // reintenta solo, con las credenciales ya conocidas, antes de
        // molestarle con el modal de error.
        if matches!(reason, ExitReason::AuthFailed) && auth_retries_left > 0 {
            auth_retries_left -= 1;
            tracing::warn!(
                auth_retries_left,
                "fallo de autenticacion, reintentando automaticamente con las mismas credenciales"
            );
            let _ = events.send(AppEvent::Connecting {
                last_state: format!(
                    "Reintentando autenticacion ({}/{})",
                    AUTH_FAILED_MAX_RETRIES - auth_retries_left,
                    AUTH_FAILED_MAX_RETRIES
                ),
            });
            tokio::time::sleep(AUTH_FAILED_RETRY_DELAY).await;
            continue 'connection;
        }

        break reason;
    };

    if matches!(exit_reason, ExitReason::AuthFailed) {
        let _ = events.send(AppEvent::AuthFailed);
    }

    let _ = events.send(AppEvent::Disconnected);
}

/// Aplica un `ConnectionStatus` ya observado por el tracker: notifica a la
/// UI y, si corresponde, responde por la management interface (envio de
/// credenciales). Devuelve `Some(ExitReason)` cuando este estado termina la
/// conexion (fallo de auth, certificado, bucle de reconexion...).
/// Compartido entre el primer estado obtenido en `start_one_attempt` y el
/// bucle principal para no duplicar esta logica.
async fn handle_status(
    mut status: ConnectionStatus,
    events: &mpsc::UnboundedSender<AppEvent>,
    client: &mut ManagementClient,
    pending_credentials: &mut Option<Credentials>,
    credentials_rx: &mut mpsc::Receiver<Credentials>,
    mut log_file: Option<&mut File>,
    tracker: &mut ConnectionTracker,
) -> Option<ExitReason> {
    loop {
        match status {
            ConnectionStatus::Connecting { last_state } => {
                let _ = events.send(AppEvent::Connecting { last_state });
                return None;
            }
            ConnectionStatus::NeedsCredentials { context } => {
                // Solo se pide a la UI que muestre el formulario si no habia
                // credenciales guardadas para este perfil; si las habia, se
                // usan directamente sin interrumpir al usuario (plan,
                // seccion 6).
                let creds = match pending_credentials.take() {
                    Some(c) => c,
                    None => {
                        let _ = events.send(AppEvent::NeedsCredentials { context: context.clone() });
                        match credentials_rx.recv().await {
                            Some(c) => c,
                            None => return Some(ExitReason::Cancelled),
                        }
                    }
                };
                // Se guardan de vuelta (tanto si venian ya guardadas como
                // si se acaban de pedir al usuario): `run_connection` las
                // recuerda para el resto de la conexion, para no tener que
                // volver a pedirlas si hace falta un reintento automatico
                // tras un fallo de autenticacion (ver
                // `AUTH_FAILED_MAX_RETRIES`).
                *pending_credentials = Some(creds.clone());

                // Espaciados igual que los comandos de arranque (ver
                // `send_paced`): mandar "username" y "password" seguidos sin
                // leer nada entre medias resulto poco fiable tambien aqui
                // -- confirmado en el log tecnico de un caso real de este
                // problema: openvpn.exe se quedaba esperando credenciales
                // ("could not read Auth username/password/ok/string from
                // management interface") 28 segundos hasta que el usuario
                // desconectaba a mano, sin ningun aviso de error mientras
                // tanto.
                let mut next_status = None;
                for cmd in [
                    format!("username \"{context}\" {}", creds.username),
                    format!("password \"{context}\" {}", creds.password),
                ] {
                    match send_paced(client, &cmd, events, log_file.as_deref_mut(), tracker).await {
                        Ok(Some(s)) => {
                            next_status = Some(s);
                            break;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            let _ = events.send(AppEvent::Error(e.to_string()));
                            return Some(ExitReason::Error);
                        }
                    }
                }

                match next_status {
                    Some(s) => {
                        status = s;
                        continue;
                    }
                    None => return None,
                }
            }
            ConnectionStatus::Connected { local_ip, remote_ip } => {
                let _ = events.send(AppEvent::Connected { local_ip, remote_ip });
                return None;
            }
            ConnectionStatus::AuthFailed => {
                // `AppEvent::AuthFailed` (el modal de error) no se manda
                // aqui: `run_connection` decide si reintentar
                // automaticamente primero (ver `AUTH_FAILED_MAX_RETRIES`) y
                // solo lo manda si se agotan los reintentos.
                return Some(ExitReason::AuthFailed);
            }
            ConnectionStatus::CertificateError { detail } => {
                let _ = events.send(AppEvent::CertificateError(detail));
                return Some(ExitReason::CertificateError);
            }
            ConnectionStatus::ReconnectLoop { attempts } => {
                let _ = events.send(AppEvent::ReconnectLoop(attempts));
                return Some(ExitReason::ReconnectLoop);
            }
        }
    }
}

enum AttemptError {
    /// El usuario cancelo mientras este intento arrancaba.
    Cancelled,
    /// Error que no tiene sentido reintentar (perfil invalido, sin puerto
    /// libre...): se informa a la UI y se abandona la conexion entera.
    Fatal(String),
    /// El intento no llego a ningun estado con significado a tiempo (o el
    /// handshake con la management interface fallo): vale la pena tirarlo y
    /// empezar de cero con un `openvpn.exe` nuevo.
    Stalled(String),
}

/// Un intento completo de arrancar la conexion: pide un puerto y passfile
/// nuevos, le pide a `PorteroVPNSvc` que lance `openvpn.exe`, completa el
/// handshake de la management interface y espera al primer evento con
/// significado real (un estado, una peticion de credenciales...). Si nada
/// de eso llega dentro de `ATTEMPT_STALL_TIMEOUT`, se aborta este intento
/// (parando el proceso y borrando el passfile) para que el llamador pueda
/// reintentar desde cero -- ver `MAX_CONNECT_ATTEMPTS` y el incidente donde
/// desconectar/reconectar a mano varias veces acababa funcionando.
async fn start_one_attempt(
    profile: &ProfileMeta,
    events: &mpsc::UnboundedSender<AppEvent>,
    mut log_file: Option<&mut File>,
    cancel_rx: &mut watch::Receiver<bool>,
) -> Result<(ManagementClient, u32, PathBuf, ConnectionTracker, ConnectionStatus), AttemptError> {
    if *cancel_rx.borrow() {
        return Err(AttemptError::Cancelled);
    }

    let mgmt_port = pick_management_port().await.map_err(|e| AttemptError::Fatal(e.to_string()))?;

    let (passfile_path, passfile_secret) =
        generate_passfile().map_err(|e| AttemptError::Fatal(format!("no se pudo preparar la conexion: {e}")))?;

    let pid = match SvcClient::start_profile(
        &profile.stored_ovpn_path.to_string_lossy(),
        &passfile_path.to_string_lossy(),
        mgmt_port,
    )
    .await
    {
        Ok(pid) => pid,
        Err(e) => {
            let _ = std::fs::remove_file(&passfile_path);
            return Err(AttemptError::Fatal(e.to_string()));
        }
    };

    // Da tiempo a que openvpn.exe abra el socket de management antes de
    // intentar conectar.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let addr: SocketAddr = format!("127.0.0.1:{mgmt_port}").parse().expect("direccion local valida");
    let mut client = match connect_with_retry(addr, &passfile_secret).await {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(error = %e, "no se pudo completar el handshake con la management interface");
            let _ = SvcClient::stop_profile(pid).await;
            let _ = std::fs::remove_file(&passfile_path);
            return Err(AttemptError::Stalled(format!("no se pudo hablar con openvpn.exe: {e}")));
        }
    };
    tracing::info!("conectados a la management interface, activando notificaciones");

    let mut tracker = ConnectionTracker::new();

    // Mandar los comandos de arranque de golpe, sin leer nada entre medias,
    // resulto poco fiable: bajo carga, openvpn.exe a veces pierde o mezcla
    // la respuesta a alguno (visto: "state on all" sin respuesta, volcado
    // de log duplicado/incompleto, conexion colgada en "STARTING" para
    // siempre). Se manda cada comando y se espera a que termine de
    // responder (una ventana sin mas eventos) antes de mandar el siguiente.
    for cmd in ["state on all", "log on all", "bytecount 5", "hold release"] {
        match send_paced(&mut client, cmd, events, log_file.as_deref_mut(), &mut tracker).await {
            Ok(Some(status)) => return Ok((client, pid, passfile_path, tracker, status)),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(cmd, error = %e, "fallo espaciando los comandos de arranque");
                let _ = SvcClient::stop_profile(pid).await;
                let _ = std::fs::remove_file(&passfile_path);
                return Err(AttemptError::Stalled(e.to_string()));
            }
        }
    }
    tracing::info!("comandos de arranque enviados y drenados, esperando el primer evento con significado");

    let deadline = tokio::time::Instant::now() + ATTEMPT_STALL_TIMEOUT;

    loop {
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(mgmt_port, "intento colgado: sin eventos con significado tras el hold release");
            let _ = SvcClient::stop_profile(pid).await;
            let _ = std::fs::remove_file(&passfile_path);
            return Err(AttemptError::Stalled("openvpn.exe no respondio tras el hold release".to_string()));
        }

        tokio::select! {
            changed = cancel_rx.changed() => {
                if changed.is_ok() && *cancel_rx.borrow() {
                    let _ = SvcClient::stop_profile(pid).await;
                    let _ = std::fs::remove_file(&passfile_path);
                    return Err(AttemptError::Cancelled);
                }
            }
            result = tokio::time::timeout(Duration::from_millis(500), client.read_event()) => {
                match result {
                    Ok(Ok(Some(ev))) => {
                        tracing::info!(event = ?ev, "evento durante el arranque del intento");
                        forward_raw_event(events, log_file.as_deref_mut(), &ev);
                        if let Some(status) = tracker.observe(&ev) {
                            return Ok((client, pid, passfile_path, tracker, status));
                        }
                    }
                    Ok(Ok(None)) => {
                        let _ = std::fs::remove_file(&passfile_path);
                        return Err(AttemptError::Stalled("openvpn.exe cerro la conexion durante el arranque".to_string()));
                    }
                    Ok(Err(e)) => {
                        let _ = SvcClient::stop_profile(pid).await;
                        let _ = std::fs::remove_file(&passfile_path);
                        return Err(AttemptError::Stalled(e.to_string()));
                    }
                    // Timeout del poll de 500ms: vuelve a comprobar el deadline/cancelacion.
                    Err(_) => continue,
                }
            }
        }
    }
}

/// Cuanto silencio (sin eventos nuevos) hace falta tras un comando para
/// darlo por completamente respondido -- incluye tanto el "SUCCESS:"/
/// "ERROR:" inmediato como, para comandos tipo "... all", el volcado que le
/// sigue hasta su "END".
const COMMAND_QUIET_WINDOW: Duration = Duration::from_millis(300);

/// Manda un comando y espera a que termine de responder (una ventana sin
/// mas eventos) antes de devolver el control, reenviando cualquier evento
/// que llegue mientras tanto igual que el bucle principal. Si durante la
/// espera llega algo con significado real para el tracker (podria pasar si
/// un intento anterior dejo algo pendiente), se devuelve para que el
/// llamador lo trate como si fuera el primer estado de la conexion.
async fn send_paced(
    client: &mut ManagementClient,
    cmd: &str,
    events: &mpsc::UnboundedSender<AppEvent>,
    mut log_file: Option<&mut File>,
    tracker: &mut ConnectionTracker,
) -> io::Result<Option<ConnectionStatus>> {
    client.send_command(cmd).await?;
    loop {
        match tokio::time::timeout(COMMAND_QUIET_WINDOW, client.read_event()).await {
            Ok(Ok(Some(ev))) => {
                tracing::info!(cmd, event = ?ev, "evento espaciando comandos de arranque");
                forward_raw_event(events, log_file.as_deref_mut(), &ev);
                if let Some(status) = tracker.observe(&ev) {
                    return Ok(Some(status));
                }
                // Un `ERROR:` que el tracker no ha sabido traducir a un
                // estado con significado (p.ej. un fallo de credenciales,
                // que si lo traduce a `AuthFailed` arriba) es una respuesta
                // inesperada a `cmd`: visto en la practica, un eco tardio
                // de la contrasena del passfile puede colarse como
                // respuesta al primer comando mandado justo despues de
                // autenticarse, dejando ese comando (p.ej. "state on all")
                // sin confirmar de verdad aunque el resto de la conexion
                // siga adelante -- la app se quedaba para siempre en
                // "STARTING" pese a que la VPN llegaba a funcionar. Tratarlo
                // como fallo de este intento para que se reintente desde
                // cero es mas seguro que asumir que "ya se recupera solo".
                if let ManagementEvent::Error(msg) = &ev {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("respuesta inesperada de openvpn.exe a '{cmd}': {msg}"),
                    ));
                }
            }
            Ok(Ok(None)) => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "openvpn.exe cerro la conexion"));
            }
            Ok(Err(e)) => return Err(e),
            // Ventana de silencio: se considera la respuesta a este comando
            // completamente drenada.
            Err(_) => return Ok(None),
        }
    }
}

fn forward_raw_event(
    events: &mpsc::UnboundedSender<AppEvent>,
    log_file: Option<&mut File>,
    event: &ManagementEvent,
) {
    match event {
        ManagementEvent::Log(log) => {
            let _ = events.send(AppEvent::LogLine(log.text.clone()));
            if let Some(file) = log_file {
                let _ = writeln!(file, "{}", log.text);
            }
        }
        ManagementEvent::ByteCount { bytes_in, bytes_out } => {
            let _ = events.send(AppEvent::ByteCount { bytes_in: *bytes_in, bytes_out: *bytes_out });
        }
        _ => {}
    }
}

/// Abre (creandolo si hace falta) el fichero donde se persiste el log de
/// esta sesion de conexion, bajo `logs\connections\` (plan, seccion 4 y 6).
/// Si falla, la ventana de log en vivo sigue funcionando igual: solo se
/// pierde la persistencia en disco, no es motivo para abortar la conexion.
fn open_connection_log_file(profile_id: Uuid) -> Option<File> {
    if let Err(e) = storage::ensure_data_dirs() {
        tracing::warn!(error = %e, "no se pudo preparar el directorio de logs de conexion");
        return None;
    }

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let path = storage::connection_logs_dir().join(format!("{profile_id}-{timestamp}.log"));

    let file = match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => Some(file),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "no se pudo abrir el fichero de log de conexion");
            None
        }
    };

    // Un fichero por intento de conexion (incluidos los que se quedan
    // colgados y se abandonan, ver `MAX_CONNECT_ATTEMPTS`) hacia que este
    // directorio creciera sin limite. Se purga aqui, al crear uno nuevo, en
    // vez de en un hilo aparte: no hace falta mas que esto.
    storage::prune_connection_logs(MAX_CONNECTION_LOG_FILES);

    file
}

fn outcome_reason(outcome: &CheckOutcome) -> String {
    match outcome {
        CheckOutcome::Pass => "ok".to_string(),
        CheckOutcome::Fail { reason } => reason.clone(),
        CheckOutcome::Indeterminate { reason } => format!("no se pudo comprobar ({reason})"),
    }
}

async fn connect_with_retry(addr: SocketAddr, passfile_secret: &str) -> io::Result<ManagementClient> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match ManagementClient::connect(addr, Some(passfile_secret)).await {
            Ok(client) => return Ok(client),
            Err(e) if tokio::time::Instant::now() < deadline => {
                tracing::debug!(error = %e, "management interface aun no disponible, reintentando");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn drain_until_closed(client: &mut ManagementClient, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            match client.read_event().await {
                Ok(Some(_)) => continue,
                _ => return,
            }
        }
    })
    .await
    .is_ok()
}

async fn pick_management_port() -> io::Result<u16> {
    for port in 25340..25400u16 {
        if let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            drop(listener);
            return Ok(port);
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse, "no se encontro un puerto de management libre"))
}

/// Contrasena de un solo uso para el passfile de la management interface
/// (plan, seccion 3): evita que otro proceso local no relacionado se
/// conecte al puerto de management antes que la GUI.
fn generate_passfile() -> io::Result<(PathBuf, String)> {
    storage::ensure_data_dirs()?;
    let secret = SaltString::generate(&mut OsRng).to_string();
    let path = storage::run_dir().join(format!("{}.passfile", Uuid::new_v4()));
    std::fs::write(&path, &secret)?;
    Ok((path, secret))
}
