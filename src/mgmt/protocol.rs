//! Parser de la management interface de OpenVPN y maquina de estados que
//! traduce sus eventos en un estado de conexion de alto nivel.
//!
//! Logica pura, sin I/O: se testea por completo con lineas de texto
//! sintetizadas, sin necesitar un `openvpn.exe` real ni red (ver plan de
//! arquitectura, seccion 11).

/// Un evento tal como llega, ya tokenizado, de una linea de la management
/// interface. Ver plan, seccion 3, para el formato de cada uno.
#[derive(Debug, Clone, PartialEq)]
pub enum ManagementEvent {
    Info(String),
    State(StateEvent),
    /// El servidor de management pide credenciales para el contexto dado
    /// (normalmente "Auth"), via `>PASSWORD:Need '<context>' username/password`.
    PasswordRequest { context: String },
    Log(LogEvent),
    ByteCount { bytes_in: u64, bytes_out: u64 },
    Hold(String),
    Success(String),
    Error(String),
    /// El servidor rechazo las credenciales del contexto dado, via
    /// `>PASSWORD:Verification Failed:'<context>'`.
    ///
    /// Tiene variante propia en vez de viajar dentro de `Error(String)`
    /// porque `ConnectionTracker::observe` necesita reconocerlo para emitir
    /// `ConnectionStatus::AuthFailed`. Cuando era un `Error` con texto
    /// sintetizado, esa deteccion se hacia buscando una subcadena en
    /// castellano dentro del mensaje -- lo que ataba una decision de control
    /// al idioma de la interfaz y se habria roto en silencio al traducirla.
    /// El texto que ve el usuario se compone ahora en la UI.
    AuthVerificationFailed { context: String },
    /// El servidor pide la contraseña del passfile de management
    /// (`ENTER PASSWORD:`), previa a cualquier otro intercambio.
    EnterPassword,
    /// Cualquier linea reconocida como valida pero sin manejo especifico.
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateEvent {
    pub timestamp: i64,
    /// CONNECTING, WAIT, AUTH, GET_CONFIG, ASSIGN_IP, ADD_ROUTES, CONNECTED,
    /// RECONNECTING, EXITING, RESOLVE, TCP_CONNECT, ...
    pub name: String,
    /// Para CONNECTED normalmente "SUCCESS"; para RECONNECTING/EXITING, el
    /// motivo.
    pub detail: String,
    pub local_ip: Option<String>,
    pub remote_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    pub timestamp: i64,
    pub flags: String,
    pub text: String,
}

/// Parsea una linea cruda (sin salto de linea final) recibida de la
/// management interface.
pub fn parse_line(raw_line: &str) -> ManagementEvent {
    let line = raw_line.trim_end_matches(['\r', '\n']);

    if let Some(rest) = line.strip_prefix(">INFO:") {
        return ManagementEvent::Info(rest.to_string());
    }
    if let Some(rest) = line.strip_prefix(">STATE:") {
        return ManagementEvent::State(parse_state(rest));
    }
    if let Some(rest) = line.strip_prefix(">PASSWORD:") {
        return parse_password(rest);
    }
    if let Some(rest) = line.strip_prefix(">LOG:") {
        return ManagementEvent::Log(parse_log(rest));
    }
    if let Some(rest) = line.strip_prefix(">BYTECOUNT:") {
        return parse_bytecount(rest);
    }
    if let Some(rest) = line.strip_prefix(">HOLD:") {
        return ManagementEvent::Hold(rest.to_string());
    }
    if let Some(rest) = line.strip_prefix("SUCCESS:") {
        return ManagementEvent::Success(rest.trim().to_string());
    }
    if let Some(rest) = line.strip_prefix("ERROR:") {
        return ManagementEvent::Error(rest.trim().to_string());
    }
    if line.starts_with("ENTER PASSWORD:") {
        return ManagementEvent::EnterPassword;
    }

    ManagementEvent::Other(line.to_string())
}

fn parse_state(rest: &str) -> StateEvent {
    let fields: Vec<&str> = rest.split(',').collect();
    let timestamp = fields.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let name = fields.get(1).copied().unwrap_or("").to_string();
    let detail = fields.get(2).copied().unwrap_or("").to_string();
    let local_ip = fields
        .get(3)
        .copied()
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let remote_ip = fields
        .get(4)
        .copied()
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    StateEvent { timestamp, name, detail, local_ip, remote_ip }
}

fn parse_password(rest: &str) -> ManagementEvent {
    let context = rest
        .find('\'')
        .and_then(|start| {
            rest[start + 1..]
                .find('\'')
                .map(|end| rest[start + 1..start + 1 + end].to_string())
        });

    match context {
        Some(context) if rest.contains("Verification Failed") => {
            ManagementEvent::AuthVerificationFailed { context }
        }
        Some(context) => ManagementEvent::PasswordRequest { context },
        None => ManagementEvent::Other(format!(">PASSWORD:{rest}")),
    }
}

fn parse_log(rest: &str) -> LogEvent {
    let mut parts = rest.splitn(3, ',');
    let timestamp = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let flags = parts.next().unwrap_or("").to_string();
    let text = parts.next().unwrap_or("").to_string();
    LogEvent { timestamp, flags, text }
}

fn parse_bytecount(rest: &str) -> ManagementEvent {
    let mut parts = rest.split(',');
    let bytes_in = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let bytes_out = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    ManagementEvent::ByteCount { bytes_in, bytes_out }
}

/// Estado de conexion de alto nivel derivado de la secuencia de eventos de
/// management, tal como lo consume la UI (ver plan, secciones 6 y 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    Connecting { last_state: String },
    NeedsCredentials { context: String },
    Connected { local_ip: Option<String>, remote_ip: Option<String> },
    AuthFailed,
    ReconnectLoop { attempts: u32 },
    CertificateError { detail: String },
}

/// Numero de estados RECONNECTING consecutivos (sin un CONNECTED de por
/// medio) a partir del cual se considera que el servidor esta rechazando la
/// conexion en bucle. Simplificacion pragmatica de la "ventana de tiempo
/// corta" descrita en el plan: contar reintentos consecutivos evita
/// depender de reloj de pared y es suficiente para el MVP.
const RECONNECT_LOOP_THRESHOLD: u32 = 3;

/// Consume eventos de management en orden y mantiene el estado de conexion
/// derivado. No hace I/O: se alimenta desde `mgmt::client` o desde tests.
#[derive(Debug, Default)]
pub struct ConnectionTracker {
    reconnect_count: u32,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Devuelve el nuevo estado de conexion derivado de este evento, si el
    /// evento aporta informacion de estado relevante para la UI.
    pub fn observe(&mut self, event: &ManagementEvent) -> Option<ConnectionStatus> {
        match event {
            ManagementEvent::State(state) => self.observe_state(state),
            ManagementEvent::PasswordRequest { context } => {
                Some(ConnectionStatus::NeedsCredentials { context: context.clone() })
            }
            ManagementEvent::Log(log) => self.observe_log(log),
            ManagementEvent::AuthVerificationFailed { .. } => Some(ConnectionStatus::AuthFailed),
            _ => None,
        }
    }

    fn observe_state(&mut self, state: &StateEvent) -> Option<ConnectionStatus> {
        match state.name.as_str() {
            "CONNECTED" if state.detail == "SUCCESS" => {
                self.reconnect_count = 0;
                Some(ConnectionStatus::Connected {
                    local_ip: state.local_ip.clone(),
                    remote_ip: state.remote_ip.clone(),
                })
            }
            "RECONNECTING" => {
                self.reconnect_count += 1;
                if self.reconnect_count >= RECONNECT_LOOP_THRESHOLD {
                    Some(ConnectionStatus::ReconnectLoop { attempts: self.reconnect_count })
                } else {
                    Some(ConnectionStatus::Connecting { last_state: state.name.clone() })
                }
            }
            other => Some(ConnectionStatus::Connecting { last_state: other.to_string() }),
        }
    }

    fn observe_log(&mut self, log: &LogEvent) -> Option<ConnectionStatus> {
        if log.text.contains("AUTH_FAILED") {
            return Some(ConnectionStatus::AuthFailed);
        }
        if log.text.contains("TLS_ERROR") || log.text.contains("VERIFY ERROR") {
            return Some(ConnectionStatus::CertificateError { detail: log.text.clone() });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_info_banner() {
        assert_eq!(
            parse_line(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info"),
            ManagementEvent::Info("OpenVPN Management Interface Version 5 -- type 'help' for more info".into())
        );
    }

    #[test]
    fn parses_connected_state_with_ips() {
        let event = parse_line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,,");
        assert_eq!(
            event,
            ManagementEvent::State(StateEvent {
                timestamp: 1700000000,
                name: "CONNECTED".into(),
                detail: "SUCCESS".into(),
                local_ip: Some("10.8.0.2".into()),
                remote_ip: Some("203.0.113.5".into()),
            })
        );
    }

    #[test]
    fn parses_password_request() {
        assert_eq!(
            parse_line(">PASSWORD:Need 'Auth' username/password"),
            ManagementEvent::PasswordRequest { context: "Auth".into() }
        );
    }

    #[test]
    fn parses_verification_failed_as_auth_event() {
        assert_eq!(
            parse_line(">PASSWORD:Verification Failed: 'Auth'"),
            ManagementEvent::AuthVerificationFailed { context: "Auth".into() }
        );
    }

    /// El fallo de credenciales debe llegar a la UI por la forma del evento,
    /// nunca por el texto que lo acompana: ese acoplamiento existio y se
    /// habria roto en silencio al traducir la interfaz.
    #[test]
    fn auth_verification_failed_becomes_auth_failed_status() {
        let mut tracker = ConnectionTracker::default();
        let event = ManagementEvent::AuthVerificationFailed { context: "Auth".into() };
        assert_eq!(tracker.observe(&event), Some(ConnectionStatus::AuthFailed));
    }

    #[test]
    fn parses_log_line_with_commas_in_text() {
        assert_eq!(
            parse_line(">LOG:1700000000,I,TLS: Initial packet from [AF_INET]203.0.113.5:1194, sid=abc123"),
            ManagementEvent::Log(LogEvent {
                timestamp: 1700000000,
                flags: "I".into(),
                text: "TLS: Initial packet from [AF_INET]203.0.113.5:1194, sid=abc123".into(),
            })
        );
    }

    #[test]
    fn parses_bytecount() {
        assert_eq!(
            parse_line(">BYTECOUNT:1024,2048"),
            ManagementEvent::ByteCount { bytes_in: 1024, bytes_out: 2048 }
        );
    }

    #[test]
    fn parses_enter_password_prompt() {
        assert_eq!(parse_line("ENTER PASSWORD:"), ManagementEvent::EnterPassword);
    }

    #[test]
    fn unknown_line_is_other() {
        assert_eq!(parse_line("something unexpected"), ManagementEvent::Other("something unexpected".into()));
    }

    #[test]
    fn tracker_reports_connected_on_success_state() {
        let mut tracker = ConnectionTracker::new();
        let event = parse_line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,,");
        assert_eq!(
            tracker.observe(&event),
            Some(ConnectionStatus::Connected {
                local_ip: Some("10.8.0.2".into()),
                remote_ip: Some("203.0.113.5".into()),
            })
        );
    }

    #[test]
    fn tracker_reports_auth_failed_from_log() {
        let mut tracker = ConnectionTracker::new();
        let event = parse_line(">LOG:1700000000,,AUTH_FAILED");
        assert_eq!(tracker.observe(&event), Some(ConnectionStatus::AuthFailed));
    }

    #[test]
    fn tracker_reports_certificate_error_from_log() {
        let mut tracker = ConnectionTracker::new();
        let event = parse_line(">LOG:1700000000,,VERIFY ERROR: depth=0, error=certificate has expired");
        assert!(matches!(tracker.observe(&event), Some(ConnectionStatus::CertificateError { .. })));
    }

    #[test]
    fn tracker_reports_reconnect_loop_after_threshold() {
        let mut tracker = ConnectionTracker::new();
        let reconnecting = parse_line(">STATE:1700000000,RECONNECTING,tls-error,,,,,");

        let mut last = None;
        for _ in 0..RECONNECT_LOOP_THRESHOLD {
            last = tracker.observe(&reconnecting);
        }

        assert_eq!(last, Some(ConnectionStatus::ReconnectLoop { attempts: RECONNECT_LOOP_THRESHOLD }));
    }

    #[test]
    fn tracker_resets_reconnect_count_after_success() {
        let mut tracker = ConnectionTracker::new();
        let reconnecting = parse_line(">STATE:1700000000,RECONNECTING,tls-error,,,,,");
        let connected = parse_line(">STATE:1700000001,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,,");

        tracker.observe(&reconnecting);
        tracker.observe(&reconnecting);
        tracker.observe(&connected);

        // Tras el reset, hacen falta de nuevo RECONNECT_LOOP_THRESHOLD eventos.
        let mut last = None;
        for _ in 0..RECONNECT_LOOP_THRESHOLD - 1 {
            last = tracker.observe(&reconnecting);
        }
        assert!(!matches!(last, Some(ConnectionStatus::ReconnectLoop { .. })));
    }

    #[test]
    fn tracker_reports_needs_credentials() {
        let mut tracker = ConnectionTracker::new();
        let event = parse_line(">PASSWORD:Need 'Auth' username/password");
        assert_eq!(tracker.observe(&event), Some(ConnectionStatus::NeedsCredentials { context: "Auth".into() }));
    }
}
