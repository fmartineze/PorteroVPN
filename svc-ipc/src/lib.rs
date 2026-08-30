//! Mensajes intercambiados por el named pipe entre la GUI de Portero VPN
//! (sesion de usuario, sin privilegios) y `PorteroVPNSvc` (LocalSystem).
//!
//! El servicio no interpreta perfiles .ovpn ni politica de seguridad: solo
//! sabe lanzar/matar procesos openvpn.exe con la ruta y el puerto de
//! management que la GUI ya decidio. La unica excepcion es
//! `QueryBitLocker`: una consulta de solo lectura que no puede resolver la
//! GUI por si misma porque el namespace WMI de BitLocker
//! (`root\cimv2\security\MicrosoftVolumeEncryption`) esta restringido por
//! defecto a Administradores, y la GUI corre deliberadamente sin privilegios
//! (ver `checks::bitlocker` en el crate principal). El servicio no decide si
//! esto bloquea la conexion -- solo informa del estado observado; esa
//! decision (obligatorio/no obligatorio) sigue viviendo en `policy.toml` y
//! el motor de checks de la GUI.

pub mod openvpn_path;
pub mod wireguard_path;

use serde::{Deserialize, Serialize};

/// Nombre del named pipe que expone `PorteroVPNSvc`.
pub const PIPE_NAME: &str = r"\\.\pipe\PorteroVPN\ctrl";

/// Nombre de registro del servicio en el Service Control Manager. Compartido
/// entre el servicio (que se registra con este nombre) y la GUI (que lo
/// consulta e instala/desinstala).
pub const SERVICE_NAME: &str = "PorteroVPNSvc";

/// Nombre de fichero del ejecutable del servicio, para que la GUI pueda
/// localizarlo junto a su propio `.exe` al instalar/reinstalar.
pub const SERVICE_EXE_NAME: &str = "portero-vpn-svc.exe";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Lanza `openvpn.exe --config <profile_path> --management 127.0.0.1
    /// <mgmt_port> <passfile_path> --management-hold
    /// --management-query-passwords --management-signal`.
    StartProfile {
        profile_path: String,
        passfile_path: String,
        mgmt_port: u16,
    },
    /// Termina el proceso identificado por `pid` (usado solo si el
    /// `signal SIGTERM` por management interface no surtio efecto a tiempo).
    StopProfile { pid: u32 },
    /// Comprobacion de vida del servicio (usada por la GUI al arrancar).
    Ping,
    /// Estado de BitLocker en el volumen de arranque -- ver comentario del
    /// modulo.
    QueryBitLocker,

    /// `wireguard.exe /installtunnelservice <config_path>`. WireGuard registra
    /// el tunel como servicio propio de Windows; no queda proceso hijo que
    /// vigilar, a diferencia de `StartProfile`.
    ///
    /// `config_path` apunta a un fichero temporal que la GUI acaba de
    /// materializar y borrara en cuanto el tunel este levantado: el `.conf`
    /// contiene la clave privada del par y no se guarda en claro (ver
    /// `ProfileMeta::config_blob` en el crate principal).
    StartWireGuardTunnel { config_path: String, tunnel_name: String },
    /// `wireguard.exe /uninstalltunnelservice <tunnel_name>`.
    StopWireGuardTunnel { tunnel_name: String },
    /// Estado del tunel: cuando fue el ultimo handshake y cuanto se ha
    /// transferido.
    ///
    /// Vive aqui por el mismo motivo que `QueryBitLocker`: el pipe de estado
    /// que expone cada tunel de WireGuard esta restringido a Administradores,
    /// y la GUI corre deliberadamente sin privilegios. El servicio solo
    /// informa de lo observado; interpretar si el tunel esta sano sigue siendo
    /// cosa de la GUI.
    QueryWireGuardStatus { tunnel_name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    Started { pid: u32 },
    Stopped,
    Pong,
    Error { message: String },
    BitLockerStatus(BitLockerVolumeStatus),
    WireGuardStarted,
    WireGuardStatus(WireGuardTunnelStatus),
}

/// Lo que el servicio observa de un tunel de WireGuard.
///
/// El dato que importa es `last_handshake_secs_ago`. WireGuard no tiene
/// sesion: no existe "conectado" como estado persistente, solo un handshake
/// que el protocolo renueva cada 120 s y da por muerto a los 180 s. Un
/// handshake reciente certifica que el tunel funciona **ahora**, que es mas de
/// lo que dice el `CONNECTED` de OpenVPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardTunnelStatus {
    /// Segundos desde el ultimo handshake. `None` si todavia no ha habido
    /// ninguno, que es lo normal justo despues de levantar el tunel: el
    /// handshake no ocurre al arrancar, sino cuando hay trafico que enviar.
    pub last_handshake_secs_ago: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl WireGuardTunnelStatus {
    /// A partir de aqui WireGuard descarta el tunel (`REJECT_AFTER_TIME`).
    pub const STALE_AFTER_SECS: u64 = 180;

    /// Si el tunel esta verificado ahora mismo.
    pub fn is_alive(&self) -> bool {
        self.last_handshake_secs_ago.is_some_and(|s| s < Self::STALE_AFTER_SECS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitLockerVolumeStatus {
    /// `ProtectionStatus` == 1: el volumen esta protegido.
    Protected,
    /// `ProtectionStatus` == 0 (nunca activado) o 2 (cifrando/descifrando
    /// todavia, protegido solo parcialmente).
    NotProtected,
    /// No existe el proveedor WMI de BitLocker en este equipo (tipico en
    /// Windows Home, donde BitLocker no esta disponible) o no se encontro
    /// el volumen de arranque -- se trata igual que "no protegido" a
    /// efectos de la comprobacion, no como un error de consulta.
    Unavailable,
}
