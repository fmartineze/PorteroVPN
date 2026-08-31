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

#[derive(Clone, Serialize, Deserialize)]
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

    /// Levanta un tunel de WireGuard. WireGuard lo registra como servicio
    /// propio de Windows; no queda proceso hijo que vigilar, a diferencia de
    /// `StartProfile`.
    ///
    /// Viaja el **contenido** del `.conf`, no una ruta, y lo escribe el
    /// servicio. Dos motivos, los dos aprendidos a base de fallo:
    ///
    /// 1. `wireguard.exe /installtunnelservice` **no se queda una copia** de la
    ///    configuracion: registra el servicio apuntando a la ruta que se le da
    ///    y la relee en cada arranque. El fichero tiene que sobrevivir al
    ///    tunel, asi que no puede ser un temporal que la GUI borre acto
    ///    seguido.
    /// 2. Ese fichero contiene la clave privada del par en claro. La GUI abre
    ///    permisos de `BUILTIN\Users` sobre todo su arbol de datos (ver
    ///    `storage::acl`), asi que escribirlo ahi lo dejaria al alcance de
    ///    cualquier usuario del equipo. Escribiendolo el servicio, va a un
    ///    directorio propio con permisos restringidos a SYSTEM y
    ///    Administradores.
    StartWireGuardTunnel { config: String, tunnel_name: String },
    /// `wireguard.exe /uninstalltunnelservice <tunnel_name>`.
    StopWireGuardTunnel { tunnel_name: String },
    /// Estado del tunel: cuando fue el ultimo handshake y cuanto se ha
    /// transferido.
    ///
    /// Vive aqui por el mismo motivo que `QueryBitLocker`: leer el estado de un
    /// tunel exige privilegios que la GUI no tiene a proposito. El servicio
    /// solo informa de lo observado; interpretar si el tunel esta sano sigue
    /// siendo cosa de la GUI.
    ///
    /// El estado se saca de `wg.exe show <nombre> dump`, **no de un named
    /// pipe**: WireGuard para Windows usa el driver WireGuardNT desde la 0.4 y
    /// no expone la UAPI por pipe (comprobado con un tunel corriendo -- ver
    /// `wireguard_path::locate_wg_exe`).
    QueryWireGuardStatus { tunnel_name: String },
}

/// `Debug` a mano, no derivado: la GUI y el servicio registran cada peticion
/// con `?request`, y un `.conf` de WireGuard contiene **siempre** la clave
/// privada del par. Con el derive, esa clave acababa en claro en
/// `portero-vpn.log`, que vive en un directorio legible por cualquier usuario
/// del equipo. Se redacta aqui, en el tipo, para que ningun sitio que registre
/// una peticion pueda filtrarla -- ni los que existen hoy ni los que se anadan.
impl std::fmt::Debug for IpcRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StartProfile { profile_path, passfile_path, mgmt_port } => f
                .debug_struct("StartProfile")
                .field("profile_path", profile_path)
                .field("passfile_path", passfile_path)
                .field("mgmt_port", mgmt_port)
                .finish(),
            Self::StopProfile { pid } => f.debug_struct("StopProfile").field("pid", pid).finish(),
            Self::Ping => f.write_str("Ping"),
            Self::QueryBitLocker => f.write_str("QueryBitLocker"),
            Self::StartWireGuardTunnel { tunnel_name, .. } => f
                .debug_struct("StartWireGuardTunnel")
                .field("tunnel_name", tunnel_name)
                .field("config", &"<redactado: contiene la clave privada>")
                .finish(),
            Self::StopWireGuardTunnel { tunnel_name } => {
                f.debug_struct("StopWireGuardTunnel").field("tunnel_name", tunnel_name).finish()
            }
            Self::QueryWireGuardStatus { tunnel_name } => {
                f.debug_struct("QueryWireGuardStatus").field("tunnel_name", tunnel_name).finish()
            }
        }
    }
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
