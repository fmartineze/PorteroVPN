//! Cliente named pipe hacia `PorteroVPNSvc`: la GUI solo le pide
//! "arranca este proceso" / "mata este pid" (plan, seccion 1). Todo lo
//! demas (credenciales, estado, log) se habla directamente con la
//! management interface una vez el proceso vive.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::time::{self, Instant};

use svc_ipc::{IpcRequest, IpcResponse, PIPE_NAME};

const ERROR_PIPE_BUSY: i32 = 231;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Cuanto esperar la respuesta del servicio una vez conectados y enviada la
/// peticion. Sin este limite, si el servicio acepta la conexion pero nunca
/// responde (bug o cuelgue en su lado), la GUI se queda esperando para
/// siempre en `read_line` y la UI parece congelada en "Conectando" sin dar
/// ninguna pista de por que (incidente: log de conexion vacio, passfile sin
/// borrar).
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum SvcClientError {
    #[error("no se pudo hablar con PorteroVPNSvc: {0}")]
    Io(#[from] io::Error),
    #[error("respuesta inesperada del servicio: {0:?}")]
    UnexpectedResponse(IpcResponse),
    #[error("el servicio devolvio un error: {0}")]
    ServiceError(String),
    #[error(
        "no se pudo conectar con el servicio PorteroVPNSvc a tiempo. \
         Puede que no este instalado o no haya arrancado."
    )]
    Timeout,
    #[error(
        "PorteroVPNSvc acepto la conexion pero no respondio a tiempo. \
         Puede estar bloqueado; prueba a reiniciar el servicio desde Configuracion."
    )]
    ResponseTimeout,
}

pub struct SvcClient;

impl SvcClient {
    pub async fn ping() -> Result<(), SvcClientError> {
        match send_request(IpcRequest::Ping).await? {
            IpcResponse::Pong => Ok(()),
            IpcResponse::Error { message } => Err(SvcClientError::ServiceError(message)),
            other => Err(SvcClientError::UnexpectedResponse(other)),
        }
    }

    pub async fn start_profile(
        profile_path: &str,
        passfile_path: &str,
        mgmt_port: u16,
    ) -> Result<u32, SvcClientError> {
        let request = IpcRequest::StartProfile {
            profile_path: profile_path.to_string(),
            passfile_path: passfile_path.to_string(),
            mgmt_port,
        };
        match send_request(request).await? {
            IpcResponse::Started { pid } => Ok(pid),
            IpcResponse::Error { message } => Err(SvcClientError::ServiceError(message)),
            other => Err(SvcClientError::UnexpectedResponse(other)),
        }
    }

    pub async fn stop_profile(pid: u32) -> Result<(), SvcClientError> {
        match send_request(IpcRequest::StopProfile { pid }).await? {
            IpcResponse::Stopped => Ok(()),
            IpcResponse::Error { message } => Err(SvcClientError::ServiceError(message)),
            other => Err(SvcClientError::UnexpectedResponse(other)),
        }
    }

    /// Ver `svc_ipc::IpcRequest::QueryBitLocker`: el servicio (LocalSystem)
    /// consulta WMI porque ese namespace esta restringido a Administradores
    /// y la GUI corre sin privilegios a proposito.
    pub async fn query_bitlocker() -> Result<svc_ipc::BitLockerVolumeStatus, SvcClientError> {
        match send_request(IpcRequest::QueryBitLocker).await? {
            IpcResponse::BitLockerStatus(status) => Ok(status),
            IpcResponse::Error { message } => Err(SvcClientError::ServiceError(message)),
            other => Err(SvcClientError::UnexpectedResponse(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No forma parte de `cargo test` normal: depende de que `PorteroVPNSvc`
    /// este instalado y corriendo de verdad en la maquina donde se ejecute
    /// (`cargo test -- --ignored --nocapture`), para contrastar contra
    /// `manage-bde -status C:` a mano.
    #[tokio::test]
    #[ignore = "depende de PorteroVPNSvc corriendo de verdad en esta maquina"]
    async fn real_query_bitlocker_matches_actual_state() {
        let status = SvcClient::query_bitlocker().await.expect("consulta real a PorteroVPNSvc fallo");
        println!("bitlocker status = {status:?}");
    }
}

async fn send_request(request: IpcRequest) -> Result<IpcResponse, SvcClientError> {
    tracing::info!(?request, "conectando con PorteroVPNSvc");
    let client = connect_with_retry().await?;
    let (read_half, mut write_half) = tokio::io::split(client);
    let mut reader = BufReader::new(read_half);

    let mut payload = serde_json::to_string(&request).expect("IpcRequest siempre serializable");
    payload.push('\n');
    write_half.write_all(payload.as_bytes()).await?;
    write_half.flush().await?;
    tracing::info!("peticion enviada a PorteroVPNSvc, esperando respuesta");

    let mut line = String::new();
    match time::timeout(RESPONSE_TIMEOUT, reader.read_line(&mut line)).await {
        Err(_) => {
            tracing::warn!("PorteroVPNSvc no respondio dentro de RESPONSE_TIMEOUT");
            return Err(SvcClientError::ResponseTimeout);
        }
        Ok(read_result) => {
            read_result?;
        }
    }
    if line.is_empty() {
        return Err(SvcClientError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "el servicio cerro el pipe")));
    }
    tracing::info!(response = %line.trim_end(), "respuesta recibida de PorteroVPNSvc");
    serde_json::from_str(line.trim_end())
        .map_err(|e| SvcClientError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))
}

/// El servicio puede tardar un instante en tener una instancia del pipe
/// lista tras (re)arrancar; se reintenta brevemente en vez de fallar de
/// inmediato con `ERROR_PIPE_BUSY`.
async fn connect_with_retry() -> Result<tokio::net::windows::named_pipe::NamedPipeClient, SvcClientError> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                if Instant::now() >= deadline {
                    return Err(SvcClientError::Timeout);
                }
                time::sleep(Duration::from_millis(100)).await;
            }
            Err(_) if Instant::now() < deadline => {
                time::sleep(Duration::from_millis(200)).await;
            }
            Err(_) => return Err(SvcClientError::Timeout),
        }
    }
}
