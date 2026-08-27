//! Driver de I/O sobre la management interface: conecta al socket TCP local
//! que expone `openvpn.exe`, envia comandos y entrega los eventos ya
//! parseados (ver `mgmt::protocol`).

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use super::protocol::{parse_line, ManagementEvent};

pub struct ManagementClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    /// Puerto local efimero de esta conexion concreta: se incluye en cada
    /// linea de traza para poder distinguir, si hiciera falta, entre
    /// conexiones/intentos distintos que se solaparan en el tiempo.
    local_port: u16,
}

impl ManagementClient {
    /// Conecta a `127.0.0.1:<puerto>` y, si el proceso se arranco con un
    /// passfile (ver plan, seccion 3), completa el intercambio de
    /// autenticacion inicial antes de devolver el cliente listo para usar.
    pub async fn connect(addr: SocketAddr, passfile_password: Option<&str>) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
        let (read_half, write_half) = stream.into_split();
        let mut client = Self { reader: BufReader::new(read_half), writer: write_half, local_port };

        if let Some(password) = passfile_password {
            client.wait_for_enter_password_prompt().await?;
            client.write_line(password).await?;

            // Verificar explicitamente la respuesta a la contrasena (en vez
            // de asumir que fue aceptada y seguir adelante a ciegas): si
            // openvpn.exe no la reconoce como tal -se ha visto, en raras
            // ocasiones, que la trata como un comando normal y responde
            // "unknown command"-, tratarlo como fallo de conexion para que
            // el bucle de reintento en `connect_with_retry` lo intente de
            // nuevo con una conexion nueva, en vez de dejar la sesion en un
            // estado inconsistente sin que la UI se entere.
            match client.read_event().await? {
                Some(ManagementEvent::Success(_)) => {}
                Some(other) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("la management interface no acepto la contrasena (respuesta: {other:?})"),
                    ));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "conexion cerrada justo despues de enviar la contrasena",
                    ));
                }
            }

            // Un margen tras aceptar la contrasena antes de mandar el
            // primer comando de verdad: mandarlo a los pocos microsegundos
            // de recibir el "SUCCESS: password is correct" (como hacia
            // antes, sin esperar nada aqui) resulto en que openvpn.exe, en
            // ocasiones, respondia a ESE primer comando con un eco tardio
            // de la contrasena tratada como "unknown command" -- confirmado
            // en el log tecnico de un caso real: `state on all` nunca
            // llegaba a confirmarse ("SUCCESS: real-time state notification
            // set to ON" no aparecia en todo el log de esa sesion), asi que
            // la app se quedaba para siempre en "STARTING" aunque el resto
            // de la conexion (via `log on all`, que si sobrevivia) se
            // completara con normalidad y la VPN funcionara de verdad. Da
            // la impresion de ser una ventana de carrera del lado de
            // openvpn.exe justo al pasar de "leyendo la contrasena" a
            // "parseando comandos normales"; este margen evita disparar esa
            // ventana en vez de intentar detectarla despues.
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }

        Ok(client)
    }

    /// El prompt `ENTER PASSWORD:` que pide openvpn.exe al proteger la
    /// management interface con un passfile se manda SIN salto de linea (es
    /// un prompt interactivo, no un mensaje de una linea como el resto del
    /// protocolo) -- comprobado hablando a mano con un `openvpn.exe` real.
    /// Usar `read_line`/`read_event` aqui se queda esperando para siempre un
    /// '\n' que nunca llega (incidente: conexion colgada en "Conectando",
    /// log de conexion vacio). Por eso se leen bytes crudos hasta reconocer
    /// el texto exacto del prompt.
    async fn wait_for_enter_password_prompt(&mut self) -> io::Result<()> {
        const PROMPT: &[u8] = b"ENTER PASSWORD:";
        let mut seen = Vec::with_capacity(PROMPT.len());
        let mut discarded: Vec<u8> = Vec::new();
        let mut byte = [0u8; 1];
        let mut total = 0u32;
        loop {
            let n = self.reader.read(&mut byte).await?;
            if n == 0 {
                tracing::warn!(
                    total,
                    discarded = %String::from_utf8_lossy(&discarded),
                    "EOF esperando el prompt ENTER PASSWORD:"
                );
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "conexion cerrada durante el handshake"));
            }
            total += 1;
            seen.push(byte[0]);
            if seen.len() > PROMPT.len() {
                discarded.push(seen.remove(0));
            }
            if seen == PROMPT {
                tracing::info!(total, discarded = %String::from_utf8_lossy(&discarded), "prompt ENTER PASSWORD: detectado");
                return Ok(());
            }
        }
    }

    /// Lee la siguiente linea del socket y la parsea. `Ok(None)` significa
    /// que el otro extremo cerro la conexion (EOF).
    pub async fn read_event(&mut self) -> io::Result<Option<ManagementEvent>> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        tracing::info!(local_port = self.local_port, raw = %line.trim_end(), "RAW recibido");
        Ok(Some(parse_line(&line)))
    }

    async fn write_line(&mut self, line: &str) -> io::Result<()> {
        tracing::info!(local_port = self.local_port, raw = %line, "RAW enviado");
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await
    }

    /// Envia una linea de comando cruda. Publico para que el llamador pueda
    /// espaciar los comandos con sus propias lecturas entre medias (ver
    /// `connection::send_paced`) en vez de mandar varios seguidos sin leer
    /// nada -- eso se probo poco fiable: `openvpn.exe`, bajo carga, a veces
    /// pierde o mezcla la respuesta a alguno de los comandos si llegan
    /// demasiado seguidos (incidente: `state on all` sin respuesta, volcado
    /// de log duplicado/incompleto, "STARTING" colgado).
    pub async fn send_command(&mut self, line: &str) -> io::Result<()> {
        self.write_line(line).await
    }

    /// Cierre limpio: ver plan, seccion 3. El llamador es responsable de
    /// esperar despues a que el proceso `openvpn.exe` termine, con timeout.
    pub async fn signal_sigterm(&mut self) -> io::Result<()> {
        self.write_line("signal SIGTERM").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// Monta un "servidor OpenVPN falso" en un puerto efimero y guioniza la
    /// secuencia de lineas que envia, replicando el flujo de exito descrito
    /// en el plan (seccion 3): sin depender de un binario openvpn.exe real
    /// ni de red externa.
    async fn fake_server(listener: TcpListener, script: Vec<&'static str>) {
        let (stream, _) = listener.accept().await.expect("no llego conexion");
        let (read_half, mut write_half) = stream.into_split();

        for line in script {
            write_half.write_all(line.as_bytes()).await.expect("fallo al escribir");
            write_half.write_all(b"\n").await.expect("fallo al escribir salto de linea");
        }

        // Mantiene la conexion viva brevemente para poder leer comandos del
        // cliente (p.ej. signal SIGTERM) en los tests que lo necesiten.
        let mut buf = [0u8; 256];
        let mut reader = read_half;
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), reader.read(&mut buf)).await;
    }

    #[tokio::test]
    async fn drives_successful_connection_sequence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fallo");
        let addr = listener.local_addr().unwrap();

        let script = vec![
            ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info",
            ">STATE:1700000000,CONNECTING,,,,,,",
            ">STATE:1700000001,WAIT,,,,,,",
            ">STATE:1700000002,AUTH,,,,,,",
            ">PASSWORD:Need 'Auth' username/password",
            "SUCCESS: 'Auth' username entered",
            "SUCCESS: 'Auth' password entered",
            ">STATE:1700000003,GET_CONFIG,,,,,,",
            ">STATE:1700000004,ASSIGN_IP,,,,,,",
            ">STATE:1700000005,ADD_ROUTES,,,,,,",
            ">STATE:1700000006,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,,",
        ];
        tokio::spawn(fake_server(listener, script));

        let mut client = ManagementClient::connect(addr, None).await.expect("connect fallo");

        use crate::mgmt::protocol::{ConnectionStatus, ConnectionTracker};
        let mut tracker = ConnectionTracker::new();
        let mut final_status = None;

        while let Some(event) = client.read_event().await.expect("read fallo") {
            if let ManagementEvent::PasswordRequest { context } = &event {
                client.send_command(&format!("username \"{context}\" usuario")).await.expect("username fallo");
                client.send_command(&format!("password \"{context}\" secreto")).await.expect("password fallo");
            }
            if let Some(status) = tracker.observe(&event) {
                final_status = Some(status);
            }
        }

        assert_eq!(
            final_status,
            Some(ConnectionStatus::Connected {
                local_ip: Some("10.8.0.2".into()),
                remote_ip: Some("203.0.113.5".into()),
            })
        );
    }

    #[tokio::test]
    async fn detects_auth_failed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fallo");
        let addr = listener.local_addr().unwrap();

        let script = vec![
            ">STATE:1700000000,AUTH,,,,,,",
            ">LOG:1700000001,,AUTH_FAILED",
        ];
        tokio::spawn(fake_server(listener, script));

        let mut client = ManagementClient::connect(addr, None).await.expect("connect fallo");

        use crate::mgmt::protocol::{ConnectionStatus, ConnectionTracker};
        let mut tracker = ConnectionTracker::new();
        let mut final_status = None;

        while let Some(event) = client.read_event().await.expect("read fallo") {
            if let Some(status) = tracker.observe(&event) {
                final_status = Some(status);
            }
        }

        assert_eq!(final_status, Some(ConnectionStatus::AuthFailed));
    }

    #[tokio::test]
    async fn connect_with_passfile_sends_password_first() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fallo");
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("no llego conexion");
            let (read_half, mut write_half) = stream.into_split();
            // Sin salto de linea: asi es como lo manda openvpn.exe de verdad.
            write_half.write_all(b"ENTER PASSWORD:").await.expect("fallo al escribir prompt");

            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("no se recibio la contrasena");
            assert_eq!(line.trim_end(), "el-passfile-secreto");

            write_half
                .write_all(b"SUCCESS: password is correct\n")
                .await
                .expect("fallo al confirmar la contrasena");
        });

        let _client = ManagementClient::connect(addr, Some("el-passfile-secreto"))
            .await
            .expect("connect con passfile fallo");
    }
}
