//! Comprobacion de que Windows tiene alguna proteccion antivirus activa, via
//! WMI (`root\SecurityCenter2`, clase `AntiVirusProduct`) -- el mismo
//! catalogo que usa la propia app "Seguridad de Windows" para su semaforo de
//! estado, asi que cubre tanto Windows Defender como cualquier antivirus de
//! terceros que se haya registrado en el (McAfee, Norton, Bitdefender...).
//! Antes esta comprobacion consultaba `root\Microsoft\Windows\Defender`
//! directamente, lo que la hacia fallar en maquinas donde Defender esta
//! desactivado porque otro antivirus ya se encarga de la proteccion en
//! tiempo real (Windows hace eso automaticamente al detectar un tercero).
//!
//! Se consulta en la sesion del usuario (nunca en sesion 0/SYSTEM), que es
//! precisamente el motivo de que esta herramienta exista en vez de un script
//! de OpenVPN GUI (ver plan, Contexto).

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use wmi::{COMLibrary, WMIConnection};

use crate::i18n::{t, Msg};
use super::{Check, CheckContext, CheckOutcome, RetryPolicy, WmiDataSource, WmiError};

const SECURITY_CENTER_NAMESPACE: &str = r"root\SecurityCenter2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntivirusStatus {
    pub real_time_protection_enabled: bool,
}

/// Los nombres de propiedad de `root\SecurityCenter2` van en camelCase (a
/// diferencia de la mayoria de clases WMI, que usan PascalCase) -- asi los
/// documenta Microsoft para esta clase en concreto.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAntiVirusProduct {
    product_state: u32,
}

/// Implementacion real de `WmiDataSource` sobre el crate `wmi` (COM). Las
/// llamadas COM son sincronas, por lo que se ejecutan en un hilo bloqueante
/// dedicado (`spawn_blocking`) para no bloquear el runtime de tokio.
pub struct WindowsWmiDataSource;

#[async_trait]
impl WmiDataSource for WindowsWmiDataSource {
    async fn antivirus_status(&self) -> Result<AntivirusStatus, WmiError> {
        tokio::task::spawn_blocking(query_antivirus_status)
            .await
            .map_err(|e| WmiError::Query(format!("tarea WMI abortada: {e}")))?
    }

    // A diferencia de arriba, esto no consulta WMI en este mismo proceso:
    // viaja por IPC hasta `PorteroVPNSvc` (ver `checks::bitlocker` para el
    // porque).
    async fn bitlocker_status(&self) -> Result<svc_ipc::BitLockerVolumeStatus, WmiError> {
        crate::svc_client::SvcClient::query_bitlocker().await.map_err(|e| WmiError::Query(e.to_string()))
    }
}

fn query_antivirus_status() -> Result<AntivirusStatus, WmiError> {
    let com_con = COMLibrary::new().map_err(|e| WmiError::Query(e.to_string()))?;
    let wmi_con = WMIConnection::with_namespace_path(SECURITY_CENTER_NAMESPACE, com_con)
        .map_err(|e| WmiError::Query(e.to_string()))?;

    let results: Vec<RawAntiVirusProduct> = wmi_con
        .raw_query("SELECT productState FROM AntiVirusProduct")
        .map_err(|e| WmiError::Query(e.to_string()))?;

    // Basta con que UN producto registrado tenga la proteccion en tiempo
    // real activa (puede haber varios: Defender listado aunque este
    // inactivo porque un tercero tomo el relevo, entradas obsoletas de un
    // antivirus ya desinstalado, etc.). Si no hay ningun producto
    // registrado, se interpreta como "sin proteccion" (no como error).
    let real_time_protection_enabled =
        results.iter().any(|product| real_time_protection_enabled(product.product_state));

    Ok(AntivirusStatus { real_time_protection_enabled })
}

/// Decodifica el campo `productState` de `AntiVirusProduct`. No es un
/// formato documentado oficialmente por Microsoft; hay varios esquemas
/// "de facto" circulando en scripts de deteccion de antivirus y no todos
/// coinciden entre si. Este usa la mascara `0xF000` (`0x1000` = proteccion
/// en tiempo real activa, `0x2000` = "snoozed" -el usuario la silencio unas
/// horas, no cuenta como protegido de verdad-, `0x3000` = caducada,
/// cualquier otro valor = inactiva) -- verificado a mano contra este mismo
/// equipo: con Windows Defender realmente activo (confirmado por
/// `Get-MpComputerStatus`), `productState` valia `397568` (`0x061100`),
/// que con esta mascara da `0x1000` (activa) correctamente. Un esquema
/// alternativo, muy citado en blogs, que mira el byte central del valor
/// (posiciones 2-4 en hexadecimal) da el resultado contrario para ese mismo
/// valor real -- de ahi la verificacion manual en vez de fiarse a ciegas de
/// una sola fuente.
fn real_time_protection_enabled(product_state: u32) -> bool {
    const REAL_TIME_PROTECTION_ON: u32 = 0x1000;
    (product_state & 0xF000) == REAL_TIME_PROTECTION_ON
}

pub struct AntivirusActiveCheck;

#[async_trait]
impl Check for AntivirusActiveCheck {
    fn id(&self) -> &'static str {
        // No se renombra a algo mas generico (p.ej. "antivirus_active")
        // para no invalidar el `policy.toml` ya guardado en maquinas donde
        // la app ya se ha usado: el motor de checks busca por este id
        // exacto (ver `CheckRegistry::get`) y lo trata como "sin
        // implementacion" (check ignorado, sin avisar) si no coincide.
        "defender_realtime_protection"
    }

    fn display_name(&self) -> Msg {
        Msg::CheckAntivirusName
    }

    async fn evaluate(&self, ctx: &CheckContext) -> CheckOutcome {
        match ctx.wmi.antivirus_status().await {
            Ok(status) if status.real_time_protection_enabled => CheckOutcome::Pass,
            Ok(_) => CheckOutcome::Fail { reason: t(Msg::ReasonAntivirusInactive).to_string() },
            Err(e) => CheckOutcome::Indeterminate { reason: e.to_string() },
        }
    }

    // `root\SecurityCenter2` no refleja los cambios de estado del antivirus
    // al instante: lo actualiza el servicio "Centro de seguridad" (wscsvc)
    // por su cuenta, con un retraso observado en la practica (bug
    // reportado: reactivar el antivirus y conectar de inmediato seguia
    // dando "inactivo"; reintentar unos segundos despues, sin haber
    // cambiado nada mas, funcionaba). Reintentar aqui, dentro del propio
    // check, evita que ese retraso se traduzca en un intento de conexion
    // fallido que el usuario tenga que reintentar el mismo a mano.
    fn retry_policy(&self) -> RetryPolicy {
        RetryPolicy { attempts: 5, delay: Duration::from_secs(2) }
    }
}

#[cfg(test)]
mod tests {
    use super::{query_antivirus_status, real_time_protection_enabled};

    #[test]
    fn detects_enabled_from_a_real_observed_value() {
        // Windows Defender realmente activo en la maquina de desarrollo
        // (`Get-MpComputerStatus` confirmando `RealTimeProtectionEnabled:
        // True` en el mismo instante en que se consulto este valor).
        assert!(real_time_protection_enabled(397568));
    }

    #[test]
    fn detects_disabled_and_snoozed_and_expired() {
        assert!(!real_time_protection_enabled(393216)); // off (valor real, ver tabla en el modulo)
        // Construidos a partir del valor real de arriba desplazando solo el
        // nibble de estado (bits 12-15), para probar snoozed/expired sin
        // tener que provocarlos de verdad en una maquina real.
        assert!(!real_time_protection_enabled(397568 + 0x1000)); // snoozed
        assert!(!real_time_protection_enabled(397568 + 0x2000)); // expired
    }

    /// No forma parte de `cargo test` normal (depende del antivirus real de
    /// la maquina donde se ejecute): sirve para comprobar a mano, con
    /// `cargo test -- --ignored --nocapture`, que la consulta WMI real
    /// concuerda con el estado real de Windows Defender/antivirus en ese
    /// momento (ver `Get-MpComputerStatus` en PowerShell para contrastar).
    #[test]
    #[ignore = "depende del antivirus real de la maquina donde se ejecuta"]
    fn real_query_matches_actual_state() {
        let status = query_antivirus_status().expect("consulta real a SecurityCenter2 fallo");
        println!("real_time_protection_enabled = {}", status.real_time_protection_enabled);
    }
}
