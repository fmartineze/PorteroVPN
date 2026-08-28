//! Comprobacion de que el volumen de arranque tiene BitLocker activo.
//!
//! A diferencia del check de antivirus (`checks::antivirus`, que consulta
//! WMI directamente desde la propia GUI), esta consulta viaja hasta
//! `PorteroVPNSvc` por el named pipe existente: el namespace WMI de
//! BitLocker (`root\cimv2\security\MicrosoftVolumeEncryption`) esta
//! restringido por defecto a Administradores, y la GUI corre
//! deliberadamente sin privilegios (ver plan de arquitectura, Contexto).
//! Consultarlo sin privilegios devolveria "acceso denegado" en muchos
//! equipos aunque BitLocker si este activo -- justo lo contrario de "una
//! comprobacion que funcione en cualquier equipo con Windows".
//!
//! La implementacion real de la consulta WMI vive en `svc/src/main.rs`
//! (LocalSystem, sin esa restriccion); aqui solo se traduce la respuesta
//! del servicio (`svc_ipc::BitLockerVolumeStatus`) a un `CheckOutcome`.

use async_trait::async_trait;

use crate::i18n::{t, Msg};
use super::{Check, CheckContext, CheckOutcome};

pub struct BitLockerEnabledCheck;

#[async_trait]
impl Check for BitLockerEnabledCheck {
    fn id(&self) -> &'static str {
        "bitlocker_enabled"
    }

    fn display_name(&self) -> Msg {
        Msg::CheckBitLockerName
    }

    async fn evaluate(&self, ctx: &CheckContext) -> CheckOutcome {
        match ctx.wmi.bitlocker_status().await {
            Ok(svc_ipc::BitLockerVolumeStatus::Protected) => CheckOutcome::Pass,
            Ok(svc_ipc::BitLockerVolumeStatus::NotProtected) => CheckOutcome::Fail {
                reason: t(Msg::ReasonBitLockerOff).to_string(),
            },
            // Namespace ausente (tipico en Windows Home, donde BitLocker no
            // existe como funcion) o sin volumen de arranque reportado: se
            // trata como "no protegido", no como fallo de la comprobacion
            // en si (ver `svc_ipc::BitLockerVolumeStatus::Unavailable`).
            Ok(svc_ipc::BitLockerVolumeStatus::Unavailable) => CheckOutcome::Fail {
                reason: t(Msg::ReasonBitLockerUnavailable).to_string(),
            },
            Err(e) => CheckOutcome::Indeterminate { reason: e.to_string() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{antivirus, WmiDataSource, WmiError};

    struct MockWmiDataSource {
        bitlocker: Result<svc_ipc::BitLockerVolumeStatus, String>,
    }

    #[async_trait]
    impl WmiDataSource for MockWmiDataSource {
        async fn antivirus_status(&self) -> Result<antivirus::AntivirusStatus, WmiError> {
            Ok(antivirus::AntivirusStatus { real_time_protection_enabled: true })
        }

        async fn firewall_status(&self) -> Result<crate::checks::firewall::FirewallStatus, WmiError> {
            Ok(crate::checks::firewall::FirewallStatus { enabled: true })
        }

        async fn bitlocker_status(&self) -> Result<svc_ipc::BitLockerVolumeStatus, WmiError> {
            self.bitlocker.clone().map_err(WmiError::Query)
        }
    }

    fn ctx(bitlocker: Result<svc_ipc::BitLockerVolumeStatus, String>) -> CheckContext {
        CheckContext { wmi: std::sync::Arc::new(MockWmiDataSource { bitlocker }) }
    }

    #[tokio::test]
    async fn passes_when_protected() {
        let outcome = BitLockerEnabledCheck.evaluate(&ctx(Ok(svc_ipc::BitLockerVolumeStatus::Protected))).await;
        assert_eq!(outcome, CheckOutcome::Pass);
    }

    #[tokio::test]
    async fn fails_when_not_protected() {
        let outcome = BitLockerEnabledCheck.evaluate(&ctx(Ok(svc_ipc::BitLockerVolumeStatus::NotProtected))).await;
        assert!(matches!(outcome, CheckOutcome::Fail { .. }));
    }

    #[tokio::test]
    async fn fails_when_unavailable() {
        let outcome = BitLockerEnabledCheck.evaluate(&ctx(Ok(svc_ipc::BitLockerVolumeStatus::Unavailable))).await;
        assert!(matches!(outcome, CheckOutcome::Fail { .. }));
    }

    #[tokio::test]
    async fn indeterminate_when_service_unreachable() {
        let outcome = BitLockerEnabledCheck.evaluate(&ctx(Err("PorteroVPNSvc no responde".into()))).await;
        assert!(matches!(outcome, CheckOutcome::Indeterminate { .. }));
    }
}
