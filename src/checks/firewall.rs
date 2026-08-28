//! Comprobacion de que hay un cortafuegos activo, via el Centro de seguridad
//! de Windows (`root\SecurityCenter2`, clase `FirewallProduct`).
//!
//! Misma fuente y mismo razonamiento que `checks::antivirus`: es el catalogo
//! que usa la propia app "Seguridad de Windows", asi que cubre tanto el
//! cortafuegos de Windows como cualquier producto de terceros que se haya
//! registrado en el. Y se consulta desde la sesion del usuario, nunca desde
//! sesion 0, que es el motivo de que esta aplicacion exista.

use async_trait::async_trait;

use crate::i18n::{t, Msg};

use super::{Check, CheckContext, CheckOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallStatus {
    pub enabled: bool,
}

pub struct FirewallEnabledCheck;

#[async_trait]
impl Check for FirewallEnabledCheck {
    fn id(&self) -> &'static str {
        "firewall_enabled"
    }

    fn display_name(&self) -> Msg {
        Msg::CheckFirewallName
    }

    async fn evaluate(&self, ctx: &CheckContext) -> CheckOutcome {
        match ctx.wmi.firewall_status().await {
            Ok(status) if status.enabled => CheckOutcome::Pass,
            Ok(_) => CheckOutcome::Fail { reason: t(Msg::ReasonFirewallInactive).to_string() },
            Err(e) => CheckOutcome::Indeterminate { reason: e.to_string() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{antivirus, WmiDataSource, WmiError};

    struct MockWmiDataSource {
        firewall: Result<bool, String>,
    }

    #[async_trait]
    impl WmiDataSource for MockWmiDataSource {
        async fn antivirus_status(&self) -> Result<antivirus::AntivirusStatus, WmiError> {
            Ok(antivirus::AntivirusStatus { real_time_protection_enabled: true })
        }

        async fn firewall_status(&self) -> Result<FirewallStatus, WmiError> {
            match &self.firewall {
                Ok(enabled) => Ok(FirewallStatus { enabled: *enabled }),
                Err(e) => Err(WmiError::Query(e.clone())),
            }
        }

        async fn bitlocker_status(&self) -> Result<svc_ipc::BitLockerVolumeStatus, WmiError> {
            Ok(svc_ipc::BitLockerVolumeStatus::Unavailable)
        }
    }

    fn ctx(firewall: Result<bool, String>) -> CheckContext {
        CheckContext { wmi: std::sync::Arc::new(MockWmiDataSource { firewall }) }
    }

    #[tokio::test]
    async fn passes_when_a_firewall_is_active() {
        assert_eq!(FirewallEnabledCheck.evaluate(&ctx(Ok(true))).await, CheckOutcome::Pass);
    }

    #[tokio::test]
    async fn fails_when_no_firewall_is_active() {
        let outcome = FirewallEnabledCheck.evaluate(&ctx(Ok(false))).await;
        assert!(matches!(outcome, CheckOutcome::Fail { .. }));
    }

    /// Un error de WMI no es lo mismo que "no hay cortafuegos": no sabemos si
    /// el equipo cumple, asi que el motor lo trata como bloqueante por
    /// seguridad, pero el resultado tiene que distinguirse de un fallo real.
    #[tokio::test]
    async fn indeterminate_when_wmi_fails() {
        let outcome = FirewallEnabledCheck.evaluate(&ctx(Err("COM no disponible".into()))).await;
        assert!(matches!(outcome, CheckOutcome::Indeterminate { .. }));
    }
}
