//! Motor de comprobaciones de seguridad previas a la conexion (plan,
//! seccion 5). Anadir un check nuevo es: implementar el trait `Check` +
//! registrarlo en `CheckRegistry::new()` + una entrada en `policy.toml`; el
//! motor de ejecucion y la UI de progreso no cambian.

pub mod antivirus;
pub mod bitlocker;
pub mod firewall;
pub mod windows_password;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::i18n::Msg;
use crate::storage::SecurityPolicy;

/// Resultado tipado de una evaluacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    Pass,
    Fail { reason: String },
    /// La fuente de datos no esta disponible o dio un error inesperado:
    /// distinto de `Fail`, no sabemos si el sistema cumple o no. Se trata
    /// como fallo por seguridad en el motor de agregacion.
    Indeterminate { reason: String },
}

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub delay: Duration,
}

impl RetryPolicy {
    pub fn none() -> Self {
        Self { attempts: 1, delay: Duration::ZERO }
    }
}

/// Fuente de datos WMI, abstraida para poder mockearla en tests unitarios
/// sin depender de un Windows real en un estado concreto (plan, seccion 11).
#[async_trait]
pub trait WmiDataSource: Send + Sync {
    async fn antivirus_status(&self) -> Result<antivirus::AntivirusStatus, WmiError>;
    /// Mismo namespace y misma codificacion de estado que `antivirus_status`,
    /// solo cambia la clase consultada (ver `checks::firewall`).
    async fn firewall_status(&self) -> Result<firewall::FirewallStatus, WmiError>;
    /// A diferencia de `antivirus_status` (consulta WMI directa en la
    /// propia GUI), esto viaja por IPC hasta `PorteroVPNSvc`: el namespace
    /// WMI de BitLocker esta restringido a Administradores y la GUI corre
    /// sin privilegios a proposito (ver `checks::bitlocker`).
    async fn bitlocker_status(&self) -> Result<svc_ipc::BitLockerVolumeStatus, WmiError>;
}

#[derive(Debug, thiserror::Error)]
pub enum WmiError {
    #[error("no se pudo consultar WMI: {0}")]
    Query(String),
}

pub struct CheckContext {
    pub wmi: Arc<dyn WmiDataSource>,
}

#[async_trait]
pub trait Check: Send + Sync {
    /// Identificador estable, usado en policy.toml (checks[].id) y en logs.
    fn id(&self) -> &'static str;

    /// Nombre para mostrar en la UI, como clave de traduccion: el texto se
    /// resuelve al pintar, no al registrar el check, para que cambiar de
    /// idioma se refleje tambien en resultados ya calculados.
    fn display_name(&self) -> Msg;

    /// Evaluacion puntual. Debe tener su propio timeout interno razonable
    /// para no colgar el flujo de "conectando...".
    async fn evaluate(&self, ctx: &CheckContext) -> CheckOutcome;

    fn retry_policy(&self) -> RetryPolicy {
        RetryPolicy::none()
    }
}

pub struct CheckRegistry {
    checks: HashMap<&'static str, Box<dyn Check>>,
}

impl CheckRegistry {
    pub fn new() -> Self {
        let mut registry = Self { checks: HashMap::new() };
        registry.register(Box::new(antivirus::AntivirusActiveCheck));
        registry.register(Box::new(bitlocker::BitLockerEnabledCheck));
        registry.register(Box::new(firewall::FirewallEnabledCheck));
        registry.register(Box::new(windows_password::WindowsPasswordCheck));
        // Ojo al anadir uno nuevo: no basta con registrarlo aqui. El motor
        // recorre `policy.toml`, no el registro, asi que un check que no
        // figure en la politica no se ejecuta ni aparece en Configuracion.
        // De eso se encarga `SecurityPolicy::add_missing_checks`, que corre al
        // arrancar; anadelo tambien a `bootstrap_default` para las
        // instalaciones nuevas.
        registry
    }

    pub fn register(&mut self, check: Box<dyn Check>) {
        self.checks.insert(check.id(), check);
    }

    pub fn get(&self, id: &str) -> Option<&dyn Check> {
        self.checks.get(id).map(|c| c.as_ref())
    }

    pub fn all(&self) -> impl Iterator<Item = &dyn Check> {
        self.checks.values().map(|c| c.as_ref())
    }
}

impl Default for CheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Resultado de un check individual dentro de una pasada de
/// pre-conexion, con el detalle necesario para la pantalla "Conectando..."
/// (plan, seccion 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRunResult {
    pub check_id: String,
    pub display_name: Msg,
    pub mandatory: bool,
    pub outcome: CheckOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreConnectResult {
    pub results: Vec<CheckRunResult>,
}

impl PreConnectResult {
    /// Bloquea la conexion si cualquier check obligatorio fallo o dio
    /// resultado indeterminado (ver plan, seccion 5 y 7).
    pub fn blocks_connection(&self) -> bool {
        self.results.iter().any(|r| {
            r.mandatory
                && !matches!(r.outcome, CheckOutcome::Pass)
        })
    }

    pub fn blocking_failures(&self) -> impl Iterator<Item = &CheckRunResult> {
        self.results
            .iter()
            .filter(|r| r.mandatory && !matches!(r.outcome, CheckOutcome::Pass))
    }
}

/// Ejecuta todos los checks activos de la politica y agrega los resultados.
/// No decide por si mismo si arrancar `openvpn.exe`: eso lo hace el
/// llamador, inspeccionando `PreConnectResult::blocks_connection()`.
pub async fn run_pre_connect_checks(
    policy: &SecurityPolicy,
    registry: &CheckRegistry,
    ctx: &CheckContext,
) -> PreConnectResult {
    let mut results = Vec::new();

    for config in policy.checks.iter().filter(|c| c.enabled) {
        let Some(check) = registry.get(&config.id) else {
            tracing::warn!(check_id = %config.id, "check en policy.toml sin implementacion registrada");
            continue;
        };

        let outcome = evaluate_with_retries(check, ctx).await;
        results.push(CheckRunResult {
            check_id: config.id.clone(),
            display_name: check.display_name(),
            mandatory: config.mandatory,
            outcome,
        });
    }

    PreConnectResult { results }
}

async fn evaluate_with_retries(check: &dyn Check, ctx: &CheckContext) -> CheckOutcome {
    let policy = check.retry_policy();
    let mut last = CheckOutcome::Indeterminate { reason: "no se ejecuto ningun intento".into() };

    for attempt in 0..policy.attempts.max(1) {
        last = check.evaluate(ctx).await;
        if matches!(last, CheckOutcome::Pass) {
            return last;
        }
        if attempt + 1 < policy.attempts {
            tokio::time::sleep(policy.delay).await;
        }
    }

    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::CheckConfig;

    struct MockWmiDataSource {
        real_time_protection_enabled: Result<bool, String>,
    }

    #[async_trait]
    impl WmiDataSource for MockWmiDataSource {
        async fn antivirus_status(&self) -> Result<antivirus::AntivirusStatus, WmiError> {
            match &self.real_time_protection_enabled {
                Ok(enabled) => Ok(antivirus::AntivirusStatus { real_time_protection_enabled: *enabled }),
                Err(e) => Err(WmiError::Query(e.clone())),
            }
        }

        // No usados por los tests de este modulo (solo ejercitan el check de
        // antivirus): valores fijos solo para satisfacer el trait.
        async fn firewall_status(&self) -> Result<firewall::FirewallStatus, WmiError> {
            Ok(firewall::FirewallStatus { enabled: true })
        }

        async fn bitlocker_status(&self) -> Result<svc_ipc::BitLockerVolumeStatus, WmiError> {
            Ok(svc_ipc::BitLockerVolumeStatus::Unavailable)
        }
    }

    fn policy_with_defender(mandatory: bool) -> SecurityPolicy {
        SecurityPolicy {
            checks: vec![CheckConfig {
                id: "defender_realtime_protection".into(),
                enabled: true,
                mandatory,
            }],
        }
    }

    #[tokio::test]
    async fn passes_when_defender_active() {
        let ctx = CheckContext { wmi: Arc::new(MockWmiDataSource { real_time_protection_enabled: Ok(true) }) };
        let registry = CheckRegistry::new();
        let result = run_pre_connect_checks(&policy_with_defender(true), &registry, &ctx).await;

        assert!(!result.blocks_connection());
        assert_eq!(result.results[0].outcome, CheckOutcome::Pass);
    }

    #[tokio::test]
    async fn mandatory_fail_blocks_connection() {
        let ctx = CheckContext { wmi: Arc::new(MockWmiDataSource { real_time_protection_enabled: Ok(false) }) };
        let registry = CheckRegistry::new();
        let result = run_pre_connect_checks(&policy_with_defender(true), &registry, &ctx).await;

        assert!(result.blocks_connection());
        assert_eq!(result.blocking_failures().count(), 1);
    }

    #[tokio::test]
    async fn non_mandatory_fail_does_not_block() {
        let ctx = CheckContext { wmi: Arc::new(MockWmiDataSource { real_time_protection_enabled: Ok(false) }) };
        let registry = CheckRegistry::new();
        let result = run_pre_connect_checks(&policy_with_defender(false), &registry, &ctx).await;

        assert!(!result.blocks_connection());
    }

    #[tokio::test]
    async fn indeterminate_result_blocks_when_mandatory() {
        let ctx = CheckContext {
            wmi: Arc::new(MockWmiDataSource { real_time_protection_enabled: Err("WMI no disponible".into()) }),
        };
        let registry = CheckRegistry::new();
        let result = run_pre_connect_checks(&policy_with_defender(true), &registry, &ctx).await;

        assert!(result.blocks_connection());
        assert!(matches!(result.results[0].outcome, CheckOutcome::Indeterminate { .. }));
    }

    #[tokio::test]
    async fn disabled_check_is_skipped() {
        let mut policy = policy_with_defender(true);
        policy.checks[0].enabled = false;

        let ctx = CheckContext { wmi: Arc::new(MockWmiDataSource { real_time_protection_enabled: Ok(false) }) };
        let registry = CheckRegistry::new();
        let result = run_pre_connect_checks(&policy, &registry, &ctx).await;

        assert!(result.results.is_empty());
        assert!(!result.blocks_connection());
    }

    /// Simula el retraso real de `root\SecurityCenter2` en reflejar que el
    /// antivirus se ha vuelto a activar (ver `AntivirusActiveCheck::
    /// retry_policy`): las primeras `fails_before_success` consultas
    /// devuelven "inactivo" aunque ya este activo, y a partir de ahi
    /// "activo".
    struct FlakyAntivirusWmiDataSource {
        calls: std::sync::atomic::AtomicU32,
        fails_before_success: u32,
    }

    #[async_trait]
    impl WmiDataSource for FlakyAntivirusWmiDataSource {
        async fn antivirus_status(&self) -> Result<antivirus::AntivirusStatus, WmiError> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(antivirus::AntivirusStatus { real_time_protection_enabled: call >= self.fails_before_success })
        }

        async fn firewall_status(&self) -> Result<firewall::FirewallStatus, WmiError> {
            Ok(firewall::FirewallStatus { enabled: true })
        }

        async fn bitlocker_status(&self) -> Result<svc_ipc::BitLockerVolumeStatus, WmiError> {
            Ok(svc_ipc::BitLockerVolumeStatus::Unavailable)
        }
    }

    // `start_paused = true`: avanza el reloj virtual de tokio en vez de
    // esperar de verdad los `sleep` entre reintentos (ver
    // `AntivirusActiveCheck::retry_policy`, 2s de espera x hasta 4 veces).
    #[tokio::test(start_paused = true)]
    async fn antivirus_check_retries_transient_wmi_lag_until_it_reports_active() {
        let ctx = CheckContext {
            wmi: Arc::new(FlakyAntivirusWmiDataSource {
                calls: std::sync::atomic::AtomicU32::new(0),
                fails_before_success: 2,
            }),
        };
        let registry = CheckRegistry::new();
        let result = run_pre_connect_checks(&policy_with_defender(true), &registry, &ctx).await;

        assert!(!result.blocks_connection());
        assert_eq!(result.results[0].outcome, CheckOutcome::Pass);
    }
}
