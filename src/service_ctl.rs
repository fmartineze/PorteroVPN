//! Deteccion e instalacion/desinstalacion de `PorteroVPNSvc` desde la GUI
//! (plan, seccion 6 y 10: la GUI corre sin privilegios, asi que instalar o
//! quitar un servicio Windows exige pedir elevacion). El propio ejecutable
//! del servicio hace de instalador cuando se le llama con
//! `install`/`uninstall`/`reinstall`; aqui solo se le lanza elevado (ver
//! `crate::elevate`, compartido con `openvpn_install`) y se espera a que
//! termine.

use std::io;
use std::path::PathBuf;

use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use svc_ipc::SERVICE_NAME;

use crate::elevate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceInstallState {
    NotInstalled,
    Stopped,
    Running,
    /// Instalado pero en un estado transitorio (arrancando, parando...).
    Transitioning,
}

pub fn query_state() -> ServiceInstallState {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return ServiceInstallState::NotInstalled;
    };
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
        return ServiceInstallState::NotInstalled;
    };
    match service.query_status().map(|s| s.current_state) {
        Ok(ServiceState::Running) => ServiceInstallState::Running,
        Ok(ServiceState::Stopped) => ServiceInstallState::Stopped,
        Ok(_) => ServiceInstallState::Transitioning,
        Err(_) => ServiceInstallState::NotInstalled,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    #[error("no se encontro portero-vpn-svc.exe junto a esta aplicacion ({0})")]
    ExeNotFound(PathBuf),
    #[error(transparent)]
    Elevate(#[from] elevate::ElevationError),
}

fn svc_exe_path() -> io::Result<PathBuf> {
    let path = std::env::current_exe()?
        .parent()
        .map(|dir| dir.join(svc_ipc::SERVICE_EXE_NAME))
        .ok_or_else(|| io::Error::other("no se pudo determinar el directorio del ejecutable"))?;
    Ok(path)
}

/// Lanza `portero-vpn-svc.exe <action>` elevado (UAC) y espera a que
/// termine. Bloqueante: se llama solo desde una accion explicita del
/// usuario en Configuracion/Seguridad, nunca en el arranque de la app.
pub fn run_elevated(action: &str) -> Result<(), ElevationError> {
    let exe_path = svc_exe_path().map_err(|_| ElevationError::ExeNotFound(PathBuf::from(svc_ipc::SERVICE_EXE_NAME)))?;
    if !exe_path.is_file() {
        return Err(ElevationError::ExeNotFound(exe_path));
    }

    elevate::run_elevated_and_wait(&exe_path, action, SW_HIDE).map_err(Into::into)
}
