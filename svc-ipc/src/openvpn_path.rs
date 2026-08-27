//! Localizacion del ejecutable `openvpn.exe` del motor OpenVPN Community ya
//! instalado en la maquina (ver plan de arquitectura, seccion 8:
//! "comprobar y guiar"). Compartido entre `PorteroVPNSvc` (que lo lanza) y
//! la GUI (que comprueba si esta instalado para avisar/ofrecer instalarlo,
//! ver `openvpn_install` en el crate principal), para que ambos usen
//! exactamente la misma logica de deteccion.

use std::path::{Path, PathBuf};

const CANDIDATE_PATHS: &[&str] = &[
    r"C:\Program Files\OpenVPN\bin\openvpn.exe",
    r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
];

/// Devuelve la ruta a `openvpn.exe`, permitiendo un override explicito via
/// la variable de entorno `PORTERO_VPN_OPENVPN_EXE` (util para pruebas y
/// para instalaciones en rutas no estandar).
pub fn locate_openvpn_exe() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("PORTERO_VPN_OPENVPN_EXE") {
        let path = PathBuf::from(override_path);
        if path.is_file() {
            return Some(path);
        }
    }

    CANDIDATE_PATHS
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .map(Path::to_path_buf)
}

/// Comprobacion rapida de si OpenVPN Community esta instalado, sin
/// necesitar la ruta completa (para banners/avisos en la UI).
pub fn is_installed() -> bool {
    locate_openvpn_exe().is_some()
}
