//! Localizacion del ejecutable `wireguard.exe` de WireGuard para Windows ya
//! instalado en la maquina. Mismo reparto que `openvpn_path`: lo comparten
//! `PorteroVPNSvc` (que lo invoca para instalar y quitar tuneles) y la GUI
//! (que comprueba si esta instalado para avisar u ofrecer instalarlo), de modo
//! que los dos detecten exactamente igual.

use std::path::{Path, PathBuf};

const CANDIDATE_PATHS: &[&str] = &[
    r"C:\Program Files\WireGuard\wireguard.exe",
    r"C:\Program Files (x86)\WireGuard\wireguard.exe",
];

/// Prefijo de los tuneles que crea esta aplicacion.
///
/// Sirve para dos cosas: no pisar tuneles que el usuario haya creado con el
/// cliente oficial de WireGuard, y poder reconocer los nuestros para retirar
/// los que queden huerfanos si la GUI muere con uno levantado.
pub const TUNNEL_NAME_PREFIX: &str = "PorteroVPN-";

/// Devuelve la ruta a `wireguard.exe`, permitiendo un override explicito via
/// la variable de entorno `PORTERO_VPN_WIREGUARD_EXE` (util para pruebas y
/// para instalaciones en rutas no estandar).
pub fn locate_wireguard_exe() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("PORTERO_VPN_WIREGUARD_EXE") {
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

/// Comprobacion rapida de si WireGuard esta instalado, sin necesitar la ruta
/// completa (para banners/avisos en la UI).
pub fn is_installed() -> bool {
    locate_wireguard_exe().is_some()
}

/// Ruta a `wg.exe`, la herramienta de estado que WireGuard instala junto a
/// `wireguard.exe`.
///
/// Hace falta porque **WireGuard para Windows no expone el estado del tunel
/// por un named pipe**: desde que usa el driver WireGuardNT en vez del modelo
/// en espacio de usuario, el estado se lee del propio adaptador. Comprobado en
/// la practica: con el tunel corriendo y su adaptador creado, abrir
/// `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<nombre>` da
/// ERROR_FILE_NOT_FOUND, y no hay ningun pipe de WireGuard entre los 337 que
/// enumera el sistema. `wg.exe show <nombre> dump` es la via que si funciona.
pub fn locate_wg_exe() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("PORTERO_VPN_WG_EXE") {
        let path = PathBuf::from(override_path);
        if path.is_file() {
            return Some(path);
        }
    }

    // Vive junto a `wireguard.exe`, asi que se deriva de el en vez de repetir
    // la lista de candidatos.
    locate_wireguard_exe().map(|p| p.with_file_name("wg.exe")).filter(|p| p.is_file())
}

/// Nombre de tunel para un perfil, a partir de su id en hexadecimal sin
/// guiones (`Uuid::simple`). Se toma como texto y no como `Uuid` para no
/// arrastrar la dependencia a este crate, que a proposito solo depende de
/// serde.
///
/// **No se puede usar el UUID entero.** WireGuard toma este nombre del nombre
/// del fichero `.conf` y con el bautiza tambien el adaptador de red, asi que lo
/// limita en longitud y en juego de caracteres; un UUID de 36 caracteres no
/// pasa. Se usan los 8 primeros digitos hexadecimales, que sobran para
/// distinguir los perfiles de un equipo y dejan el nombre en 19 caracteres.
pub fn tunnel_name_for(profile_id_simple: &str) -> String {
    let short: String = profile_id_simple.chars().take(8).collect();
    format!("{TUNNEL_NAME_PREFIX}{short}")
}

/// Si un nombre de tunel lo creo esta aplicacion.
pub fn is_ours(tunnel_name: &str) -> bool {
    tunnel_name.starts_with(TUNNEL_NAME_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_name_is_short_and_recognisable() {
        // Tal como lo daria `Uuid::simple()`: hexadecimal sin guiones.
        let name = tunnel_name_for("3ab2863b727f45bba6f0c76e1837e427");

        assert_eq!(name, "PorteroVPN-3ab2863b");
        assert!(is_ours(&name));
        // WireGuard nombra tambien el adaptador con esto: si crece, deja de
        // valer. Ver el comentario de `tunnel_name_for`.
        assert!(name.len() <= 32, "nombre de tunel demasiado largo: {}", name.len());
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "el nombre debe limitarse a caracteres seguros para un adaptador"
        );
    }

    #[test]
    fn tunnels_from_other_tools_are_not_ours() {
        assert!(!is_ours("casa"));
        assert!(!is_ours("wg0"));
    }
}
