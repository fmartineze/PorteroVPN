//! Descriptor de seguridad del named pipe de control.
//!
//! Por defecto, un named pipe creado por un servicio LocalSystem solo admite
//! conectar a SYSTEM/Administradores. La GUI de Portero VPN corre en sesion
//! de usuario normal (a proposito, ver plan seccion 1), asi que el pipe debe
//! conceder acceso explicito a usuarios autenticados.

use anyhow::{Context, Result};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// Concede acceso generico a: Usuarios autenticados (AU), SYSTEM (SY) y
/// Administradores (BA). Suficiente para el escenario de uso personal (ver
/// plan, seccion 10): no se restringe por SID especifico porque el servicio
/// solo acepta arrancar/parar openvpn.exe, ninguna operacion mas sensible.
const PIPE_SDDL: &str = "D:(A;;GA;;;AU)(A;;GA;;;SY)(A;;GA;;;BA)";

pub fn authenticated_users_security_attributes() -> Result<SECURITY_ATTRIBUTES> {
    let sddl = HSTRING::from(PIPE_SDDL);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1, // SDDL_REVISION_1
            &mut descriptor,
            None,
        )
        .context("ConvertStringSecurityDescriptorToSecurityDescriptorW fallo")?;
    }

    // El descriptor se deja vivo intencionadamente durante toda la vida del
    // servicio: se reutiliza al crear cada instancia sucesiva del pipe.
    Ok(SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    })
}
