//! Lanzar un ejecutable elevado (UAC, verbo "runas" de `ShellExecuteExW`) y
//! esperar a que termine -- infraestructura compartida entre `service_ctl`
//! (instalar/desinstalar `PorteroVPNSvc`) y `openvpn_install` (ejecutar el
//! instalador MSI de OpenVPN Community).

use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HWND};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SHOW_WINDOW_CMD;

#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    #[error("no se pudo lanzar la operacion elevada: {0}")]
    Launch(#[from] windows::core::Error),
    #[error(
        "la operacion se cancelo (el usuario rechazo el aviso de permisos de administrador, \
         o UAC no esta disponible)"
    )]
    Cancelled,
    #[error("la operacion elevada termino con un error (codigo {0})")]
    NonZeroExit(u32),
}

/// Lanza `exe_path` elevado (UAC) con `params` como linea de argumentos, y
/// espera bloqueando a que termine. `show` controla si se ve o no la
/// ventana del proceso lanzado (p.ej. `SW_HIDE` para nuestro propio
/// `portero-vpn-svc.exe`, que no tiene ventana; `SW_SHOWNORMAL` para dejar
/// ver el progreso de un instalador de terceros como el de OpenVPN).
pub fn run_elevated_and_wait(exe_path: &Path, params: &str, show: SHOW_WINDOW_CMD) -> Result<(), ElevationError> {
    let exe_wide = to_wide(&exe_path.to_string_lossy());
    let params_wide = to_wide(params);
    let verb_wide = to_wide("runas");

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: HWND::default(),
        lpVerb: PCWSTR(verb_wide.as_ptr()),
        lpFile: PCWSTR(exe_wide.as_ptr()),
        lpParameters: PCWSTR(params_wide.as_ptr()),
        nShow: show.0,
        ..Default::default()
    };

    unsafe {
        ShellExecuteExW(&mut info).map_err(|_| ElevationError::Cancelled)?;

        if info.hProcess.is_invalid() {
            return Err(ElevationError::Cancelled);
        }

        WaitForSingleObject(info.hProcess, INFINITE);

        let mut exit_code = 0u32;
        let _ = GetExitCodeProcess(info.hProcess, &mut exit_code);
        let _ = CloseHandle(info.hProcess);

        if exit_code != 0 {
            return Err(ElevationError::NonZeroExit(exit_code));
        }
    }

    Ok(())
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
