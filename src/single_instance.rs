//! Comprueba que no haya ya otra instancia de la app corriendo. Un mutex con
//! nombre fijo -creado por el proceso y liberado automaticamente por
//! Windows al salir, incluso si termina de forma anormal- es la forma
//! estandar de detectarlo sin depender de ficheros de "lock" que podrian
//! quedar huerfanos tras un cierre en falso.
//!
//! Relevante ahora que la app se queda viva en la bandeja al cerrar la
//! ventana (ver `ui::tray`): sin esta comprobacion, volver a abrir el
//! ejecutable (p.ej. doble clic en el acceso directo sin darse cuenta de
//! que ya estaba minimizada) lanzaria una segunda instancia con su propio
//! icono de bandeja duplicado.

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_SHOW};

const MUTEX_NAME: &str = "PorteroVPN_SingleInstance_9F1E9E2B-3B7B-4E88-9F1B-6C8E9E7F2B10";
const WINDOW_TITLE: &str = "Portero VPN";

/// Debe vivir hasta el final de `main`: el mutex que representa se libera
/// solo al terminar el proceso (de cualquier forma), asi que basta con
/// mantener este valor en el ambito de `main`, no hace falta liberarlo a
/// mano.
pub struct InstanceGuard(#[allow(dead_code)] Option<HANDLE>);

/// `Some(guard)` si esta es la unica instancia -guardar el valor devuelto
/// hasta el final de `main`-. `None` si ya habia una corriendo: en ese caso
/// ya se ha intentado traer al frente la ventana de la instancia existente,
/// y lo unico que le queda a este proceso nuevo es terminar sin hacer nada
/// mas.
pub fn acquire_or_activate_existing() -> Option<InstanceGuard> {
    let name = HSTRING::from(MUTEX_NAME);
    let handle = match unsafe { CreateMutexW(None, false, &name) } {
        Ok(handle) => handle,
        Err(e) => {
            // No se pudo ni comprobar: mejor dejar arrancar la app que
            // bloquearla por un fallo en esta comprobacion.
            tracing::warn!(error = %e, "no se pudo crear el mutex de instancia unica");
            return Some(InstanceGuard(None));
        }
    };

    // El handle es valido tanto si se ha creado el mutex como si ya
    // existia; `GetLastError` es lo unico que distingue los dos casos (hay
    // que leerlo justo despues de `CreateMutexW`, antes de cualquier otra
    // llamada que lo pudiera pisar).
    let already_running = unsafe { windows::Win32::Foundation::GetLastError() } == ERROR_ALREADY_EXISTS;
    if already_running {
        activate_existing_window();
        None
    } else {
        Some(InstanceGuard(Some(handle)))
    }
}

fn activate_existing_window() {
    let title = HSTRING::from(WINDOW_TITLE);
    match unsafe { FindWindowW(PCWSTR::null(), &title) } {
        Ok(hwnd) => unsafe {
            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = SetForegroundWindow(hwnd);
        },
        Err(e) => {
            tracing::warn!(error = %e, "no se encontro la ventana de la instancia ya en ejecucion");
        }
    }
}
