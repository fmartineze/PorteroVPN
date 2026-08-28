//! Icono de bandeja del sistema: al cerrar la ventana con la X se oculta en
//! vez de terminar el proceso (ver el manejo de `close_requested` en
//! `PorteroApp::update`); desde el icono, un clic (izquierdo o derecho)
//! abre un menu contextual con "Panel" (reabre la ventana) y "Cerrar"
//! (termina el proceso de verdad). Doble clic sobre el icono tambien
//! reabre la ventana directamente, sin pasar por el menu.
//!
//! Los eventos se atienden con un manejador sincrono (`set_event_handler`)
//! en vez de sondear `MenuEvent::receiver()`/`TrayIconEvent::receiver()`
//! desde `PorteroApp::update`: en Windows, una ventana oculta
//! (`WS_VISIBLE` sin activar) deja de recibir `WM_PAINT`, asi que en
//! cuanto se minimiza a bandeja `update()` deja de ejecutarse y nunca
//! llegaria a drenar esa cola (comprobado en la practica: "Panel" y
//! "Cerrar" no hacian nada). El manejador, en cambio, se ejecuta
//! directamente en el bucle de mensajes de Windows del hilo principal (el
//! mismo que crea el icono), asi que actua sin depender de que egui este
//! repintando: llama a `ShowWindow`/`SetForegroundWindow` sobre el HWND
//! nativo de la ventana en crudo.

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::Arc;

use egui::Color32;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, SetForegroundWindow, ShowWindow, SW_SHOW, WM_CLOSE};

use crate::i18n::{t, Msg};
use crate::ui::theme;

const PANEL_ID: &str = "panel";
const QUIT_ID: &str = "cerrar";

/// Debe vivir mientras la app este viva: si se suelta (`Drop`), el icono
/// desaparece de la bandeja. Por eso `PorteroApp` lo guarda como campo en
/// vez de dejarlo caer de scope tras crearlo en `init()`.
pub struct AppTray {
    icon: TrayIcon,
    /// HWND (como `isize`) de la ventana principal, `0` mientras aun no se
    /// ha capturado. Se guarda como entero, no como `HWND`, porque este
    /// valor lo lee el manejador de eventos del tray desde el hilo de
    /// mensajes de Windows y un puntero crudo no es `Send`/`Sync`.
    hwnd: Arc<AtomicIsize>,
    /// Ultimo estado de conexion con el que se pinto el icono, para no
    /// reconstruir la imagen y llamar a `set_icon` en cada frame si no ha
    /// cambiado nada.
    connected: AtomicBool,
}

impl AppTray {
    /// Se llama cada frame desde `PorteroApp::update`, en cuanto `eframe`
    /// da acceso al handle nativo de la ventana -- hace falta tenerlo
    /// guardado de antemano porque el manejador de "Panel"/"Cerrar" se
    /// dispara fuera del ciclo normal de `update` (ver comentario del
    /// modulo) y ahi no hay forma de pedirselo a `eframe`.
    pub fn set_main_window(&self, hwnd: isize) {
        self.hwnd.store(hwnd, Ordering::Relaxed);
    }

    /// Cambia el color del circulo a `theme::SUCCESS` (verde) mientras hay
    /// una conexion VPN activa, o de vuelta a `theme::ACCENT` (azul) en
    /// cuanto se desconecta.
    pub fn set_connected(&self, connected: bool) {
        if self.connected.swap(connected, Ordering::Relaxed) == connected {
            return;
        }
        let color = if connected { theme::SUCCESS } else { theme::ACCENT };
        match build_icon(color) {
            Ok(icon) => {
                if let Err(e) = self.icon.set_icon(Some(icon)) {
                    tracing::warn!(error = %e, "no se pudo actualizar el color del icono de bandeja");
                }
            }
            Err(e) => tracing::warn!(error = %e, "no se pudo generar el icono de bandeja"),
        }
    }
}

/// `None` si no se pudo crear (p.ej. entorno sin shell de bandeja): la app
/// sigue funcionando igual, simplemente sin icono ni minimizado a bandeja.
///
/// `quit_requested` es la misma bandera que revisa `PorteroApp::update` al
/// interceptar el cierre de la ventana: se pone a `true` solo desde
/// "Cerrar", para distinguirlo de un simple clic en la X.
pub fn init(quit_requested: Arc<AtomicBool>) -> Option<AppTray> {
    let menu = Menu::new();
    let panel_item = MenuItem::with_id(PANEL_ID, t(Msg::TrayPanel), true, None);
    let quit_item = MenuItem::with_id(QUIT_ID, t(Msg::TrayQuit), true, None);
    if menu.append(&panel_item).is_err() || menu.append(&quit_item).is_err() {
        tracing::warn!("no se pudo construir el menu del icono de bandeja");
        return None;
    }

    let icon = match build_icon(theme::ACCENT) {
        Ok(icon) => icon,
        Err(e) => {
            tracing::warn!(error = %e, "no se pudo generar el icono de bandeja");
            return None;
        }
    };

    let tray_icon =
        match TrayIconBuilder::new().with_menu(Box::new(menu)).with_icon(icon).with_tooltip("Portero VPN").build() {
            Ok(icon) => icon,
            Err(e) => {
                tracing::warn!(error = %e, "no se pudo crear el icono de bandeja");
                return None;
            }
        };

    let hwnd = Arc::new(AtomicIsize::new(0));

    let hwnd_for_menu = Arc::clone(&hwnd);
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if event.id() == PANEL_ID {
            show_main_window(&hwnd_for_menu);
        } else if event.id() == QUIT_ID {
            quit_requested.store(true, Ordering::Relaxed);
            close_main_window(&hwnd_for_menu);
        }
    }));

    let hwnd_for_tray = Arc::clone(&hwnd);
    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        if let TrayIconEvent::DoubleClick { .. } = event {
            show_main_window(&hwnd_for_tray);
        }
    }));

    Some(AppTray { icon: tray_icon, hwnd, connected: AtomicBool::new(false) })
}

fn show_main_window(hwnd: &AtomicIsize) {
    let raw = hwnd.load(Ordering::Relaxed);
    if raw == 0 {
        return;
    }
    let hwnd = HWND(raw as *mut _);
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
}

fn close_main_window(hwnd: &AtomicIsize) {
    let raw = hwnd.load(Ordering::Relaxed);
    if raw == 0 {
        return;
    }
    let hwnd = HWND(raw as *mut _);
    unsafe {
        // Hace falta mostrarla primero: con la ventana oculta `update()` no
        // se ejecuta (ver comentario del modulo), asi que el cierre normal
        // via `WM_CLOSE` -> `close_requested()` en `update` no llegaria a
        // procesarse nunca si se deja oculta.
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
    }
}

/// Circulo relleno de `color` (azul mientras no hay conexion, verde
/// mientras la hay -ver `set_connected`-) con una "V" blanca en el centro,
/// sobre fondo transparente: evita depender de un fichero .ico externo
/// solo para tener un icono de bandeja distintivo. Mismo dibujo, via
/// `include!`, que el icono embebido en los .exe (ver `build.rs`).
fn build_icon(color: Color32) -> Result<Icon, tray_icon::BadIcon> {
    const SIZE: u32 = 32;
    let rgba = generate_icon_rgba(SIZE, [color.r(), color.g(), color.b()]);
    Icon::from_rgba(rgba, SIZE, SIZE)
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/icon_shape.rs"));
