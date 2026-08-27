//! Estado y render de la GUI (plan, seccion 6). Un unico `eframe::App` con
//! dos pantallas (Conexiones / Configuracion) y, como maximo, una conexion
//! activa a la vez (MVP, ver plan seccion 1). El runtime de tokio corre en
//! segundo plano; los eventos de una conexion en curso llegan por un canal
//! que se drena en cada frame (`try_recv`), patron estandar para combinar
//! egui (immediate-mode) con tareas async.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use egui::{Color32, RichText};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use uuid::Uuid;

use crate::checks::{CheckOutcome, CheckRegistry, CheckRunResult, WmiDataSource};
use crate::connection::{self, AppEvent, ConnectionHandle};
use crate::credentials::{self, Credentials};
use crate::openvpn_install::{self, InstallEvent};
use crate::service_ctl::{self, ServiceInstallState};
use crate::storage::{self, ProfileMeta, SecurityPolicy};
use crate::svc_client::SvcClient;
use crate::ui::theme;
use crate::ui::tray::{self, AppTray};
use crate::{auth, checks};

const MAX_LOG_LINES: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Connections,
    Settings,
}

#[derive(Clone)]
enum ConnectionPhase {
    RunningChecks,
    /// El mensaje ya no se guarda aqui: vive en `ErrorModal.message`
    /// (`error_modal`), que se muestra en el momento en que llega el
    /// evento. Este solo importa para pintar el punto de estado "Error".
    ChecksFailed,
    Connecting { last_state: String },
    Connected { local_ip: Option<String>, remote_ip: Option<String>, since: Instant },
    AuthFailed,
    Failed,
}

struct CredentialForm {
    context: String,
    username: String,
    password: String,
    remember: bool,
}

/// Contenido del modal de error de conexion (comprobaciones de seguridad,
/// fallo de autenticacion, certificado, etc.): se muestra centrado sobre la
/// ventana en vez de incrustado en la tarjeta de conexion.
struct ErrorModal {
    title: String,
    message: String,
    profile_id: Uuid,
    can_forget_credentials: bool,
}

struct ActiveConnection {
    profile_id: Uuid,
    display_name: String,
    phase: ConnectionPhase,
    check_results: Vec<CheckRunResult>,
    log_lines: VecDeque<String>,
    bytes_in: u64,
    bytes_out: u64,
    handle: ConnectionHandle,
    events_rx: tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
    pending_credentials: Option<CredentialForm>,
}

struct ImportDraft {
    source_path: std::path::PathBuf,
    display_name: String,
    remember_credentials: bool,
    username: String,
    password: String,
}

struct EditDraft {
    profile_id: Uuid,
    display_name: String,
    remember_credentials: bool,
    username: String,
    password: String,
}

struct FirstRunState {
    password: String,
    confirm: String,
    error: Option<String>,
}

#[derive(Default)]
struct ChangePasswordState {
    current: String,
    new_password: String,
    confirm: String,
    error: Option<String>,
}

/// Estado del flujo "Instalar OpenVPN" (banner en Conexiones, ver
/// `openvpn_install`). `Idle` cubre tanto "todavia no se ha pedido" como
/// "termino bien" -- una vez `Done`, `openvpn_installed` ya vale `true` y el
/// banner entero deja de pintarse, asi que no hace falta un estado aparte.
enum OpenVpnInstallUiState {
    Idle,
    Working(String),
    Error(String),
}

pub struct PorteroApp {
    rt: tokio::runtime::Runtime,
    registry: Arc<CheckRegistry>,
    wmi: Arc<dyn WmiDataSource>,

    policy: SecurityPolicy,
    profiles: Vec<ProfileMeta>,

    screen: Screen,
    active: Option<ActiveConnection>,
    /// Perfil elegido en la lista (clic en la fila): el boton unico de
    /// "CONECTAR" de la parte inferior actua sobre este.
    selected_profile: Option<Uuid>,
    error_modal: Option<ErrorModal>,

    import_draft: Option<ImportDraft>,
    import_error: Option<String>,
    edit_draft: Option<EditDraft>,
    edit_error: Option<String>,

    settings_unlocked: bool,
    settings_password_input: String,
    settings_error: Option<String>,
    first_run: Option<FirstRunState>,
    change_password: ChangePasswordState,

    show_log_window: bool,
    /// `Some(mensaje)` si `PorteroVPNSvc` no respondio al arrancar la app
    /// (plan, seccion 7: "servicio no disponible"). Se comprueba una vez al
    /// inicio; una conexion fallida por este motivo lo confirma de nuevo.
    service_warning: Option<String>,
    /// Si el servicio esta registrado en el SCM (independientemente de si
    /// esta arrancado). Distinto de `service_warning`: esto se puede saber
    /// sin privilegios, con una simple consulta al SCM.
    service_state: ServiceInstallState,
    service_action_error: Option<String>,

    /// Si `openvpn.exe` (motor OpenVPN Community) esta instalado. Se
    /// comprueba una vez al inicio; el flujo de instalacion (ver
    /// `openvpn_install`) lo reconsulta al terminar.
    openvpn_installed: bool,
    openvpn_install_state: OpenVpnInstallUiState,
    openvpn_install_rx: Option<tokio::sync::mpsc::UnboundedReceiver<InstallEvent>>,

    /// `None` si no se pudo crear (ver `tray::init`): la app sigue
    /// funcionando igual, pero cerrar con la X termina el proceso de verdad
    /// en vez de minimizar a bandeja, porque sin icono no habria forma de
    /// volver a abrir la ventana.
    _tray: Option<AppTray>,
    /// Solo se pone a `true` desde la opcion "Cerrar" del menu del icono de
    /// bandeja; distingue ese cierre real de un simple clic en la X de la
    /// ventana (ver el manejo de `close_requested` en `update`). Es
    /// `Arc<AtomicBool>` en vez de un `bool` normal porque el manejador de
    /// eventos del tray (`tray::init`) la escribe desde el hilo de
    /// mensajes de Windows, fuera del ciclo de `update` de egui.
    quit_requested: Arc<AtomicBool>,

    preferences: storage::AppPreferences,
    /// Se pone a `true` en `drain_events` al llegar a "Conectado" si
    /// `preferences.minimize_on_connect` esta activo; `update` lo consume
    /// el mismo frame para pedir `ViewportCommand::Visible(false)` (con
    /// `ctx`, que no esta disponible dentro de `drain_events`).
    minimize_pending: bool,
}

impl PorteroApp {
    pub fn new() -> Self {
        let rt = tokio::runtime::Runtime::new().expect("no se pudo crear el runtime de tokio");
        let registry = Arc::new(CheckRegistry::new());
        let mut policy = storage::load_policy().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "no se pudo cargar policy.toml, usando politica por defecto");
            SecurityPolicy::bootstrap_default()
        });
        // Reconciliacion con `policy.toml` ya guardados de antes de que
        // existiera este check: sin esto, uno nuevo en el registro pero
        // ausente del policy.toml del usuario ni se mostraria en
        // Configuracion (la pantalla solo pinta los checks que encuentra en
        // `policy.checks`, ver `render_settings_screen`). Desactivado por
        // defecto -- activarlo es una eleccion del usuario, no algo que deba
        // aparecer ya obligatorio tras una actualizacion silenciosa.
        let mut policy_needs_save = false;
        for check in registry.all() {
            if !policy.checks.iter().any(|c| c.id == check.id()) {
                policy.checks.push(storage::CheckConfig {
                    id: check.id().to_string(),
                    enabled: false,
                    mandatory: false,
                });
                policy_needs_save = true;
            }
        }
        if policy_needs_save {
            if let Err(e) = storage::save_policy(&policy) {
                tracing::warn!(error = %e, "no se pudo guardar policy.toml tras anadir checks nuevos");
            }
        }
        let profiles = storage::list_profiles().unwrap_or_default();
        // Foco inicial en la ultima conexion usada (la de `last_connected_at`
        // mas reciente), para que el boton CONECTAR de abajo ya apunte a
        // ella sin tener que elegir la fila a mano cada vez que se abre la
        // app. `None` si no hay ninguna conexion con fecha (perfiles recien
        // importados sin usar todavia).
        let selected_profile =
            profiles.iter().filter(|p| p.last_connected_at.is_some()).max_by_key(|p| p.last_connected_at).map(|p| p.id);
        let first_run = match storage::read_config_password_hash() {
            Ok(None) => Some(FirstRunState { password: String::new(), confirm: String::new(), error: None }),
            _ => None,
        };
        let service_state = service_ctl::query_state();
        let service_warning = rt.block_on(SvcClient::ping()).err().map(|e| e.to_string());
        let quit_requested = Arc::new(AtomicBool::new(false));
        let preferences = storage::load_preferences().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "no se pudo cargar preferences.toml, usando valores por defecto");
            storage::AppPreferences::default()
        });

        Self {
            rt,
            registry,
            wmi: Arc::new(checks::antivirus::WindowsWmiDataSource),
            policy,
            profiles,
            screen: Screen::Connections,
            active: None,
            selected_profile,
            error_modal: None,
            import_draft: None,
            import_error: None,
            edit_draft: None,
            edit_error: None,
            settings_unlocked: false,
            settings_password_input: String::new(),
            settings_error: None,
            first_run,
            change_password: ChangePasswordState::default(),
            show_log_window: false,
            service_warning,
            service_state,
            service_action_error: None,
            openvpn_installed: openvpn_install::is_installed(),
            openvpn_install_state: OpenVpnInstallUiState::Idle,
            openvpn_install_rx: None,
            _tray: tray::init(quit_requested.clone()),
            quit_requested,
            preferences,
            minimize_pending: false,
        }
    }

    /// Reconsulta el estado del servicio tras instalar/reinstalar/
    /// desinstalar, o al reintentar desde el banner de aviso.
    fn refresh_service_status(&mut self) {
        self.service_state = service_ctl::query_state();
        self.service_warning = self.rt.block_on(SvcClient::ping()).err().map(|e| e.to_string());
    }

    fn run_service_action(&mut self, action: &'static str) {
        match service_ctl::run_elevated(action) {
            Ok(()) => self.service_action_error = None,
            Err(e) => self.service_action_error = Some(e.to_string()),
        }
        self.refresh_service_status();
    }

    /// Descarta cualquier intento anterior (p.ej. tras un error) y lanza el
    /// flujo de instalacion de OpenVPN en segundo plano; el progreso llega
    /// por `openvpn_install_rx`, drenado en `drain_openvpn_install_events`.
    fn start_openvpn_install(&mut self) {
        let _guard = self.rt.enter();
        self.openvpn_install_rx = Some(openvpn_install::spawn_install());
        self.openvpn_install_state =
            OpenVpnInstallUiState::Working("Buscando la ultima version de OpenVPN...".to_string());
    }

    fn drain_openvpn_install_events(&mut self) {
        let Some(rx) = self.openvpn_install_rx.as_mut() else { return };

        while let Ok(event) = rx.try_recv() {
            match event {
                InstallEvent::Status(message) => self.openvpn_install_state = OpenVpnInstallUiState::Working(message),
                InstallEvent::Done => {
                    self.openvpn_install_state = OpenVpnInstallUiState::Idle;
                    self.openvpn_install_rx = None;
                    self.openvpn_installed = openvpn_install::is_installed();
                    return;
                }
                InstallEvent::Error(message) => {
                    self.openvpn_install_state = OpenVpnInstallUiState::Error(message);
                    self.openvpn_install_rx = None;
                    return;
                }
            }
        }
    }

    fn drain_events(&mut self) {
        let Some(active) = self.active.as_mut() else { return };

        while let Ok(event) = active.events_rx.try_recv() {
            match event {
                AppEvent::ChecksStarted => {
                    active.phase = ConnectionPhase::RunningChecks;
                    active.check_results.clear();
                }
                AppEvent::CheckResult(result) => active.check_results.push(result),
                AppEvent::ChecksFailed(reason) => {
                    active.phase = ConnectionPhase::ChecksFailed;
                    self.error_modal = Some(ErrorModal {
                        title: "No se puede conectar".to_string(),
                        message: reason,
                        profile_id: active.profile_id,
                        can_forget_credentials: false,
                    });
                }
                AppEvent::Connecting { last_state } => active.phase = ConnectionPhase::Connecting { last_state },
                AppEvent::NeedsCredentials { context } => {
                    active.pending_credentials = Some(CredentialForm {
                        context,
                        username: String::new(),
                        password: String::new(),
                        remember: false,
                    });
                }
                AppEvent::LogLine(line) => {
                    active.log_lines.push_back(line);
                    while active.log_lines.len() > MAX_LOG_LINES {
                        active.log_lines.pop_front();
                    }
                }
                AppEvent::ByteCount { bytes_in, bytes_out } => {
                    active.bytes_in = bytes_in;
                    active.bytes_out = bytes_out;
                }
                AppEvent::Connected { local_ip, remote_ip } => {
                    active.phase = ConnectionPhase::Connected { local_ip, remote_ip, since: Instant::now() };
                    if let Some(meta) = self.profiles.iter_mut().find(|p| p.id == active.profile_id) {
                        meta.last_connected_at = Some(chrono::Utc::now());
                        let _ = storage::save_profile_meta(meta);
                    }
                    if self.preferences.minimize_on_connect {
                        self.minimize_pending = true;
                    }
                }
                AppEvent::AuthFailed => {
                    active.phase = ConnectionPhase::AuthFailed;
                    let can_forget_credentials =
                        self.profiles.iter().any(|p| p.id == active.profile_id && p.remember_credentials);
                    self.error_modal = Some(ErrorModal {
                        title: "Autenticacion fallida".to_string(),
                        message: "Usuario o contrasena incorrectos.".to_string(),
                        profile_id: active.profile_id,
                        can_forget_credentials,
                    });
                }
                AppEvent::CertificateError(detail) => {
                    let message = format!("No se pudo verificar el certificado del servidor: {detail}");
                    active.phase = ConnectionPhase::Failed;
                    self.error_modal = Some(ErrorModal {
                        title: "Error de certificado".to_string(),
                        message,
                        profile_id: active.profile_id,
                        can_forget_credentials: false,
                    });
                }
                AppEvent::ReconnectLoop(attempts) => {
                    let message = format!("El servidor rechaza la conexion repetidamente (intentos: {attempts}).");
                    active.phase = ConnectionPhase::Failed;
                    self.error_modal = Some(ErrorModal {
                        title: "Conexion rechazada".to_string(),
                        message,
                        profile_id: active.profile_id,
                        can_forget_credentials: false,
                    });
                }
                AppEvent::Error(message) => {
                    active.phase = ConnectionPhase::Failed;
                    self.error_modal = Some(ErrorModal {
                        title: "Error de conexion".to_string(),
                        message,
                        profile_id: active.profile_id,
                        can_forget_credentials: false,
                    });
                }
                AppEvent::Disconnected => {
                    self.active = None;
                    return;
                }
            }
        }
    }

    fn start_connection(&mut self, profile: ProfileMeta) {
        let stored_credentials = credentials::load_for_profile(&profile).ok().flatten();

        let _guard = self.rt.enter();
        let (events_rx, handle) = connection::spawn_connection(
            profile.clone(),
            self.policy.clone(),
            Arc::clone(&self.registry),
            Arc::clone(&self.wmi),
            stored_credentials,
        );

        self.active = Some(ActiveConnection {
            profile_id: profile.id,
            display_name: profile.display_name.clone(),
            phase: ConnectionPhase::RunningChecks,
            check_results: Vec::new(),
            log_lines: VecDeque::new(),
            bytes_in: 0,
            bytes_out: 0,
            handle,
            events_rx,
            pending_credentials: None,
        });
    }

    /// Abre el selector de fichero nativo para importar un perfil `.ovpn`
    /// (disparado desde el boton "+ Importar perfil .ovpn" del menu
    /// superior). Si el usuario elige un fichero, prepara el borrador que
    /// `render_import_dialog` pinta a continuacion.
    fn request_profile_import(&mut self) {
        if let Some(path) = rfd::FileDialog::new().add_filter("OpenVPN", &["ovpn"]).pick_file() {
            let default_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("Perfil").to_string();
            self.import_draft = Some(ImportDraft {
                source_path: path,
                display_name: default_name,
                remember_credentials: false,
                username: String::new(),
                password: String::new(),
            });
        }
    }

    fn disconnect_active(&mut self) {
        if let Some(active) = &self.active {
            let _ = active.handle.cancel_tx.send(true);
        }
    }
}

impl eframe::App for PorteroApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.drain_events();
        self.drain_openvpn_install_events();

        // Le hace falta al manejador de eventos del tray (ver
        // `tray::init`/`AppTray::set_main_window`) para poder mostrar la
        // ventana desde fuera del ciclo de `update`. Solo se puede pedir
        // aqui (mientras `update` se esta ejecutando, o sea, con la
        // ventana visible), asi que se refresca cada frame por si acaso
        // cambia el handle (no deberia, pero es una simple escritura
        // atomica, no hay coste real en repetirla).
        if let Some(tray) = &self._tray {
            if let Ok(handle) = frame.window_handle() {
                if let RawWindowHandle::Win32(win32) = handle.as_raw() {
                    tray.set_main_window(win32.hwnd.get());
                }
            }

            let connected = matches!(
                self.active.as_ref().map(|a| &a.phase),
                Some(ConnectionPhase::Connected { .. })
            );
            tray.set_connected(connected);
        }

        // Si se esta ejecutando `update`, la ventana tiene que estar
        // visible (pintar requiere `WS_VISIBLE`, ver comentario de
        // `tray::init`). El manejador del tray la vuelve a mostrar en
        // crudo, sin pasar por `egui`/`winit`, asi que esto realinea su
        // idea de la visibilidad con la realidad -- inofensivo cuando ya
        // coincide, evita que quede desincronizada tras un "Panel".
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));

        // Clic en la X de la ventana: si no ha sido "Cerrar" desde el menu
        // de bandeja, se cancela el cierre real y se oculta la ventana en
        // su lugar (minimizado a bandeja). El icono de bandeja sigue vivo
        // (es un campo de `PorteroApp`, no se suelta), asi que "Panel" la
        // puede volver a mostrar.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quit_requested.load(Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // "Minimizar al conectar" (Configuracion): puesto por `drain_events`
        // al ver `AppEvent::Connected`. Solo si hay icono de bandeja -- sin
        // el no habria forma de volver a mostrar la ventana (ver "Panel").
        if self.minimize_pending {
            self.minimize_pending = false;
            if self._tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        }

        if self.first_run.is_some() {
            self.render_first_run_gate(ctx);
        } else {
            egui::TopBottomPanel::top("top_bar").show(ctx, |ui| self.render_top_bar(ui));

            egui::CentralPanel::default().show(ctx, |ui| match self.screen {
                Screen::Connections => {
                    self.render_connections_screen(ui);
                    self.render_bottom_bar(ui);
                }
                Screen::Settings => self.render_settings_screen(ui),
            });

            self.render_import_dialog(ctx);
            self.render_edit_dialog(ctx);
            self.render_credential_modal(ctx);
            self.render_error_modal(ctx);

            if self.show_log_window {
                self.render_log_window(ctx);
            }
        }

        // Repintado periodico incondicional (no solo con conexion activa):
        // necesario para seguir sondeando el menu de bandeja y detectar el
        // cierre por la X mientras la ventana esta oculta, cuando de otro
        // modo no llegaria ningun evento que despertara el frame siguiente.
        let repaint_interval = if self.active.is_some() || self.openvpn_install_rx.is_some() {
            std::time::Duration::from_millis(200)
        } else {
            std::time::Duration::from_millis(300)
        };
        ctx.request_repaint_after(repaint_interval);
    }
}

impl PorteroApp {
    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        // `allocate_new_ui` con un `max_rect` explicito (el mismo patron que
        // la fila de perfiles, ver `render_connections_screen`): un
        // `ui.horizontal` normal sin acotar antes le da a sus hijos un
        // ancho maximo no acotado (piensa que puede crecer sin limite), asi
        // que un `with_layout(right_to_left)` anidado directamente dentro
        // se alinea contra ese borde "infinito" en vez del borde real de la
        // ventana -- se queda invisible, fuera de pantalla (comprobado en
        // la practica: sin este acotado, ni el icono de la rueda ni nada
        // puesto ahi llegaba a pintarse).
        let bar_rect = ui.max_rect();
        ui.allocate_new_ui(egui::UiBuilder::new().max_rect(bar_rect), |ui| {
            ui.horizontal(|ui| {
                if ui.selectable_label(self.screen == Screen::Connections, "Conexiones").clicked() {
                    self.screen = Screen::Connections;
                }
                // `selectable_label` con `false` fijo (nunca "seleccionado"):
                // es una accion, no una pestana, pero con la misma
                // apariencia que Conexiones para que el menu superior quede
                // uniforme.
                if ui.selectable_label(false, "Importar ovpn").clicked() {
                    self.request_profile_import();
                }
                // Configuracion, sola, justificada del todo al borde
                // derecho: como rueda dentada en vez de texto para que
                // quede claramente distinta de las dos acciones de la
                // izquierda.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .selectable_label(self.screen == Screen::Settings, RichText::new("\u{2699}").size(16.0))
                        .on_hover_text("Configuracion")
                        .clicked()
                    {
                        self.screen = Screen::Settings;
                    }
                });
            });
        });
        ui.add_space(4.0);
    }

    /// Boton unico de accion, a todo lo ancho, fijo en la parte inferior de
    /// la ventana. Actua sobre la conexion activa si hay una, o sobre el
    /// perfil seleccionado en la lista si no. Desactivado si el servicio no
    /// esta instalado (no se puede conectar sin el) o si no hay perfil
    /// elegido.
    ///
    /// Dibujado a mano con `ui.painter()` + lectura directa del puntero (via
    /// `ui.ctx().input`) en vez de un `Button` normal: en esta ventana de
    /// tamano fijo, los widgets normales (y hasta un `Area`/`TopBottomPanel`
    /// propios) dejaban de pintarse cerca del borde inferior (bug de layout
    /// no resuelto). Pintar desde este mismo `ui` -el de `CentralPanel`- si
    /// funciona en cualquier posicion, confirmado con marcadores de
    /// diagnostico; por eso se llama desde dentro de
    /// `render_connections_screen` en vez de como panel/area aparte.
    fn render_bottom_bar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let bar_height = 90.0;
        // `ui.max_rect()` (el rect de CentralPanel) en vez de
        // `ctx.screen_rect()`: es la referencia que coincide con lo que de
        // verdad se pinta en pantalla en esta ventana.
        let screen = ui.max_rect();
        let bar_rect = egui::Rect::from_min_max(
            egui::pos2(screen.left(), screen.bottom() - bar_height),
            screen.right_bottom(),
        );
        let button_rect = egui::Rect::from_center_size(
            egui::pos2(bar_rect.center().x, bar_rect.bottom() - 34.0),
            egui::vec2(bar_rect.width() - 32.0, 46.0),
        );

        let pointer_pos = ctx.input(|i| i.pointer.interact_pos());
        let hovered = pointer_pos.is_some_and(|p| button_rect.contains(p));
        let clicked = hovered && ctx.input(|i| i.pointer.primary_clicked());
        if hovered {
            ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
        }

        let (status, label, fill, enabled, disabled_reason) = if let Some(active) = &self.active {
            let is_connected = matches!(active.phase, ConnectionPhase::Connected { .. });
            let status = match &active.phase {
                ConnectionPhase::RunningChecks => "Comprobando seguridad...".to_string(),
                ConnectionPhase::Connecting { last_state } => format!("Conectando... ({last_state})"),
                ConnectionPhase::Connected { .. } => format!("Conectado a {}", active.display_name),
                ConnectionPhase::ChecksFailed | ConnectionPhase::AuthFailed | ConnectionPhase::Failed => {
                    "La conexion fallo".to_string()
                }
            };
            let label = if is_connected { "DESCONECTAR" } else { "CANCELAR CONEXION" };
            (status, label, theme::DANGER, true, None)
        } else {
            let service_ready = self.service_state != ServiceInstallState::NotInstalled;
            let selected = self.selected_profile.and_then(|id| self.profiles.iter().find(|p| p.id == id));
            let status = if let Some(profile) = selected {
                format!("Listo para conectar: {}", profile.display_name)
            } else if self.profiles.is_empty() {
                "Importa un perfil .ovpn para empezar".to_string()
            } else {
                "Elige una conexion de la lista".to_string()
            };
            let can_connect = service_ready && self.openvpn_installed && selected.is_some();
            let reason = if !service_ready {
                Some("Instala el servicio PorteroVPNSvc para poder conectar.")
            } else if !self.openvpn_installed {
                Some("Instala OpenVPN Community para poder conectar.")
            } else if selected.is_none() {
                Some("Elige una conexion de la lista.")
            } else {
                None
            };
            (status, "CONECTAR", theme::ACCENT, can_connect, reason)
        };

        let button_fill = if !enabled {
            theme::SURFACE_RAISED
        } else if hovered {
            fill.linear_multiply(1.15)
        } else {
            fill
        };
        let text_color = if enabled { Color32::WHITE } else { Color32::from_gray(120) };

        let painter = ui.painter();
        painter.rect_filled(bar_rect, 0.0, theme::SURFACE);
        painter.hline(bar_rect.x_range(), bar_rect.top(), egui::Stroke::new(1.0_f32, theme::SURFACE_RAISED));
        painter.text(
            egui::pos2(bar_rect.center().x, bar_rect.top() + 20.0),
            egui::Align2::CENTER_CENTER,
            &status,
            egui::FontId::proportional(13.0),
            theme::WARNING,
        );
        painter.rect_filled(button_rect, egui::Rounding::same(8.0), button_fill);
        painter.text(
            button_rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(15.0),
            text_color,
        );
        // Reserva la region para que el `Ui` de CentralPanel sepa que este
        // espacio esta ocupado (evita que otro contenido se solape con la
        // barra inferior).
        ui.allocate_rect(bar_rect, egui::Sense::hover());

        if !enabled {
            if let Some(reason) = disabled_reason {
                if hovered {
                    egui::show_tooltip_at_pointer(
                        &ctx,
                        egui::LayerId::new(egui::Order::Tooltip, egui::Id::new("bottom_bar_tip")),
                        egui::Id::new("bottom_bar_tip_id"),
                        |ui| {
                            ui.label(reason);
                        },
                    );
                }
            }
        }

        if clicked && enabled {
            if self.active.is_some() {
                self.disconnect_active();
            } else if let Some(profile) =
                self.selected_profile.and_then(|id| self.profiles.iter().find(|p| p.id == id).cloned())
            {
                self.start_connection(profile);
            }
        }
        ctx.request_repaint(); // asegura que el hover/click se refleje sin esperar a otro evento
    }

    fn render_connections_screen(&mut self, ui: &mut egui::Ui) {
        if self.service_state == ServiceInstallState::NotInstalled {
            ui.colored_label(
                theme::WARNING,
                "El servicio PorteroVPNSvc no esta instalado todavia: hace falta para poder conectar.",
            );
            if ui.button("Instalar servicio").clicked() {
                self.run_service_action("install");
            }
            if let Some(error) = &self.service_action_error {
                ui.colored_label(theme::DANGER, error);
            }
            ui.separator();
        } else if let Some(warning) = &self.service_warning {
            ui.colored_label(
                theme::DANGER,
                format!("El servicio PorteroVPNSvc esta instalado pero no responde: {warning}"),
            );
            ui.separator();
        }

        if !self.openvpn_installed {
            match &self.openvpn_install_state {
                OpenVpnInstallUiState::Idle => {
                    ui.colored_label(
                        theme::WARNING,
                        "OpenVPN Community no esta instalado todavia: hace falta para poder conectar.",
                    );
                    if ui.button("Instalar OpenVPN").clicked() {
                        self.start_openvpn_install();
                    }
                }
                OpenVpnInstallUiState::Working(status) => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(status);
                    });
                }
                OpenVpnInstallUiState::Error(error) => {
                    ui.colored_label(theme::DANGER, format!("No se pudo instalar OpenVPN: {error}"));
                    if ui.button("Reintentar").clicked() {
                        self.start_openvpn_install();
                    }
                }
            }
            ui.separator();
        }

        if let Some(error) = &self.import_error {
            ui.colored_label(theme::DANGER, error);
        }
        if let Some(error) = &self.edit_error {
            ui.colored_label(theme::DANGER, error);
        }

        ui.separator();

        if self.profiles.is_empty() {
            ui.label("Todavia no has importado ningun perfil .ovpn.");
        }

        // Alto maximo para que la lista haga scroll en vez de empujar el
        // resto de la pantalla (y el boton inferior, pintado aparte) fuera
        // de la ventana cuando hay muchos perfiles.
        let list_max_height = (ui.available_height() - 140.0).max(80.0);
        egui::ScrollArea::vertical().max_height(list_max_height).show(ui, |ui| {
            let profiles = self.profiles.clone();
            for profile in &profiles {
                self.render_profile_row(ui, profile);
            }
        });

        if let Some(active) = &self.active {
            ui.separator();
            ui.heading(format!("Conectando a {}", active.display_name));
        }
        self.render_active_connection_card(ui);
    }

    /// Fila de perfil: seleccionable con un clic (arma el boton unico
    /// "CONECTAR" de abajo sobre este perfil). "Editar"/"Eliminar" siguen
    /// siendo acciones por fila (como iconos que solo aparecen al pasar el
    /// cursor), ya que no tiene sentido un boton global para ellas. Toda la
    /// fila es clicable para seleccionar el perfil.
    fn render_profile_row(&mut self, ui: &mut egui::Ui, profile: &ProfileMeta) {
        let is_active = self.active.as_ref().is_some_and(|a| a.profile_id == profile.id);
        let is_selected = self.selected_profile == Some(profile.id);

        let row_height = 38.0;
        let row_rect =
            egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), row_height));
        let hovered = ui.rect_contains_pointer(row_rect);

        let row_id = ui.id().with(("profile_row", profile.id));
        let row_response = ui.interact(row_rect, row_id, egui::Sense::click());
        if row_response.clicked() {
            self.selected_profile = Some(profile.id);
        }

        let bg = if is_selected {
            theme::SURFACE_RAISED
        } else if hovered {
            theme::SURFACE_RAISED.gamma_multiply(0.6)
        } else {
            Color32::TRANSPARENT
        };
        ui.painter().rect_filled(row_rect, egui::Rounding::same(6.0), bg);
        if is_selected {
            ui.painter().rect_stroke(row_rect, egui::Rounding::same(6.0), egui::Stroke::new(1.5_f32, theme::ACCENT));
        }

        let (status_color, status_text) = if is_active {
            match &self.active.as_ref().unwrap().phase {
                ConnectionPhase::RunningChecks => (theme::WARNING, "Comprobando..."),
                ConnectionPhase::Connecting { .. } => (theme::WARNING, "Conectando..."),
                ConnectionPhase::Connected { .. } => (theme::SUCCESS, "Conectado"),
                ConnectionPhase::ChecksFailed | ConnectionPhase::Failed | ConnectionPhase::AuthFailed => {
                    (theme::DANGER, "Error")
                }
            }
        } else {
            (Color32::GRAY, "")
        };

        let mut edit_requested = false;
        let mut delete_requested = false;

        ui.allocate_new_ui(egui::UiBuilder::new().max_rect(row_rect), |ui| {
            ui.horizontal_centered(|ui| {
                ui.add_space(10.0);
                ui.colored_label(status_color, "\u{25CF}");
                ui.add_space(2.0);
                ui.add(egui::Label::new(RichText::new(&profile.display_name).strong()).truncate());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(10.0);
                    if hovered && !is_active {
                        let icon_button = |ui: &mut egui::Ui, icon: &str| {
                            ui.add(egui::Button::new(RichText::new(icon).size(15.0)).frame(false)).clicked()
                        };
                        if icon_button(ui, "\u{1F5D1}") {
                            delete_requested = true;
                        }
                        if icon_button(ui, "\u{270F}") {
                            edit_requested = true;
                        }
                    } else if !status_text.is_empty() {
                        ui.label(RichText::new(status_text).small().color(status_color));
                    }
                });
            });
        });

        ui.advance_cursor_after_rect(row_rect);

        if delete_requested {
            let _ = storage::delete_profile(profile.id);
            self.profiles.retain(|p| p.id != profile.id);
            if self.selected_profile == Some(profile.id) {
                self.selected_profile = None;
            }
        }
        if edit_requested {
            let stored = credentials::load_for_profile(profile).ok().flatten();
            self.edit_draft = Some(EditDraft {
                profile_id: profile.id,
                display_name: profile.display_name.clone(),
                remember_credentials: profile.remember_credentials,
                username: stored.as_ref().map(|c| c.username.clone()).unwrap_or_default(),
                password: stored.as_ref().map(|c| c.password.clone()).unwrap_or_default(),
            });
            self.edit_error = None;
        }
    }

    /// Progreso de la conexion activa (comprobaciones / conectando /
    /// conectado). Los errores ya no se muestran aqui: van al modal
    /// centrado (`render_error_modal`), que ademas se dispara en el mismo
    /// instante en que ocurren (ver `drain_events`).
    fn render_active_connection_card(&mut self, ui: &mut egui::Ui) {
        let Some(active) = &self.active else { return };
        let check_results = active.check_results.clone();
        let phase = active.phase.clone();
        let bytes_in = active.bytes_in;
        let bytes_out = active.bytes_out;

        let mut show_log_requested = false;

        ui.add_space(8.0);
        egui::Frame::group(ui.style()).rounding(10.0).show(ui, |ui| {
            ui.set_width(ui.available_width());

            if !check_results.is_empty() {
                ui.label(RichText::new("Comprobaciones de seguridad").strong());
                for result in &check_results {
                    let (color, symbol) = match &result.outcome {
                        CheckOutcome::Pass => (theme::SUCCESS, "\u{2714}"),
                        CheckOutcome::Fail { .. } | CheckOutcome::Indeterminate { .. } => (theme::DANGER, "\u{2716}"),
                    };
                    ui.horizontal(|ui| {
                        ui.colored_label(color, symbol);
                        ui.label(&result.display_name);
                        if let CheckOutcome::Fail { reason } | CheckOutcome::Indeterminate { reason } = &result.outcome {
                            ui.label(RichText::new(reason).color(theme::DANGER).italics());
                        }
                    });
                }
                ui.separator();
            }

            match &phase {
                ConnectionPhase::RunningChecks => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Ejecutando comprobaciones de seguridad...");
                    });
                }
                ConnectionPhase::Connecting { last_state } => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!("Conectando... ({last_state})"));
                    });
                }
                ConnectionPhase::Connected { local_ip, remote_ip, since } => {
                    let elapsed = since.elapsed();
                    ui.colored_label(theme::SUCCESS, "Conectado");
                    ui.label(format!("IP local: {}", local_ip.clone().unwrap_or_else(|| "-".into())));
                    ui.label(format!("Servidor: {}", remote_ip.clone().unwrap_or_else(|| "-".into())));
                    ui.label(format!("Tiempo conectado: {}s", elapsed.as_secs()));
                    ui.label(format!(
                        "Trafico: {} recibidos / {} enviados",
                        format_bytes(bytes_in),
                        format_bytes(bytes_out)
                    ));
                }
                ConnectionPhase::ChecksFailed | ConnectionPhase::AuthFailed | ConnectionPhase::Failed => {
                    ui.colored_label(theme::DANGER, "Ver el aviso de error.");
                }
            }

            ui.horizontal(|ui| {
                if ui.button("Ver log de conexion").clicked() {
                    show_log_requested = true;
                }
            });
        });

        if show_log_requested {
            self.show_log_window = true;
        }
    }

    /// Formulario de credenciales VPN, en un modal centrado sobre la
    /// ventana (con fondo atenuado) en vez de incrustado en la tarjeta de
    /// conexion.
    fn render_credential_modal(&mut self, ctx: &egui::Context) {
        let Some(active) = self.active.as_mut() else { return };
        let Some(mut form) = active.pending_credentials.take() else { return };

        draw_modal_backdrop(ctx);

        let mut submitted = false;
        egui::Window::new("Credenciales requeridas")
            .id(egui::Id::new("credential_modal"))
            .collapsible(false)
            .resizable(false)
            // Tamano explicito y fijo en vez de dejar que `Window` lo
            // calcule solo: `auto_sized()` se probo y, por como `Window`
            // persiste el tamano "deseado" entre frames (solo puede crecer,
            // nunca encoger, salvo que se fije min==max==tamano), acababa
            // ocupando todo el alto disponible. `fixed_size` fuerza
            // min_size == max_size == este tamano en cada frame, ignorando
            // cualquier valor mas grande que hubiera quedado en memoria de
            // antes. `vscroll(true)` es solo red de seguridad por si el
            // texto del contexto es muy largo y no cabe.
            .fixed_size(egui::vec2(240.0, 220.0))
            .vscroll(true)
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(format!("La conexion VPN pide usuario y contrasena ({}).", form.context));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("Usuario:");
                    ui.text_edit_singleline(&mut form.username);
                });
                ui.horizontal(|ui| {
                    ui.label("Contrasena:");
                    ui.add(egui::TextEdit::singleline(&mut form.password).password(true));
                });
                ui.checkbox(&mut form.remember, "Recordar credenciales en este equipo");

                ui.add_space(4.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!form.username.is_empty(), egui::Button::new("Conectar")).clicked() {
                        submitted = true;
                    }
                });
            });

        if submitted {
            let credentials = Credentials { username: form.username.clone(), password: form.password.clone() };
            let _ = active.handle.credentials_tx.try_send(credentials.clone());

            if form.remember {
                if let Ok(mut meta) = storage::load_profile(active.profile_id) {
                    if credentials::save_for_profile(&mut meta, &credentials).is_ok() {
                        let _ = storage::save_profile_meta(&meta);
                    }
                }
            }
        } else {
            active.pending_credentials = Some(form);
        }
    }

    /// Modal centrado de error de conexion (plan, seccion 7): comprobacion
    /// de seguridad incumplida, autenticacion fallida, certificado invalido
    /// o cualquier otro fallo. Se dispara desde `drain_events` en el mismo
    /// instante en que llega el evento correspondiente.
    fn render_error_modal(&mut self, ctx: &egui::Context) {
        let Some(modal) = &self.error_modal else { return };
        let title = modal.title.clone();
        let message = modal.message.clone();
        let profile_id = modal.profile_id;
        let can_forget_credentials = modal.can_forget_credentials;

        draw_modal_backdrop(ctx);

        let mut close_requested = false;
        let mut retry_requested = false;
        let mut forget_requested = false;

        egui::Window::new(&title)
            .id(egui::Id::new("error_modal"))
            .collapsible(false)
            .resizable(false)
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.set_width(280.0);
                ui.colored_label(theme::DANGER, &message);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Reintentar").clicked() {
                        retry_requested = true;
                    }
                    if can_forget_credentials && ui.button("Olvidar credenciales").clicked() {
                        forget_requested = true;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Cerrar").clicked() {
                            close_requested = true;
                        }
                    });
                });
            });

        if forget_requested {
            if let Ok(mut meta) = storage::load_profile(profile_id) {
                credentials::forget_for_profile(&mut meta);
                let _ = storage::save_profile_meta(&meta);
                if let Some(cached) = self.profiles.iter_mut().find(|p| p.id == profile_id) {
                    cached.remember_credentials = false;
                    cached.credentials_blob = None;
                }
            }
        }

        if retry_requested {
            self.error_modal = None;
            self.active = None;
            if let Some(profile) = self.profiles.iter().find(|p| p.id == profile_id).cloned() {
                self.start_connection(profile);
            }
        } else if close_requested {
            self.error_modal = None;
            self.active = None;
        }
    }

    fn render_import_dialog(&mut self, ctx: &egui::Context) {
        let Some(draft) = &mut self.import_draft else { return };
        let mut open = true;
        let mut confirmed = false;
        let mut cancelled = false;

        egui::Window::new("Importar perfil .ovpn").collapsible(false).resizable(false).open(&mut open).show(ctx, |ui| {
            ui.label(format!("Archivo: {}", draft.source_path.display()));
            ui.horizontal(|ui| {
                ui.label("Nombre:");
                ui.text_edit_singleline(&mut draft.display_name);
            });
            ui.checkbox(&mut draft.remember_credentials, "Recordar credenciales para este perfil");

            if draft.remember_credentials {
                ui.horizontal(|ui| {
                    ui.label("Usuario:");
                    ui.text_edit_singleline(&mut draft.username);
                });
                ui.horizontal(|ui| {
                    ui.label("Contrasena:");
                    ui.add(egui::TextEdit::singleline(&mut draft.password).password(true));
                });
            }

            let can_import = !draft.remember_credentials || (!draft.username.is_empty() && !draft.password.is_empty());
            ui.horizontal(|ui| {
                if ui.add_enabled(can_import, egui::Button::new("Importar")).clicked() {
                    confirmed = true;
                }
                if ui.button("Cancelar").clicked() {
                    cancelled = true;
                }
            });
        });

        if confirmed {
            let draft = self.import_draft.take().unwrap();
            match storage::import_profile(&draft.source_path, draft.display_name, draft.remember_credentials) {
                Ok(mut meta) => {
                    if draft.remember_credentials {
                        let creds = Credentials { username: draft.username, password: draft.password };
                        if let Err(e) = credentials::save_for_profile(&mut meta, &creds) {
                            self.import_error = Some(format!("Perfil importado, pero no se pudieron guardar las credenciales: {e}"));
                        } else if let Err(e) = storage::save_profile_meta(&meta) {
                            self.import_error = Some(format!("Perfil importado, pero no se pudieron guardar las credenciales: {e}"));
                        } else {
                            self.import_error = None;
                        }
                    } else {
                        self.import_error = None;
                    }
                    self.selected_profile = Some(meta.id);
                    self.profiles.push(meta);
                    self.profiles.sort_by(|a, b| a.display_name.cmp(&b.display_name));
                }
                Err(e) => self.import_error = Some(format!("No se pudo importar el perfil: {e}")),
            }
        } else if cancelled || !open {
            self.import_draft = None;
        }
    }

    fn render_edit_dialog(&mut self, ctx: &egui::Context) {
        let Some(draft) = &mut self.edit_draft else { return };
        let mut open = true;
        let mut confirmed = false;
        let mut cancelled = false;

        egui::Window::new("Editar conexion").collapsible(false).resizable(false).open(&mut open).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Nombre:");
                ui.text_edit_singleline(&mut draft.display_name);
            });
            ui.checkbox(&mut draft.remember_credentials, "Recordar credenciales para este perfil");

            if draft.remember_credentials {
                ui.horizontal(|ui| {
                    ui.label("Usuario:");
                    ui.text_edit_singleline(&mut draft.username);
                });
                ui.horizontal(|ui| {
                    ui.label("Contrasena:");
                    ui.add(egui::TextEdit::singleline(&mut draft.password).password(true));
                });
            }

            let can_save = !draft.display_name.trim().is_empty()
                && (!draft.remember_credentials || (!draft.username.is_empty() && !draft.password.is_empty()));
            ui.horizontal(|ui| {
                if ui.add_enabled(can_save, egui::Button::new("Guardar")).clicked() {
                    confirmed = true;
                }
                if ui.button("Cancelar").clicked() {
                    cancelled = true;
                }
            });
        });

        if confirmed {
            let draft = self.edit_draft.take().unwrap();
            match storage::load_profile(draft.profile_id) {
                Ok(mut meta) => {
                    meta.display_name = draft.display_name;
                    if draft.remember_credentials {
                        let creds = Credentials { username: draft.username, password: draft.password };
                        if let Err(e) = credentials::save_for_profile(&mut meta, &creds) {
                            self.edit_error = Some(format!("No se pudieron guardar las credenciales: {e}"));
                            return;
                        }
                    } else {
                        credentials::forget_for_profile(&mut meta);
                    }

                    if let Err(e) = storage::save_profile_meta(&meta) {
                        self.edit_error = Some(format!("No se pudo guardar el perfil: {e}"));
                        return;
                    }

                    if let Some(cached) = self.profiles.iter_mut().find(|p| p.id == meta.id) {
                        *cached = meta;
                    }
                    self.profiles.sort_by(|a, b| a.display_name.cmp(&b.display_name));
                    self.edit_error = None;
                }
                Err(e) => self.edit_error = Some(format!("No se pudo cargar el perfil: {e}")),
            }
        } else if cancelled || !open {
            self.edit_draft = None;
        }
    }

    fn render_log_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_log_window;
        egui::Window::new("Log de conexion").open(&mut open).default_height(400.0).show(ctx, |ui| {
            let Some(active) = &self.active else {
                ui.label("No hay ninguna conexion activa.");
                return;
            };

            ui.horizontal(|ui| {
                if ui.button("Copiar todo").clicked() {
                    let all_text: String = active.log_lines.iter().cloned().collect::<Vec<_>>().join("\n");
                    ui.ctx().copy_text(all_text);
                }
                if ui.button("Abrir carpeta de logs").clicked() {
                    let _ = std::process::Command::new("explorer").arg(storage::connection_logs_dir()).spawn();
                }
            });
            ui.separator();

            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for line in &active.log_lines {
                    ui.monospace(line);
                }
            });
        });
        self.show_log_window = open;
    }

    fn render_first_run_gate(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.heading("Bienvenido a Portero VPN");
                ui.label("Antes de continuar, define la contrasena que protegera la seccion de Configuracion.");
                ui.add_space(16.0);
            });

            let Some(state) = self.first_run.as_mut() else { return };
            let mut password_defined = false;

            ui.vertical_centered(|ui| {
                ui.set_max_width(320.0);
                ui.horizontal(|ui| {
                    ui.label("Contrasena:");
                    ui.add(egui::TextEdit::singleline(&mut state.password).password(true));
                });
                ui.horizontal(|ui| {
                    ui.label("Confirmar:  ");
                    ui.add(egui::TextEdit::singleline(&mut state.confirm).password(true));
                });

                if let Some(error) = &state.error {
                    ui.colored_label(theme::DANGER, error);
                }

                if ui.button("Definir contrasena").clicked() {
                    if state.password.len() < 8 {
                        state.error = Some("La contrasena debe tener al menos 8 caracteres.".into());
                    } else if state.password != state.confirm {
                        state.error = Some("Las contrasenas no coinciden.".into());
                    } else {
                        match auth::hash_password(&state.password) {
                            Ok(hash) => match storage::write_config_password_hash(&hash) {
                                Ok(()) => password_defined = true,
                                Err(e) => state.error = Some(format!("No se pudo guardar la contrasena: {e}")),
                            },
                            Err(_) => state.error = Some("No se pudo generar el hash de la contrasena.".into()),
                        }
                    }
                }
            });

            if password_defined {
                self.first_run = None;
            }
        });
    }

    fn render_settings_screen(&mut self, ui: &mut egui::Ui) {
        if !self.settings_unlocked {
            ui.vertical_centered(|ui| {
                ui.add_space(24.0);
                ui.heading("Configuracion protegida");
                ui.label("Introduce la contrasena de configuracion para continuar.");
                ui.add_space(12.0);
                ui.set_max_width(320.0);
                let password_field = ui.add(egui::TextEdit::singleline(&mut self.settings_password_input).password(true));
                let submitted_with_enter =
                    password_field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                if let Some(error) = &self.settings_error {
                    ui.colored_label(theme::DANGER, error);
                }

                if ui.button("Entrar").clicked() || submitted_with_enter {
                    match storage::read_config_password_hash() {
                        Ok(Some(hash)) => match auth::verify_password(&self.settings_password_input, &hash) {
                            Ok(()) => {
                                self.settings_unlocked = true;
                                self.settings_error = None;
                            }
                            Err(_) => self.settings_error = Some("Contrasena incorrecta.".into()),
                        },
                        _ => self.settings_error = Some("No hay contrasena de configuracion definida.".into()),
                    }
                    self.settings_password_input.clear();
                }
            });
            return;
        }

        // El contenido de esta pantalla (lista de checks + cambio de
        // contrasena + control del servicio) puede superar facilmente los
        // ~540px de alto de la ventana compacta y sin resize; con scroll en
        // vez de dejar que se recorte contra el borde.
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.heading("General");
            if ui
                .checkbox(&mut self.preferences.minimize_on_connect, "Minimizar el panel al conectar correctamente")
                .changed()
            {
                let _ = storage::save_preferences(&self.preferences);
            }
            ui.separator();

            ui.heading("Comprobaciones de seguridad");
            ui.label("Marca que comprobaciones deben cumplirse para poder conectar.");
            ui.separator();

            let mut policy_changed = false;
            for check in self.registry.all() {
                let Some(config) = self.policy.checks.iter_mut().find(|c| c.id == check.id()) else { continue };
                egui::Frame::group(ui.style()).rounding(6.0).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    // Nombre a la izquierda, checkbox pegado al borde
                    // derecho (mismo patron que la fila de perfiles: el
                    // grupo de la derecha se anade despues, en un layout
                    // right-to-left propio, para que quede fijo aunque el
                    // nombre sea largo). Un unico checkbox en vez de
                    // "Activo"/"Obligatorio" por separado: con un solo check
                    // disponible en el MVP, dos interruptores para lo mismo
                    // solo generaba confusion (activar sin marcar
                    // obligatorio no bloqueaba nada). Se mantienen
                    // sincronizados en el modelo de datos (`CheckConfig`)
                    // para no tener que tocar policy.toml ni el motor de
                    // checks si en el futuro hace falta un check
                    // opcional/no bloqueante.
                    ui.horizontal(|ui| {
                        ui.add(egui::Label::new(RichText::new(check.display_name()).strong()).truncate());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.checkbox(&mut config.enabled, "").changed() {
                                config.mandatory = config.enabled;
                                policy_changed = true;
                            }
                        });
                    });
                });
            }
            if policy_changed {
                let _ = storage::save_policy(&self.policy);
            }

            ui.separator();
            ui.collapsing("Cambiar contrasena de configuracion", |ui| {
                let state = &mut self.change_password;
                let label_width = 70.0;
                ui.horizontal(|ui| {
                    ui.add_sized([label_width, ui.spacing().interact_size.y], egui::Label::new("Actual:"));
                    ui.add(egui::TextEdit::singleline(&mut state.current).password(true).desired_width(f32::INFINITY));
                });
                ui.horizontal(|ui| {
                    ui.add_sized([label_width, ui.spacing().interact_size.y], egui::Label::new("Nueva:"));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.new_password)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.horizontal(|ui| {
                    ui.add_sized([label_width, ui.spacing().interact_size.y], egui::Label::new("Confirmar:"));
                    ui.add(egui::TextEdit::singleline(&mut state.confirm).password(true).desired_width(f32::INFINITY));
                });
                if let Some(error) = &state.error {
                    ui.colored_label(theme::DANGER, error);
                }
                if ui.add(egui::Button::new("Guardar nueva contrasena").min_size(egui::vec2(ui.available_width(), 0.0))).clicked()
                {
                    match storage::read_config_password_hash() {
                        Ok(Some(hash)) if auth::verify_password(&state.current, &hash).is_ok() => {
                            if state.new_password.len() < 8 {
                                state.error = Some("La nueva contrasena debe tener al menos 8 caracteres.".into());
                            } else if state.new_password != state.confirm {
                                state.error = Some("Las contrasenas no coinciden.".into());
                            } else if let Ok(new_hash) = auth::hash_password(&state.new_password) {
                                let _ = storage::write_config_password_hash(&new_hash);
                                *state = ChangePasswordState::default();
                            }
                        }
                        _ => state.error = Some("La contrasena actual no es correcta.".into()),
                    }
                }
            });

            ui.separator();
            self.render_service_control(ui);
        });
    }

    /// Instalar/reinstalar/desinstalar `PorteroVPNSvc` (plan, seccion 1 y 8):
    /// requiere elevacion, asi que cada boton lanza el propio ejecutable del
    /// servicio con `runas` y espera a que termine (ver `service_ctl`).
    fn render_service_control(&mut self, ui: &mut egui::Ui) {
        ui.heading("Servicio del sistema (PorteroVPNSvc)");

        let (status_color, status_text) = match self.service_state {
            ServiceInstallState::NotInstalled => (theme::WARNING, "No instalado"),
            ServiceInstallState::Stopped => (theme::WARNING, "Instalado, detenido"),
            ServiceInstallState::Running => (theme::SUCCESS, "Instalado y en ejecucion"),
            ServiceInstallState::Transitioning => (theme::WARNING, "Cambiando de estado..."),
        };
        ui.horizontal(|ui| {
            ui.label("Estado:");
            ui.colored_label(status_color, status_text);
            if ui.small_button("Actualizar").clicked() {
                self.refresh_service_status();
            }
        });
        ui.label(
            "Este servicio es el unico componente que corre con privilegios de administrador: \
             solo arranca y detiene openvpn.exe cuando la GUI se lo pide. Instalarlo, reinstalarlo o \
             quitarlo pide confirmacion de administrador (UAC) cada vez.",
        );

        if let Some(error) = &self.service_action_error {
            ui.colored_label(theme::DANGER, error);
        }

        // `horizontal_wrapped` en vez de `horizontal`: al ancho compacto
        // actual los tres botones no siempre caben en una sola linea, y con
        // `horizontal` se recortarian contra el borde de la ventana en vez
        // de pasar a una segunda linea.
        ui.horizontal_wrapped(|ui| {
            let not_installed = self.service_state == ServiceInstallState::NotInstalled;
            if ui.add_enabled(not_installed, egui::Button::new("Instalar")).clicked() {
                self.run_service_action("install");
            }
            if ui.add_enabled(!not_installed, egui::Button::new("Reinstalar")).clicked() {
                self.run_service_action("reinstall");
            }
            if ui.add_enabled(!not_installed, egui::Button::new("Desinstalar")).clicked() {
                self.run_service_action("uninstall");
            }
        });
    }
}

/// Fondo atenuado a pantalla completa para los dialogos modales
/// (credenciales, errores de conexion): se pinta en la capa `Foreground` y,
/// al capturar el clic, evita que se pueda interactuar con lo que hay
/// detras mientras el modal esta abierto.
fn draw_modal_backdrop(ctx: &egui::Context) {
    egui::Area::new(egui::Id::new("modal_backdrop"))
        .order(egui::Order::Foreground)
        .fixed_pos(egui::Pos2::ZERO)
        .show(ctx, |ui| {
            let screen = ctx.screen_rect();
            ui.allocate_rect(screen, egui::Sense::click());
            ui.painter().rect_filled(screen, 0.0, egui::Color32::from_black_alpha(150));
        });
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}
