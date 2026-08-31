// La app no necesita consola en modo release; en debug se deja para poder
// ver los logs de tracing mientras se desarrolla.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod auth;
mod checks;
mod connection;
mod credentials;
mod elevate;
mod gpu_fallback;
mod i18n;
mod mgmt;
mod openvpn_install;
mod wireguard_install;
mod service_ctl;
mod single_instance;
mod storage;
mod svc_client;
mod ui;

fn main() -> eframe::Result<()> {
    init_logging();

    // Antes de tocar nada grafico y antes de comprobar si ya hay otra
    // instancia corriendo: si no hay ningun backend wgpu funcional,
    // relanza con Vulkan por software (Lavapipe) forzado (ver
    // `gpu_fallback`). Tiene que ir lo primero de todo porque la variable
    // de entorno que usa solo tiene efecto si se pone antes de que el
    // proceso toque Vulkan por primera vez -- y tiene que ir tambien antes
    // del mutex de instancia unica, porque si relanza, este proceso nunca
    // llega a abrir ventana ni a ser "la" instancia (el relanzado si lo
    // sera), asi que no debe quedarse con el mutex a medias.
    gpu_fallback::ensure_working_backend_or_relaunch();

    // Si ya hay una instancia corriendo, esta ya ha intentado traer su
    // ventana al frente (ver `single_instance`): no hay nada mas que hacer
    // aqui, salvo terminar sin abrir una segunda ventana ni un segundo
    // icono de bandeja duplicado.
    let Some(_instance_guard) = single_instance::acquire_or_activate_existing() else {
        return Ok(());
    };

    if let Err(e) = storage::ensure_data_dirs() {
        tracing::error!("no se pudo preparar el almacen de datos: {e}");
    }

    // Antes de pintar nada. En el primer arranque `load_preferences` crea el
    // fichero resolviendo el idioma contra el de Windows (ver
    // `AppPreferences::bootstrap_default`); a partir de ahi manda lo guardado.
    // Si la carga falla se sigue con el idioma por defecto en vez de abortar:
    // no poder leer una preferencia no es motivo para dejar al usuario sin
    // aplicacion.
    let language = storage::load_preferences().map(|p| p.language).unwrap_or_default();
    i18n::set_current(language);

    // Ventana compacta y de tamano fijo (widget, no aplicacion de escritorio
    // clasica): sin boton de maximizar ni borde de redimensionado.
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([380.0, 540.0])
            .with_min_inner_size([380.0, 540.0])
            .with_max_inner_size([380.0, 540.0])
            .with_resizable(false)
            .with_maximize_button(false)
            // Sin esto, la ventana en si (barra de titulo, Alt-Tab, boton de
            // la barra de tareas mientras esta corriendo) usa el icono
            // generico de la ventana, no el del icono de bandeja/exe: son
            // mecanismos distintos en egui/winit (el .exe empotra el suyo
            // via build.rs; la ventana necesita el suyo aparte). Mismo
            // dibujo que la bandeja, via `assets/icon_shape.rs`.
            .with_icon(app_icon()),
        // wgpu (DirectX/Vulkan) en vez del renderer por defecto (glow,
        // OpenGL): en una VM sin aceleracion 3D propia (visto en la
        // practica en una VM Win11 sobre Proxmox) no hay OpenGL 2.0+
        // disponible y la app ni siquiera llega a abrir ("egui_glow:
        // OpenGL: egui_glow requires opengl 2.0+"). DirectX si esta
        // siempre disponible en Windows (con reasterizador por software si
        // hace falta), incluso sin drivers de GPU reales.
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };

    eframe::run_native(
        "Portero VPN",
        native_options,
        Box::new(|cc| {
            ui::theme::apply(&cc.egui_ctx);
            Ok(Box::new(app::PorteroApp::new()))
        }),
    )
}

/// Mismo circulo azul con la "V" que el icono de bandeja (`ui::tray`) y el
/// del .exe (`build.rs`), a una resolucion mas alta (64px, no los 32px de la
/// bandeja) porque aqui la usa tambien Alt-Tab, que la pinta mas grande.
fn app_icon() -> egui::IconData {
    const SIZE: u32 = 64;
    let rgba = ui::tray::generate_icon_rgba(SIZE, [ui::theme::ACCENT.r(), ui::theme::ACCENT.g(), ui::theme::ACCENT.b()]);
    egui::IconData { rgba, width: SIZE, height: SIZE }
}

fn init_logging() {
    let log_dir = storage::logs_dir();
    let _ = std::fs::create_dir_all(&log_dir);

    // `wgpu_core` es muy ruidoso a nivel INFO (una linea de log por cada
    // frame/submission, ver `wgpu_core::device::resource::maintain`):
    // bajado a warn especificamente para el, o el fichero de log crecia
    // varios ordenes de magnitud mas rapido que antes sin aportar nada util
    // para depurar la app en si. `wgpu_hal` se deja a info a proposito (a
    // diferencia de `wgpu_core`): ahi es donde salen los intentos de cada
    // backend grafico (Vulkan/DX12/GL) al elegir adaptador, informacion
    // clave para diagnosticar maquinas donde wgpu no encuentra ninguno (ver
    // incidente de la VM de Proxmox sin aceleracion 3D).
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wgpu_core=warn,naga=warn"));

    // `rolling::daily` entra en panico si no puede abrir el fichero de hoy
    // (p.ej. quedo con permisos de solo lectura para el usuario tras un
    // arranque anterior como Administrador -ver incidente "se abre y se
    // cierra sin ser admin"-). Con el builder se degrada a "sin log a
    // fichero" en vez de impedir que la app arranque por esto.
    match tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("portero-vpn.log")
        // Sin esto, un fichero de log tecnico nuevo cada dia se acumulaba
        // para siempre; se conservan como mucho los ultimos 10.
        .max_log_files(10)
        .build(&log_dir)
    {
        Ok(file_appender) => {
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            // El guard debe vivir mientras el proceso este vivo para no perder logs
            // en buffer; se filtra deliberadamente en vez de guardarlo en una
            // variable que se caeria de scope al salir de esta funcion.
            std::mem::forget(guard);

            let _ = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_writer(non_blocking)
                .with_ansi(false)
                .try_init();
        }
        Err(e) => {
            eprintln!("no se pudo inicializar el log a fichero, continuo sin el: {e}");
            let _ = tracing_subscriber::fmt().with_env_filter(env_filter).with_ansi(false).try_init();
        }
    }
}
