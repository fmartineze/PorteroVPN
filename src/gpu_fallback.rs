//! Deteccion de un backend grafico funcional (Vulkan/DX12/GL) antes de
//! arrancar egui de verdad, y relanzamiento con Lavapipe (Vulkan por
//! software, ver `assets/lavapipe/`) como ultimo recurso si no hay ninguno.
//!
//! Motivado por una VM de pruebas sin ningun backend grafico disponible (ni
//! Vulkan, ni DX12/WARP, ni OpenGL 3.3+): `eframe` con el renderer `wgpu`
//! (ver `main.rs`) no llegaba ni a abrir la ventana ("WGPU error: Failed to
//! create wgpu adapter, no suitable adapter found"). El `egui-wgpu`
//! vendorizado (ver `vendor/egui-wgpu-0.29.1`) ya reintenta con
//! `force_fallback_adapter: true` si el primer intento no encuentra nada,
//! pero eso solo ayuda si existe *algun* adaptador de respaldo (WARP) que
//! el sistema sepa encontrar. Cuando ni eso hay, la unica salida es
//! proporcionar nosotros mismos un ICD de Vulkan por software.
//!
//! La variable de entorno `VK_ICD_FILENAMES` solo tiene efecto si esta
//! puesta *antes* de que el cargador de Vulkan (`vulkan-1.dll`) se
//! inicialice por primera vez en el proceso -- una vez inicializado, no
//! vuelve a releer la lista de ICDs. Por eso esta comprobacion se hace lo
//! primero de todo en `main` (antes de que `eframe` toque nada grafico), y
//! si hace falta activar Lavapipe, se hace relanzando el proceso entero con
//! la variable ya puesta desde el arranque, en vez de intentar inyectarla a
//! mitad de ejecucion.

use std::path::{Path, PathBuf};

use eframe::wgpu;

/// Puesta por el propio proceso relanzado (ver `relaunch_with_lavapipe`)
/// para no volver a sondear ni relanzarse de nuevo si Lavapipe tampoco
/// funcionara -- evita un bucle de relanzamientos infinito.
const FORCE_LAVAPIPE_ENV: &str = "PORTERO_VPN_FORCE_LAVAPIPE";

/// Si hace falta, relanza el proceso entero con Lavapipe forzado y no
/// vuelve (termina el proceso actual con el codigo de salida del nuevo).
/// Si no hace falta (ya hay un backend grafico funcional, no se encuentra
/// el Lavapipe empaquetado, o ya somos el proceso relanzado), devuelve el
/// control normalmente y `main` continua como siempre.
pub fn ensure_working_backend_or_relaunch() {
    if std::env::var_os(FORCE_LAVAPIPE_ENV).is_some() {
        // Ya somos el proceso relanzado con Lavapipe: no volver a sondear
        // (si Lavapipe tampoco funcionara, mejor dejar que falle con su
        // propio error mas adelante que entrar en un bucle).
        return;
    }

    if has_working_wgpu_backend() {
        return;
    }

    let Some(icd_path) = lavapipe_icd_path() else {
        tracing::warn!(
            "ningun backend grafico funciona y no se encontro el Lavapipe empaquetado junto \
             al ejecutable; se continua igualmente y probablemente falle al abrir la ventana"
        );
        return;
    };

    tracing::warn!(
        icd = %icd_path.display(),
        "ningun backend grafico (Vulkan/DX12/OpenGL) funciona en este equipo; \
         relanzando con Vulkan por software (Lavapipe) como ultimo recurso"
    );
    relaunch_with_lavapipe(&icd_path);
}

/// Sondeo ligero, sin ventana ni superficie real, de si Vulkan o DX12
/// encontrarian algun adaptador utilizable -- las mismas dos pasadas
/// (normal, y forzando `force_fallback_adapter`) que hace de verdad
/// `egui-wgpu` (ver `vendor/egui-wgpu-0.29.1`) al crear la ventana. Si esto
/// dice que si, se deja que el arranque normal siga su curso tal cual y ya
/// se encargara `egui-wgpu` de elegir adaptador de verdad.
fn has_working_wgpu_backend() -> bool {
    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
        backends: wgpu::Backends::PRIMARY | wgpu::Backends::GL,
        ..Default::default()
    });

    pollster::block_on(async {
        for force_fallback_adapter in [false, true] {
            let found = instance
                .request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    compatible_surface: None,
                    force_fallback_adapter,
                })
                .await;
            if found.is_some() {
                return true;
            }
        }
        false
    })
}

/// Ruta al manifiesto ICD de Lavapipe empaquetado junto al ejecutable (ver
/// `installer/portero-vpn.iss`, que lo copia a `lavapipe\` dentro de la
/// carpeta de instalacion). `None` si no esta presente (p.ej. en un build
/// de desarrollo sin empaquetar) -- en ese caso no hay nada que ofrecer
/// como respaldo.
fn lavapipe_icd_path() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let icd_path = exe_dir.join("lavapipe").join("lvp_icd.x86_64.json");
    icd_path.is_file().then_some(icd_path)
}

/// Relanza este mismo ejecutable con `VK_ICD_FILENAMES` apuntando al ICD de
/// Lavapipe (y `FORCE_LAVAPIPE_ENV` puesta, para que el proceso relanzado
/// no vuelva a sondear ni a relanzarse a si mismo). No espera a que
/// termine ("fire and forget": el relanzado es la GUI de verdad, que vive
/// mientras dure la sesion del usuario -- esperarla aqui dejaria este
/// proceso colgado de fondo todo ese tiempo para nada) y no vuelve: termina
/// el proceso actual justo despues de lanzarlo.
fn relaunch_with_lavapipe(icd_path: &Path) -> ! {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("portero-vpn.exe"));

    let spawn_result = std::process::Command::new(&exe)
        .args(std::env::args_os().skip(1))
        .env("VK_ICD_FILENAMES", icd_path)
        .env(FORCE_LAVAPIPE_ENV, "1")
        .spawn();

    std::process::exit(match spawn_result {
        Ok(_child) => 0,
        Err(e) => {
            tracing::error!(error = %e, "no se pudo relanzar con Lavapipe");
            1
        }
    });
}
