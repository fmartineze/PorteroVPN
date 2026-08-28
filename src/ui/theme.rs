//! Theming propio de egui (plan, seccion 2: "hay que invertir
//! deliberadamente en theming" para lograr un aspecto moderno sin salir de
//! egui/eframe). Paleta oscura con acento, esquinas redondeadas y espaciado
//! generoso. Embeber tipografia e iconos propios queda como mejora
//! incremental (ver plan, seccion 9).

use egui::{Color32, Margin, Rounding, Stroke, Vec2};

pub const ACCENT: Color32 = Color32::from_rgb(88, 166, 255);
pub const SUCCESS: Color32 = Color32::from_rgb(63, 185, 80);
pub const WARNING: Color32 = Color32::from_rgb(210, 153, 34);
pub const DANGER: Color32 = Color32::from_rgb(248, 81, 73);
pub const SURFACE: Color32 = Color32::from_rgb(22, 27, 34);
pub const SURFACE_RAISED: Color32 = Color32::from_rgb(30, 36, 45);

pub fn apply(ctx: &egui::Context) {
    // Sin esto, la ventana sale con el tema CLARO por defecto de egui en
    // cualquier Windows configurado en modo claro (visto en la practica en
    // un equipo remoto por TeamViewer). El motivo: egui 0.29 guarda dos
    // estilos, `dark_style` y `light_style`, y `set_style` de abajo solo
    // escribe en el del tema activo en ese momento. Como aqui todavia no se
    // ha pintado ningun frame, `system_theme` es `None` y egui cae a su
    // `fallback_theme` (Dark), asi que toda la paleta de abajo aterriza en
    // `dark_style`; en el primer frame llega el tema real del sistema desde
    // winit y, si es claro, egui pasa a usar `light_style`, que nadie ha
    // tocado. Fijando la preferencia a Dark, `set_style` apunta siempre a
    // `dark_style` y el tema del sistema deja de poder pisarlo.
    //
    // Es lo correcto ademas de lo comodo: esta app tiene una unica paleta,
    // oscura (las constantes de arriba), y hay trozos que se pintan a mano
    // con ellas -la barra inferior de `app.rs`, el fondo de la fila de
    // perfil seleccionada- sin pasar por el estilo. Con el tema claro
    // activo, esos trozos seguian oscuros sobre un fondo blanco.
    ctx.set_theme(egui::ThemePreference::Dark);

    let mut style = (*ctx.style()).clone();

    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = SURFACE;
    style.visuals.window_fill = SURFACE_RAISED;
    style.visuals.extreme_bg_color = Color32::from_rgb(13, 17, 23);
    style.visuals.faint_bg_color = SURFACE_RAISED;

    style.visuals.widgets.noninteractive.rounding = Rounding::same(8.0);
    style.visuals.widgets.inactive.rounding = Rounding::same(8.0);
    style.visuals.widgets.hovered.rounding = Rounding::same(8.0);
    style.visuals.widgets.active.rounding = Rounding::same(8.0);
    style.visuals.window_rounding = Rounding::same(12.0);

    style.visuals.widgets.inactive.bg_fill = SURFACE_RAISED;
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(40, 48, 61);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    style.visuals.widgets.active.bg_fill = ACCENT;
    style.visuals.selection.bg_fill = ACCENT.linear_multiply(0.4);
    style.visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);

    // Barra de scroll solida y siempre presente, en vez de la flotante que
    // egui trae por defecto. La flotante solo aparece con el puntero encima
    // del area, asi que con la lista de conexiones llena (comprobado con 20
    // perfiles) nada indicaba que hubiera mas por debajo del ultimo visible:
    // la rueda del raton funcionaba, pero habia que adivinarlo. Ocupando
    // sitio de verdad, ademas, el texto de las filas ya no queda por debajo
    // de la barra cuando esta aparece.
    style.spacing.scroll.floating = false;
    style.spacing.scroll.bar_width = 8.0;

    style.spacing.item_spacing = Vec2::new(10.0, 10.0);
    style.spacing.button_padding = Vec2::new(14.0, 8.0);
    style.spacing.window_margin = Margin::same(16.0);
    style.spacing.menu_margin = Margin::same(10.0);

    ctx.set_style(style);
}
