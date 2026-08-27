// Dibujo del icono de la app: un circulo relleno con una "V" blanca en el
// centro. Fichero compartido, via `include!`, entre `build.rs` (icono
// embebido en los .exe), `src/ui/tray.rs` (icono de la bandeja en
// ejecucion) y `src/main.rs` (icono de la ventana), para que los tres sean
// pixel a pixel el mismo dibujo en vez de mantener copias que se puedan
// desincronizar. No es un modulo aparte porque `build.rs` no puede depender
// del propio crate que compila.
//
// `generate_icon_rgba` es `pub(crate)` (no solo privada al fichero que la
// incluye) para que `main.rs` tambien pueda llamarla via
// `crate::ui::tray::generate_icon_rgba`; en `build.rs`, que se compila como
// binario aparte sin nada de esto, el modificador simplemente no importa.
//
// Las proporciones estan calculadas para reproducir exactamente, a
// `size = 32`, el icono original (circulo con margen de 1px, trazo de la V
// de grosor 2.4, vertice 8px por debajo del centro, puntas a +-7.5px del
// centro y 8px por encima) -- de ahi las fracciones poco redondas.
pub(crate) fn generate_icon_rgba(size: u32, color: [u8; 3]) -> Vec<u8> {
    let size_f = size as f32;
    let center = size_f / 2.0;
    let margin = (size_f / 32.0).max(1.0);
    let radius = center - margin;
    let stroke_half_width = (size_f * 0.075).max(1.0);
    let apex = (center, center + size_f * 0.25);
    let top_left = (center - size_f * 0.234375, center - size_f * 0.25);
    let top_right = (center + size_f * 0.234375, center - size_f * 0.25);

    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;
            let dx = px - center;
            let dy = py - center;
            if (dx * dx + dy * dy).sqrt() > radius {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }

            let on_v = icon_shape_distance_to_segment(px, py, top_left, apex) <= stroke_half_width
                || icon_shape_distance_to_segment(px, py, top_right, apex) <= stroke_half_width;
            if on_v {
                rgba.extend_from_slice(&[255, 255, 255, 255]);
            } else {
                rgba.extend_from_slice(&[color[0], color[1], color[2], 255]);
            }
        }
    }
    rgba
}

fn icon_shape_distance_to_segment(px: f32, py: f32, a: (f32, f32), b: (f32, f32)) -> f32 {
    let (ax, ay) = a;
    let (bx, by) = b;
    let (abx, aby) = (bx - ax, by - ay);
    let ab_len2 = abx * abx + aby * aby;
    let t = if ab_len2 > 0.0 { ((px - ax) * abx + (py - ay) * aby) / ab_len2 } else { 0.0 };
    let t = t.clamp(0.0, 1.0);
    let (cx, cy) = (ax + t * abx, ay + t * aby);
    let (dx, dy) = (px - cx, py - cy);
    (dx * dx + dy * dy).sqrt()
}
