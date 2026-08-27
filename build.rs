//! Genera el icono de la app (mismo dibujo que `src/ui/tray.rs`, compartido
//! via `assets/icon_shape.rs`) como .ico multi-resolucion y lo embebe como
//! recurso de Windows en el .exe, para que Explorador, la barra de tareas y
//! Alt-Tab lo usen en vez del icono generico por defecto.

include!("assets/icon_shape.rs");

/// Resoluciones estandar para un .ico de Windows: desde el icono pequeno de
/// la barra de tareas hasta el que usa Explorador en vista "Iconos grandes".
const ICON_SIZES: [u32; 7] = [16, 24, 32, 48, 64, 128, 256];

/// Mismo azul que `theme::ACCENT` (`src/ui/theme.rs`): `build.rs` no puede
/// depender del propio crate que compila, asi que se repite el valor en vez
/// de importarlo.
const ACCENT: [u8; 3] = [88, 166, 255];

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR no definido");
    let ico_path = std::path::Path::new(&out_dir).join("app_icon.ico");

    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for &size in &ICON_SIZES {
        let rgba = generate_icon_rgba(size, ACCENT);
        let image = ico::IconImage::from_rgba_data(size, size, rgba);
        let entry = ico::IconDirEntry::encode(&image).expect("no se pudo codificar una resolucion del icono");
        icon_dir.add_entry(entry);
    }
    let file = std::fs::File::create(&ico_path).expect("no se pudo crear el .ico temporal");
    icon_dir.write(file).expect("no se pudo escribir el .ico temporal");

    winresource::WindowsResource::new()
        .set_icon(ico_path.to_str().expect("ruta del .ico no es UTF-8"))
        .compile()
        .expect("no se pudo embeber el icono como recurso de Windows");

    println!("cargo:rerun-if-changed=assets/icon_shape.rs");
}
