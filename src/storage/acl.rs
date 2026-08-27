//! Reparacion de permisos de `%ProgramData%\PorteroVPN\`.
//!
//! La GUI esta pensada para correr SIEMPRE sin privilegios (los checks de
//! WMI solo son fiables en la sesion del usuario, ver plan Contexto). Pero
//! si en algun momento se lanza una vez como Administrador -p.ej. al
//! instalar el servicio a mano, o al depurar- los ficheros que ese arranque
//! toca (log del dia, `policy.toml`, `config-password.hash`...) quedan con
//! propietario `Administradores` y solo lectura para `Usuarios`. Eso deja la
//! app inutilizable sin admin en el siguiente arranque normal (incidente:
//! "se abre y se cierra sin ser admin" -> `tracing_appender` no podia abrir
//! el log del dia y entraba en panico antes de crear la ventana).
//!
//! Por eso `ensure_user_writable` se invoca en cada arranque desde
//! `ensure_data_dirs`, no solo desde un futuro instalador: el arbol es
//! pequeno, la operacion es barata, y es autocurativa -si el arranque actual
//! esta elevado, arregla lo que un arranque elevado anterior rompio; si no
//! lo esta, `icacls` simplemente fallara para lo que ya estaba roto (avisa
//! por log, no aborta el arranque) pero no puede empeorar nada.
//!
//! Se usa `icacls.exe` (siempre presente en Windows) en vez del crate
//! `windows-acl`: manipular DACLs a mano via `SetNamedSecurityInfoW` es
//! fragil (en pruebas, `windows-acl` fallaba con codigos de error espurios
//! al insertar la entrada), mientras que `icacls /grant ... /T` es la
//! herramienta estandar y bien probada para exactamente este caso.

use std::io;
use std::os::windows::process::CommandExt;
use std::path::Path;

/// SID bien conocido de `BUILTIN\Users` (`S-1-5-32-545`): usar el SID en vez
/// del nombre evita depender de la resolucion de nombres, que varia con el
/// idioma del sistema ("Usuarios" en este equipo).
const BUILTIN_USERS_SID: &str = "*S-1-5-32-545";

/// `CREATE_NO_WINDOW` (procthreadsapi.h / Win32 Process Creation Flags): sin
/// esto, lanzar `icacls.exe` (app de consola) desde la GUI release (sin
/// consola propia) hace que Windows le abra su propia ventana de consola un
/// instante, visible como un parpadeo antes de que aparezca la ventana de
/// la app.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Da permiso de modificacion a `BUILTIN\Users` sobre `dir`, recursivamente
/// (`/T`), incluyendo lo que ya exista debajo. No falla el arranque de la
/// app si `icacls` no puede tocar algo: se registra un aviso y se continua.
pub fn ensure_user_writable(dir: &Path) -> io::Result<()> {
    let path_str = dir
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ruta con caracteres no validos"))?;

    let output = std::process::Command::new("icacls")
        .arg(path_str)
        .arg("/grant")
        .arg(format!("{BUILTIN_USERS_SID}:(OI)(CI)M"))
        .arg("/T")
        .arg("/C")
        .arg("/Q")
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "icacls termino con {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    Ok(())
}
