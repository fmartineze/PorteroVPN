//! Comprobacion de que la cuenta de Windows con la que se ha iniciado sesion
//! **exige** contrasena. Apunta al caso de un equipo montado con un usuario
//! local sin contrasena: cualquiera que abra la tapa entra, y desde ahi podria
//! levantar la VPN.
//!
//! # Que mide exactamente, y que no
//!
//! Lee `UF_PASSWD_NOTREQD`, que dice si Windows **permite** que esa cuenta
//! tenga la contrasena en blanco. No dice si la contrasena esta en blanco.
//! Ambas cosas se separan en la practica: en la maquina de desarrollo, la
//! cuenta tiene contrasena (con fecha de ultimo cambio y todo) y aun asi
//! aparece como "Contrasena requerida: No" en `net user`, porque asi quedo
//! dada de alta.
//!
//! Por eso el check se llama "exige contrasena" y no "tiene contrasena": una
//! cuenta marcada asi es una configuracion mas debil aunque hoy tenga
//! contrasena, porque se le puede quitar sin que nada lo impida. Pero hay que
//! contar con que en equipos ya montados dara fallo con mas frecuencia de la
//! que sugiere el nombre corto. Viene desactivado por defecto.
//!
//! # Por que se lee una bandera y no se prueba a iniciar sesion
//!
//! La prueba definitiva seria `LogonUser` con contrasena vacia: si funciona,
//! no hay contrasena. Se descarto a proposito. El problema esta en el caso
//! sano: si el usuario **si** tiene contrasena, ese intento falla, y un
//! intento fallido cuenta para el bloqueo de cuenta, que Windows 11 activa
//! por defecto (10 fallos en 10 minutos). Un check que corre antes de cada
//! conexion gastaria ese presupuesto en el camino normal y acabaria dejando
//! al usuario fuera de su propio equipo. Ademas llenaria el registro de
//! seguridad de eventos 4625, que en un entorno vigilado se lee como fuerza
//! bruta contra el propio usuario.
//!
//! `NetUserGetInfo` no autentica nada: lee la base de cuentas local (la misma
//! que hay detras de `net user <usuario>` y su "Se requiere contrasena:
//! Si/No"). Sin eventos, sin riesgo de bloqueo.
//!
//! La contrapartida, dicha claramente: `UF_PASSWD_NOTREQD` es una bandera, no
//! la contrasena. Un administrador puede quitarla manteniendo la contrasena
//! vacia. No es infalsificable, y no pretende serlo: como el resto de checks,
//! sirve contra descuido y deriva de configuracion, no contra alguien que
//! manipula su propia maquina a proposito.

use async_trait::async_trait;

use crate::i18n::{t, Msg};

use super::{Check, CheckContext, CheckOutcome};

/// Lo que se puede averiguar de la cuenta que tiene la sesion abierta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountPasswordStatus {
    /// Cuenta local que exige contrasena (no lleva UF_PASSWD_NOTREQD).
    ///
    /// Ojo: eso NO garantiza que la contrasena no este en blanco, solo que
    /// Windows no la marca como que puede estarlo. Ver la nota del modulo.
    PasswordRequired,
    /// Cuenta local marcada como que admite contrasena en blanco.
    PasswordNotRequired,
    /// La cuenta no esta en la SAM local: es de dominio o de Azure AD. La
    /// politica de contrasenas la impone el directorio, asi que este check no
    /// tiene nada que decir.
    NotALocalAccount,
}

pub struct WindowsPasswordCheck;

#[async_trait]
impl Check for WindowsPasswordCheck {
    fn id(&self) -> &'static str {
        "windows_account_password"
    }

    fn display_name(&self) -> Msg {
        Msg::CheckWindowsPasswordName
    }

    async fn evaluate(&self, _ctx: &CheckContext) -> CheckOutcome {
        // `NetUserGetInfo` es sincrona y toca la SAM: fuera del hilo del
        // runtime, como se hace con las consultas WMI.
        match tokio::task::spawn_blocking(query_account_password_status).await {
            Ok(Ok(AccountPasswordStatus::PasswordRequired)) => CheckOutcome::Pass,
            // Que no sea una cuenta local no es un fallo: es que la pregunta
            // no aplica. Resolverlo como `Indeterminate` bloquearia la
            // conexion a todo un dominio sin salida posible para el usuario,
            // que es exactamente el problema que ya tiene BitLocker en las
            // ediciones Home de Windows.
            Ok(Ok(AccountPasswordStatus::NotALocalAccount)) => CheckOutcome::Pass,
            Ok(Ok(AccountPasswordStatus::PasswordNotRequired)) => {
                CheckOutcome::Fail { reason: t(Msg::ReasonWindowsPasswordMissing).to_string() }
            }
            Ok(Err(e)) => CheckOutcome::Indeterminate { reason: e },
            Err(e) => CheckOutcome::Indeterminate { reason: format!("tarea abortada: {e}") },
        }
    }
}

/// Consulta la SAM local por la cuenta que tiene la sesion abierta.
fn query_account_password_status() -> Result<AccountPasswordStatus, String> {
    use windows::core::PCWSTR;
    use windows::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetUserGetInfo, NERR_Success, NERR_UserNotFound, UF_PASSWD_NOTREQD, USER_INFO_1,
    };

    let user = current_user_name()?;
    let mut user_utf16: Vec<u16> = user.encode_utf16().chain(std::iter::once(0)).collect();

    let mut buffer: *mut u8 = std::ptr::null_mut();
    // `servername` a nulo = esta maquina. Nivel 1 porque es el mas bajo que
    // incluye `usri1_flags`, que es lo unico que se mira.
    let status = unsafe {
        NetUserGetInfo(
            PCWSTR::null(),
            PCWSTR(user_utf16.as_mut_ptr()),
            1,
            &mut buffer as *mut *mut u8,
        )
    };

    if status == NERR_UserNotFound {
        // No esta en la SAM local: cuenta de dominio o de Azure AD.
        return Ok(AccountPasswordStatus::NotALocalAccount);
    }
    if status != NERR_Success {
        return Err(format!("NetUserGetInfo fallo (codigo {status})"));
    }
    if buffer.is_null() {
        return Err("NetUserGetInfo devolvio exito con un buffer nulo".to_string());
    }

    // El buffer lo asigna netapi32 y hay que devolverselo pase lo que pase,
    // asi que se copia lo que interesa y se libera antes de decidir nada.
    let flags = unsafe { (*(buffer as *const USER_INFO_1)).usri1_flags };
    unsafe {
        let _ = NetApiBufferFree(Some(buffer as *const core::ffi::c_void));
    }

    if flags.0 & UF_PASSWD_NOTREQD.0 != 0 {
        Ok(AccountPasswordStatus::PasswordNotRequired)
    } else {
        Ok(AccountPasswordStatus::PasswordRequired)
    }
}

/// Nombre de la cuenta con la sesion abierta, sin dominio (el formato que
/// espera `NetUserGetInfo`).
fn current_user_name() -> Result<String, String> {
    use windows::core::PWSTR;
    use windows::Win32::System::WindowsProgramming::GetUserNameW;

    // UNLEN + 1. Se pide el tamano de entrada y la llamada lo actualiza.
    let mut buffer = vec![0u16; 257];
    let mut size = buffer.len() as u32;
    unsafe { GetUserNameW(PWSTR(buffer.as_mut_ptr()), &mut size) }
        .map_err(|e| format!("GetUserNameW fallo: {e}"))?;

    // `size` incluye el terminador nulo.
    let len = (size as usize).saturating_sub(1);
    Ok(String::from_utf16_lossy(&buffer[..len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No forma parte de `cargo test` normal: depende de como este dada de
    /// alta la cuenta de la maquina donde se ejecute. Sirve para comprobar a
    /// mano, con `cargo test -- --ignored --nocapture`, que la consulta
    /// devuelve algo coherente con lo que dice `net user <usuario>`.
    #[test]
    #[ignore = "depende de la cuenta real de la maquina donde se ejecuta"]
    fn real_query_matches_actual_account() {
        let user = current_user_name().expect("no se pudo obtener el usuario actual");
        let status = query_account_password_status().expect("la consulta fallo");
        println!("usuario: {user}");
        println!("estado: {status:?}");
        println!("comprobar contra: net user {user}");
    }
}
