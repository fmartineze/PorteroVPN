//! Almacen de perfiles importados y politica de seguridad, bajo
//! `%ProgramData%\PorteroVPN\` (plan, seccion 4). La ubicacion se elige para
//! que un usuario estandar no pueda editar `policy.toml` ni
//! `config-password.hash` a mano sin darse cuenta de que esta tocando un
//! directorio de sistema; la GUI en si corre siempre sin privilegios (los
//! checks de WMI solo son fiables en la sesion del usuario) y por tanto
//! necesita poder leer y escribir todo este arbol, asi que `ensure_data_dirs`
//! repara permisos de `Usuarios` en cada arranque (ver `storage::acl`) en
//! vez de dejarlo para un instalador que corra elevado.

mod acl;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Once;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const APP_DIR_NAME: &str = "PorteroVPN";

pub fn data_dir() -> PathBuf {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(program_data).join(APP_DIR_NAME)
}

pub fn profiles_dir() -> PathBuf {
    data_dir().join("profiles")
}

pub fn run_dir() -> PathBuf {
    data_dir().join("run")
}

pub fn logs_dir() -> PathBuf {
    data_dir().join("logs")
}

pub fn connection_logs_dir() -> PathBuf {
    logs_dir().join("connections")
}

/// Purga `logs\connections\` para que no crezca sin limite (un fichero por
/// intento de conexion, ver `connection::open_connection_log_file`): se
/// conservan como mucho `max_files`, borrando los mas antiguos por fecha de
/// modificacion. Mejor esfuerzo: si falla, se avisa por log tecnico pero no
/// es motivo para interrumpir nada (ni conectar ni ninguna otra cosa).
pub fn prune_connection_logs(max_files: usize) {
    let dir = connection_logs_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(error = %e, path = %dir.display(), "no se pudo leer el directorio de logs de conexion para purgarlo");
            return;
        }
    };

    let mut files: Vec<(PathBuf, std::time::SystemTime)> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if !entry.file_type().ok()?.is_file() {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((entry.path(), modified))
        })
        .collect();

    if files.len() <= max_files {
        return;
    }

    files.sort_by_key(|(_, modified)| *modified);
    let excess = files.len() - max_files;
    for (path, _) in files.into_iter().take(excess) {
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(error = %e, path = %path.display(), "no se pudo borrar un log de conexion antiguo");
        }
    }
}

pub fn policy_path() -> PathBuf {
    data_dir().join("policy.toml")
}

pub fn preferences_path() -> PathBuf {
    data_dir().join("preferences.toml")
}

pub fn config_password_hash_path() -> PathBuf {
    data_dir().join("config-password.hash")
}

/// Se llama desde varios sitios (importar perfil, guardar politica, cambiar
/// contrasena...) ademas de al arrancar, asi que la reparacion de permisos
/// -que lanza `icacls` como subproceso- solo se ejecuta una vez por proceso
/// en vez de en cada llamada.
static ACL_REPAIR_ONCE: Once = Once::new();

pub fn ensure_data_dirs() -> io::Result<()> {
    for dir in [data_dir(), profiles_dir(), run_dir(), logs_dir(), connection_logs_dir()] {
        std::fs::create_dir_all(dir)?;
    }
    ACL_REPAIR_ONCE.call_once(|| {
        if let Err(e) = acl::ensure_user_writable(&data_dir()) {
            tracing::warn!(error = %e, "no se pudieron reparar permisos de Usuarios sobre el almacen de datos");
        }
    });
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileMeta {
    pub id: Uuid,
    pub display_name: String,
    pub imported_from: PathBuf,
    pub stored_ovpn_path: PathBuf,
    pub remember_credentials: bool,
    /// Salida de `CryptProtectData` sobre `"usuario\0contrasena"`. Presente
    /// solo si `remember_credentials == true` (ver plan, seccion 4).
    pub credentials_blob: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub last_connected_at: Option<DateTime<Utc>>,
}

fn profile_meta_path(id: Uuid) -> PathBuf {
    profiles_dir().join(format!("{id}.meta.toml"))
}

fn profile_ovpn_path(id: Uuid) -> PathBuf {
    profiles_dir().join(format!("{id}.ovpn"))
}

/// Copia el `.ovpn` elegido por el usuario al almacen propio (el original no
/// se toca ni se modifica, ver plan Contexto) y guarda sus metadatos.
pub fn import_profile(source_path: &Path, display_name: String, remember_credentials: bool) -> io::Result<ProfileMeta> {
    ensure_data_dirs()?;

    let id = Uuid::new_v4();
    let stored_ovpn_path = profile_ovpn_path(id);
    std::fs::copy(source_path, &stored_ovpn_path)?;

    let meta = ProfileMeta {
        id,
        display_name,
        imported_from: source_path.to_path_buf(),
        stored_ovpn_path,
        remember_credentials,
        credentials_blob: None,
        created_at: Utc::now(),
        last_connected_at: None,
    };

    save_profile_meta(&meta)?;
    Ok(meta)
}

pub fn save_profile_meta(meta: &ProfileMeta) -> io::Result<()> {
    ensure_data_dirs()?;
    let toml = toml::to_string_pretty(meta).map_err(io::Error::other)?;
    std::fs::write(profile_meta_path(meta.id), toml)
}

pub fn load_profile(id: Uuid) -> io::Result<ProfileMeta> {
    let raw = std::fs::read_to_string(profile_meta_path(id))?;
    toml::from_str(&raw).map_err(io::Error::other)
}

pub fn list_profiles() -> io::Result<Vec<ProfileMeta>> {
    ensure_data_dirs()?;
    let mut profiles = Vec::new();

    for entry in std::fs::read_dir(profiles_dir())? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let raw = std::fs::read_to_string(&path)?;
        match toml::from_str::<ProfileMeta>(&raw) {
            Ok(meta) => profiles.push(meta),
            Err(e) => tracing::warn!(path = %path.display(), error = %e, "metadato de perfil ilegible, se omite"),
        }
    }

    profiles.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    Ok(profiles)
}

pub fn delete_profile(id: Uuid) -> io::Result<()> {
    let _ = std::fs::remove_file(profile_ovpn_path(id));
    std::fs::remove_file(profile_meta_path(id))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityPolicy {
    pub checks: Vec<CheckConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckConfig {
    pub id: String,
    pub enabled: bool,
    pub mandatory: bool,
}

impl SecurityPolicy {
    /// Politica de arranque cuando no existe `policy.toml` todavia. El
    /// check de antivirus (ver `checks::antivirus`) va activo y obligatorio
    /// por defecto -- es el que ya existia en el MVP. El id mantiene el
    /// nombre historico "defender_realtime_protection" por compatibilidad
    /// con `policy.toml` ya guardados, aunque el check ya no se limita a
    /// Windows Defender.
    ///
    /// El check de BitLocker (`checks::bitlocker`) va desactivado por
    /// defecto: a diferencia del antivirus, muchos equipos legitimamente no
    /// tienen BitLocker configurado (o ni siquiera disponible, en Windows
    /// Home), asi que activarlo de salida bloquearia conexiones por
    /// sorpresa en la primera ejecucion en vez de ser una eleccion
    /// consciente del usuario desde Configuracion.
    pub fn bootstrap_default() -> Self {
        Self {
            checks: vec![
                CheckConfig { id: "defender_realtime_protection".to_string(), enabled: true, mandatory: true },
                CheckConfig { id: "bitlocker_enabled".to_string(), enabled: false, mandatory: false },
            ],
        }
    }
}

pub fn load_policy() -> io::Result<SecurityPolicy> {
    let path = policy_path();
    if !path.exists() {
        let policy = SecurityPolicy::bootstrap_default();
        save_policy(&policy)?;
        return Ok(policy);
    }

    let raw = std::fs::read_to_string(path)?;
    toml::from_str(&raw).map_err(io::Error::other)
}

pub fn save_policy(policy: &SecurityPolicy) -> io::Result<()> {
    ensure_data_dirs()?;
    let toml = toml::to_string_pretty(policy).map_err(io::Error::other)?;
    std::fs::write(policy_path(), toml)
}

/// Preferencias generales de la app (no son "seguridad" como
/// `SecurityPolicy`, pero viven bajo la misma seccion protegida de
/// Configuracion en la UI, asi que se guardan igual: TOML bajo
/// `%ProgramData%\PorteroVPN\`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppPreferences {
    /// Activo por defecto: minimizar la ventana a la bandeja en cuanto una
    /// conexion llega a "Conectado", en vez de dejarla ocupando el panel.
    pub minimize_on_connect: bool,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self { minimize_on_connect: true }
    }
}

pub fn load_preferences() -> io::Result<AppPreferences> {
    let path = preferences_path();
    if !path.exists() {
        let prefs = AppPreferences::default();
        save_preferences(&prefs)?;
        return Ok(prefs);
    }

    let raw = std::fs::read_to_string(path)?;
    toml::from_str(&raw).map_err(io::Error::other)
}

pub fn save_preferences(prefs: &AppPreferences) -> io::Result<()> {
    ensure_data_dirs()?;
    let toml = toml::to_string_pretty(prefs).map_err(io::Error::other)?;
    std::fs::write(preferences_path(), toml)
}

/// `None` si todavia no se ha definido contrasena de configuracion (primer
/// arranque, ver plan seccion 6).
pub fn read_config_password_hash() -> io::Result<Option<String>> {
    let path = config_password_hash_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(std::fs::read_to_string(path)?.trim().to_string()))
}

pub fn write_config_password_hash(phc_hash: &str) -> io::Result<()> {
    ensure_data_dirs()?;
    std::fs::write(config_password_hash_path(), phc_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `data_dir()` lee la variable de entorno `ProgramData` en cada
    /// llamada, que es estado global del proceso: como `cargo test` corre
    /// los tests de un mismo binario en paralelo por defecto, hace falta
    /// serializar el acceso para que dos tests no se pisen el directorio
    /// temporal el uno al otro.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn with_temp_program_data<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().expect("no se pudo crear directorio temporal");
        let previous = std::env::var("ProgramData").ok();
        unsafe { std::env::set_var("ProgramData", temp.path()) };

        let result = f();

        unsafe {
            match previous {
                Some(value) => std::env::set_var("ProgramData", value),
                None => std::env::remove_var("ProgramData"),
            }
        }
        result
    }

    #[test]
    fn bootstrap_policy_created_on_first_load() {
        with_temp_program_data(|| {
            let policy = load_policy().expect("load_policy fallo");
            assert_eq!(policy.checks.len(), 2);
            let antivirus = policy.checks.iter().find(|c| c.id == "defender_realtime_protection").unwrap();
            assert!(antivirus.enabled && antivirus.mandatory);
            let bitlocker = policy.checks.iter().find(|c| c.id == "bitlocker_enabled").unwrap();
            assert!(!bitlocker.enabled && !bitlocker.mandatory);
            assert!(policy_path().exists());
        });
    }

    #[test]
    fn import_and_list_profile_roundtrip() {
        with_temp_program_data(|| {
            let source = tempfile::NamedTempFile::new().expect("no se pudo crear .ovpn temporal");
            std::fs::write(source.path(), "client\ndev tun\n").unwrap();

            let meta = import_profile(source.path(), "Synology".to_string(), false).expect("import fallo");
            assert!(meta.stored_ovpn_path.exists());

            let profiles = list_profiles().expect("list_profiles fallo");
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles[0].display_name, "Synology");

            delete_profile(meta.id).expect("delete fallo");
            assert!(list_profiles().expect("list_profiles fallo").is_empty());
        });
    }

    #[test]
    fn config_password_hash_roundtrip() {
        with_temp_program_data(|| {
            assert_eq!(read_config_password_hash().unwrap(), None);
            write_config_password_hash("$argon2id$v=19$m=19456,t=2,p=1$abc$def").unwrap();
            assert_eq!(
                read_config_password_hash().unwrap(),
                Some("$argon2id$v=19$m=19456,t=2,p=1$abc$def".to_string())
            );
        });
    }

    #[test]
    fn prune_connection_logs_keeps_only_the_newest() {
        with_temp_program_data(|| {
            ensure_data_dirs().expect("ensure_data_dirs fallo");
            let dir = connection_logs_dir();

            for i in 0..15u64 {
                let path = dir.join(format!("conn-{i}.log"));
                let file = std::fs::File::create(&path).expect("no se pudo crear log de prueba");
                // Fecha de modificacion explicita en vez de confiar en el
                // reloj real: la resolucion del sistema de ficheros podria
                // no distinguir ficheros creados en la misma prueba.
                let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(i);
                file.set_modified(modified).expect("no se pudo fijar la fecha de modificacion");
            }

            prune_connection_logs(10);

            let remaining: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .collect();
            assert_eq!(remaining.len(), 10);
            for i in 5..15u64 {
                assert!(remaining.contains(&format!("conn-{i}.log")), "falta conn-{i}.log");
            }
        });
    }

    #[test]
    fn preferences_default_to_minimize_on_connect() {
        with_temp_program_data(|| {
            let prefs = load_preferences().expect("load_preferences fallo");
            assert!(prefs.minimize_on_connect);
            assert!(preferences_path().exists());

            let updated = AppPreferences { minimize_on_connect: false };
            save_preferences(&updated).expect("save_preferences fallo");
            assert_eq!(load_preferences().unwrap(), updated);
        });
    }
}
