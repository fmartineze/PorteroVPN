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

/// Marcador con el nombre del tunel de WireGuard que hay levantado ahora
/// mismo, si lo hay.
///
/// Existe porque un tunel de WireGuard **sobrevive a la aplicacion**: no es un
/// proceso hijo, es un servicio de Windows. Si la GUI muere con uno puesto,
/// queda una VPN activa que ya nadie sabe que existe. Con este fichero, la GUI
/// lo reconoce al arrancar y pide retirarlo.
///
/// Se resuelve asi, y no enumerando servicios desde `PorteroVPNSvc`, para no
/// meter mas codigo del imprescindible en el proceso que corre como
/// LocalSystem: mantener minima esa superficie es la decision central del
/// proyecto.
pub fn active_tunnel_marker_path() -> PathBuf {
    run_dir().join("active-tunnel")
}

pub fn mark_active_tunnel(tunnel_name: &str) -> io::Result<()> {
    ensure_data_dirs()?;
    std::fs::write(active_tunnel_marker_path(), tunnel_name)
}

pub fn clear_active_tunnel_marker() {
    let _ = std::fs::remove_file(active_tunnel_marker_path());
}

/// Nombre del tunel que quedo levantado en una ejecucion anterior, si lo hubo.
pub fn leftover_tunnel() -> Option<String> {
    let name = std::fs::read_to_string(active_tunnel_marker_path()).ok()?;
    let name = name.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
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

/// Motor con el que se levanta un perfil. El almacenamiento difiere: OpenVPN
/// guarda una copia literal del `.ovpn`, mientras que WireGuard sella el
/// `.conf` con DPAPI porque **siempre** contiene la clave privada del par
/// (ver `ProfileMeta::config_blob`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnKind {
    #[default]
    OpenVpn,
    WireGuard,
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

    /// Motor del perfil.
    ///
    /// `#[serde(default)]` **es imprescindible**: los `.meta.toml` importados
    /// antes de que WireGuard existiera no llevan este campo, y sin el atributo
    /// fallaria su deserializacion. `list_profiles` descarta con un aviso los
    /// metadatos que no puede leer, asi que el usuario se encontraria la lista
    /// de conexiones **vacia** y sin explicacion. El valor por defecto es
    /// OpenVPN, que es lo unico que podian ser.
    #[serde(default)]
    pub kind: VpnKind,

    /// El `.conf` de WireGuard entero, sellado con DPAPI. `None` en perfiles
    /// de OpenVPN.
    ///
    /// Se guarda cifrado y no como fichero porque un `.conf` de WireGuard
    /// contiene siempre `PrivateKey` en claro; dejarlo en disco seria repartir
    /// la clave del tunel a cualquiera que lea el directorio. Se materializa a
    /// un fichero temporal solo al conectar, y se borra en cuanto el tunel
    /// esta levantado (mismo patron que el passfile de un solo uso de la
    /// management interface, ver `connection::generate_passfile`).
    #[serde(default)]
    pub config_blob: Option<Vec<u8>>,
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
        kind: VpnKind::OpenVpn,
        config_blob: None,
    };

    save_profile_meta(&meta)?;
    Ok(meta)
}

/// Importa un tunel de WireGuard. A diferencia de `import_profile`, **no deja
/// ningun fichero en `profiles\`**: el `.conf` se sella con DPAPI y viaja
/// dentro del propio metadato, porque contiene la clave privada del par.
///
/// WireGuard no tiene usuario ni contrasena -- autentica con un par de claves
/// estatico -- asi que no hay nada equivalente a `remember_credentials`.
pub fn import_wireguard_profile(source_path: &Path, display_name: String) -> io::Result<ProfileMeta> {
    ensure_data_dirs()?;

    let config = std::fs::read(source_path)?;
    let sealed = crate::credentials::dpapi::protect(&config)
        .map_err(|e| io::Error::other(format!("no se pudo proteger la configuracion: {e}")))?;

    let id = Uuid::new_v4();
    let meta = ProfileMeta {
        id,
        display_name,
        imported_from: source_path.to_path_buf(),
        // Sin fichero propio: el `.conf` vive cifrado en `config_blob`. Se
        // deja la ruta que tendria por coherencia con el resto del tipo, pero
        // nada la lee en los perfiles de WireGuard.
        stored_ovpn_path: profile_ovpn_path(id),
        remember_credentials: false,
        credentials_blob: None,
        created_at: Utc::now(),
        last_connected_at: None,
        kind: VpnKind::WireGuard,
        config_blob: Some(sealed),
    };

    save_profile_meta(&meta)?;
    Ok(meta)
}

/// Recupera el `.conf` en claro de un perfil de WireGuard.
pub fn wireguard_config(meta: &ProfileMeta) -> io::Result<Vec<u8>> {
    let blob = meta
        .config_blob
        .as_ref()
        .ok_or_else(|| io::Error::other("el perfil de WireGuard no tiene configuracion guardada"))?;
    crate::credentials::dpapi::unprotect(blob)
        .map_err(|e| io::Error::other(format!("no se pudo descifrar la configuracion: {e}")))
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
                CheckConfig { id: "firewall_enabled".to_string(), enabled: false, mandatory: false },
            ],
        }
    }

    /// Anade una entrada **desactivada** por cada check registrado que todavia
    /// no figure en la politica, y devuelve si hubo cambios.
    ///
    /// Sin esto, un check nuevo seria invisible en cualquier equipo donde la
    /// aplicacion ya se haya usado: `run_pre_connect_checks` recorre
    /// `policy.toml`, no el registro, y la pantalla de Configuracion tambien
    /// se salta los checks que no encuentra en la politica. Como
    /// `bootstrap_default` solo actua cuando el fichero no existe, actualizar
    /// la app no bastaria: nadie veria el check ni se ejecutaria, y sin ningun
    /// aviso.
    ///
    /// Se anaden desactivados a proposito: actualizar no debe empezar a
    /// bloquear conexiones que antes funcionaban. Activarlos es decision del
    /// administrador.
    pub fn add_missing_checks<'a>(&mut self, registered_ids: impl IntoIterator<Item = &'a str>) -> bool {
        let mut changed = false;
        for id in registered_ids {
            if self.checks.iter().any(|c| c.id == id) {
                continue;
            }
            self.checks.push(CheckConfig { id: id.to_string(), enabled: false, mandatory: false });
            changed = true;
        }
        changed
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

    /// Idioma de la interfaz. Se resuelve una sola vez, en el primer arranque,
    /// contra el idioma de Windows (ver `bootstrap_default`); despues manda lo
    /// que el usuario elija en Configuracion.
    ///
    /// `#[serde(default)]` **es imprescindible**: los `preferences.toml` que ya
    /// existen en equipos donde la app se ha usado no tienen este campo, y sin
    /// el atributo fallaria la deserializacion entera. Como quien llama
    /// (`app.rs`) cae a `AppPreferences::default()` cuando la carga falla, el
    /// error seria mudo y ademas se llevaria por delante `minimize_on_connect`
    /// en cada arranque.
    #[serde(default)]
    pub language: crate::i18n::Lang,

    /// Cuantas veces reintentar la conexion entera, sola, cuando el servidor
    /// rechaza las credenciales, antes de dar el fallo por bueno y avisar al
    /// usuario. Existe porque un servidor que rechaza de forma intermitente
    /// unas credenciales validas suele aceptarlas a los pocos segundos sin que
    /// nadie cambie nada.
    ///
    /// `default = "..."` y no `#[serde(default)]` a secas: el `Default` de
    /// `u32` es 0, que aqui significaria "no reintentar nunca", justo lo
    /// contrario de lo que hacia la version que no tenia este ajuste.
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,

    /// Segundos de espera entre esos reintentos. Mismo cuidado con el
    /// `default`: un 0 heredado convertiria los reintentos en una rafaga.
    #[serde(default = "default_retry_delay_secs")]
    pub retry_delay_secs: u64,
}

/// Los valores que tenian las constantes del modulo `connection` antes de que
/// esto fuera configurable, para que actualizar la app no cambie el
/// comportamiento de nadie.
fn default_retry_attempts() -> u32 {
    3
}

fn default_retry_delay_secs() -> u64 {
    3
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self {
            minimize_on_connect: true,
            language: crate::i18n::Lang::default(),
            retry_attempts: default_retry_attempts(),
            retry_delay_secs: default_retry_delay_secs(),
        }
    }
}

impl AppPreferences {
    /// Preferencias de arranque cuando `preferences.toml` todavia no existe.
    ///
    /// Se separa de `Default` para que este siga siendo puro y la consulta al
    /// API de Windows quede acotada al camino de primer arranque -- mismo
    /// reparto que `SecurityPolicy::bootstrap_default`.
    pub fn bootstrap_default() -> Self {
        Self { language: crate::i18n::detect_system_language(), ..Self::default() }
    }
}

pub fn load_preferences() -> io::Result<AppPreferences> {
    let path = preferences_path();
    if !path.exists() {
        let prefs = AppPreferences::bootstrap_default();
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

    /// Se comprueban las propiedades de cada check, no cuantos hay: un
    /// recuento exacto obliga a tocar este test cada vez que se anade uno, y
    /// lo que importa de verdad es que el antivirus llegue activo y todo lo
    /// demas no.
    #[test]
    fn bootstrap_policy_created_on_first_load() {
        with_temp_program_data(|| {
            let policy = load_policy().expect("load_policy fallo");
            assert!(policy_path().exists());

            let antivirus = policy.checks.iter().find(|c| c.id == "defender_realtime_protection").unwrap();
            assert!(antivirus.enabled && antivirus.mandatory, "el antivirus debe venir activo y obligatorio");

            for id in ["bitlocker_enabled", "firewall_enabled"] {
                let check = policy
                    .checks
                    .iter()
                    .find(|c| c.id == id)
                    .unwrap_or_else(|| panic!("falta {id} en la politica de arranque"));
                assert!(!check.enabled, "{id} no debe venir activado por defecto");
                assert!(!check.mandatory, "{id} no debe venir como obligatorio por defecto");
            }
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

            let updated = AppPreferences { minimize_on_connect: false, ..AppPreferences::default() };
            save_preferences(&updated).expect("save_preferences fallo");
            assert_eq!(load_preferences().unwrap(), updated);
        });
    }

    /// Los equipos donde la app ya se uso tienen un `preferences.toml` sin
    /// campo `language`. Debe seguir leyendose, conservando lo que hubiera
    /// guardado: sin `#[serde(default)]` fallaria la deserializacion entera y
    /// `app.rs`, que cae a los valores por defecto en silencio, revertiria
    /// tambien `minimize_on_connect` en cada arranque.
    #[test]
    fn preferences_written_before_language_existed_still_load() {
        with_temp_program_data(|| {
            ensure_data_dirs().expect("ensure_data_dirs fallo");
            std::fs::write(preferences_path(), "minimize_on_connect = false\n")
                .expect("no se pudo escribir el preferences.toml antiguo");

            let prefs = load_preferences().expect("load_preferences fallo con el formato antiguo");
            assert!(!prefs.minimize_on_connect, "se perdio la preferencia ya guardada");
            assert_eq!(prefs.language, crate::i18n::Lang::default());
        });
    }

    /// Los campos de reintento llevan `#[serde(default = "...")]` y no
    /// `#[serde(default)]` a secas: el `Default` de los enteros es 0, que aqui
    /// significaria "no reintentar nunca" y "sin espera", cambiando el
    /// comportamiento a quien solo actualiza la app.
    #[test]
    fn retry_settings_fall_back_to_the_previous_hardcoded_values() {
        with_temp_program_data(|| {
            ensure_data_dirs().expect("ensure_data_dirs fallo");
            std::fs::write(preferences_path(), "minimize_on_connect = true\n")
                .expect("no se pudo escribir el preferences.toml antiguo");

            let prefs = load_preferences().expect("load_preferences fallo");
            assert_eq!(prefs.retry_attempts, 3, "los reintentos cayeron a 0 al actualizar");
            assert_eq!(prefs.retry_delay_secs, 3, "la espera entre reintentos cayo a 0 al actualizar");
        });
    }

    /// Un `policy.toml` de una version anterior no conoce los checks nuevos.
    /// Tienen que aparecer, desactivados, sin tocar lo que el usuario ya
    /// hubiera configurado.
    #[test]
    fn missing_checks_are_added_disabled_without_touching_the_existing_ones() {
        let mut policy = SecurityPolicy {
            checks: vec![CheckConfig {
                id: "defender_realtime_protection".into(),
                enabled: true,
                mandatory: true,
            }],
        };

        let changed = policy.add_missing_checks(["defender_realtime_protection", "firewall_enabled"]);

        assert!(changed);
        let defender = policy.checks.iter().find(|c| c.id == "defender_realtime_protection").unwrap();
        assert!(defender.enabled && defender.mandatory, "se piso la configuracion existente");
        let firewall = policy.checks.iter().find(|c| c.id == "firewall_enabled").unwrap();
        assert!(!firewall.enabled, "un check nuevo no debe llegar activado");
        assert!(!firewall.mandatory, "un check nuevo no debe llegar como obligatorio");
    }

    /// Sin cambios no debe reescribirse `policy.toml` en cada arranque.
    #[test]
    fn adding_checks_that_already_exist_reports_no_change() {
        let mut policy = SecurityPolicy::bootstrap_default();
        let ids: Vec<String> = policy.checks.iter().map(|c| c.id.clone()).collect();
        assert!(!policy.add_missing_checks(ids.iter().map(String::as_str)));
    }

    /// Los `.meta.toml` importados antes de que existiera WireGuard no tienen
    /// `kind` ni `config_blob`. Si fallara su deserializacion, `list_profiles`
    /// los descartaria con un aviso y el usuario se encontraria la lista de
    /// conexiones vacia sin ninguna explicacion.
    #[test]
    fn profiles_imported_before_wireguard_still_load_as_openvpn() {
        with_temp_program_data(|| {
            ensure_data_dirs().expect("ensure_data_dirs fallo");
            let id = Uuid::new_v4();
            let antiguo = format!(
                r#"id = "{id}"
display_name = "Oficina"
imported_from = 'C:\perfiles\oficina.ovpn'
stored_ovpn_path = 'C:\ProgramData\PorteroVPN\profiles\{id}.ovpn'
remember_credentials = false
created_at = "2026-08-01T09:00:00Z"
"#
            );
            std::fs::write(profiles_dir().join(format!("{id}.meta.toml")), antiguo)
                .expect("no se pudo escribir el metadato antiguo");

            let profiles = list_profiles().expect("list_profiles fallo");
            assert_eq!(profiles.len(), 1, "el perfil antiguo se perdio al listar");
            assert_eq!(profiles[0].kind, VpnKind::OpenVpn);
            assert_eq!(profiles[0].config_blob, None);
            assert_eq!(profiles[0].display_name, "Oficina");
        });
    }

    /// Importar un tunel de WireGuard no debe dejar la clave privada en disco:
    /// el `.conf` viaja cifrado dentro del metadato y no se crea fichero
    /// alguno en `profiles\` aparte de ese.
    #[test]
    fn importing_wireguard_seals_the_config_and_leaves_no_plaintext() {
        with_temp_program_data(|| {
            let source = tempfile::NamedTempFile::new().expect("no se pudo crear .conf temporal");
            let contenido = "[Interface]\nPrivateKey = CLAVE-SECRETA-DE-PRUEBA\nAddress = 10.0.0.2/32\n";
            std::fs::write(source.path(), contenido).unwrap();

            let meta = import_wireguard_profile(source.path(), "Tunel".to_string())
                .expect("import_wireguard_profile fallo");

            assert_eq!(meta.kind, VpnKind::WireGuard);
            assert!(!meta.remember_credentials, "WireGuard no tiene credenciales que recordar");

            // El blob no puede parecerse al texto en claro.
            let blob = meta.config_blob.as_ref().expect("no se guardo la configuracion");
            assert!(
                !blob.windows(contenido.len()).any(|w| w == contenido.as_bytes()),
                "la configuracion quedo en claro dentro del blob"
            );

            // Y se recupera identica.
            let recuperado = wireguard_config(&meta).expect("no se pudo descifrar");
            assert_eq!(recuperado, contenido.as_bytes());

            // En `profiles\` solo debe estar el metadato.
            let ficheros: Vec<String> = std::fs::read_dir(profiles_dir())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .collect();
            assert_eq!(ficheros, vec![format!("{}.meta.toml", meta.id)]);
        });
    }

    #[test]
    fn retry_settings_survive_a_save_and_load_roundtrip() {
        with_temp_program_data(|| {
            let updated =
                AppPreferences { retry_attempts: 7, retry_delay_secs: 12, ..AppPreferences::default() };
            save_preferences(&updated).expect("save_preferences fallo");
            assert_eq!(load_preferences().unwrap(), updated);
        });
    }
}
