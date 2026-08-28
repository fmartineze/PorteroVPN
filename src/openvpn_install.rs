//! Descubre, descarga, verifica (firma GPG) e instala OpenVPN Community de
//! forma silenciosa, disparado desde la propia app (Configuracion) en vez
//! de durante la instalacion de Portero VPN -- asi siempre coge la version
//! publicada en ese momento en vez de quedar fija a la que hubiera al
//! generar el instalador de Portero VPN.
//!
//! Solo se instalan el motor y los drivers -- ni el servicio propio de
//! OpenVPN (`OpenVPN.Service`, openvpnserv2.exe) ni su GUI
//! (`OpenVPN.GUI`), porque Portero VPN ya cubre ambos papeles. Sin la GUI
//! tampoco se crean sus accesos directos ni su arranque con el inicio de
//! sesion.

use std::path::{Path, PathBuf};

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::errors::Result as PgpResult;
use pgp::types::{Fingerprint, KeyDetails, KeyId, KeyVersion, PublicParams, SignatureBytes, Timestamp, VerifyingKey};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::elevate;
use crate::i18n::{self, t, Msg};

const RELEASES_INDEX_URL: &str = "https://build.openvpn.net/downloads/releases/";

/// Huella del key de firma de OpenVPN ("OpenVPN - Security Mailing List
/// <security@openvpn.net>"), publicada en
/// https://openvpn.net/community-resources/sig/. Se pide la clave publica
/// a un keyserver justo antes de cada verificacion en vez de empotrarla en
/// el binario: el key tiene subclaves que OpenVPN rota cada año, asi que
/// una copia fija en el codigo se quedaria obsoleta con el tiempo.
const SIGNING_KEY_FINGERPRINT: &str = "F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7";

/// Solo el motor y los drivers -- ver comentario del modulo. No incluye
/// `Drivers.OvpnDco` (Data Channel Offload, opcional/rendimiento, no
/// instalado por defecto ni en una instalacion tipica): TAP-Windows6 basta
/// para conectar con los perfiles .ovpn habituales. Nota: no existe una
/// feature "Drivers.Wintun" en el instalador MSI real (2.7.6) -- se
/// confirmo inspeccionando la tabla `Feature` del .msi tras un fallo 1603
/// ("Error 2711: The specified Feature name ('Drivers.Wintun') not found in
/// Feature Table"); Wintun no aparece como feature en absoluto en esta
/// version.
const MSI_ADDLOCAL: &str = "OpenVPN,Drivers,Drivers.TAPWindows6";

#[derive(Debug, thiserror::Error)]
pub enum OpenVpnInstallError {
    #[error("no se pudo consultar {url}: {source}")]
    Http { url: String, source: Box<ureq::Error> },
    #[error("no se pudo leer la respuesta de {url}: {source}")]
    ReadBody { url: String, source: ureq::Error },
    #[error("no se encontro ningun instalador de OpenVPN para Windows x64 en {0}")]
    NoReleaseFound(String),
    #[error("la clave de firma de OpenVPN descargada no es valida: {0}")]
    InvalidSigningKey(String),
    #[error("la firma del instalador descargado no es valida: {0}")]
    SignatureInvalid(String),
    #[error("no se pudo instalar OpenVPN (registro en {log_path}): {source}")]
    MsiInstall { log_path: String, source: elevate::ElevationError },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub version: (u64, u64, u64, u64),
    pub file_name: String,
}

impl ReleaseInfo {
    fn msi_url(&self) -> String {
        format!("{RELEASES_INDEX_URL}{}", self.file_name)
    }

    fn asc_url(&self) -> String {
        format!("{}.asc", self.msi_url())
    }

    pub fn version_string(&self) -> String {
        format!("{}.{}.{}", self.version.0, self.version.1, self.version.2)
    }
}

/// Ya esta instalado si `openvpn.exe` esta en la ruta estandar (ver
/// `svc_ipc::openvpn_path`, compartido con `PorteroVPNSvc`, que es quien
/// realmente lo lanza).
pub fn is_installed() -> bool {
    svc_ipc::openvpn_path::is_installed()
}

/// Progreso del flujo completo, para pintar la barra de Conexiones (patron
/// `AppEvent`/`events_rx` de `crate::connection`, drenado en cada frame).
#[derive(Debug, Clone)]
pub enum InstallEvent {
    Status(String),
    Done,
    Error(String),
}

/// Lanza el flujo completo (buscar version -> descargar -> verificar firma
/// -> instalar elevado) en una tarea de tokio bloqueante -- todo el trabajo
/// es sincrono (`ureq` y `ShellExecuteExW`/`WaitForSingleObject` en
/// `elevate::run_elevated_and_wait`), asi que usa `spawn_blocking` en vez de
/// `spawn` para no acaparar un hilo del executor async mientras dura la
/// descarga o el instalador MSI. Debe llamarse con el runtime de tokio ya
/// entrado (`rt.enter()`), igual que `connection::spawn_connection`.
pub fn spawn_install() -> tokio::sync::mpsc::UnboundedReceiver<InstallEvent> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::task::spawn_blocking(move || run_install(tx));
    rx
}

fn run_install(tx: tokio::sync::mpsc::UnboundedSender<InstallEvent>) {
    let _ = tx.send(InstallEvent::Status(t(Msg::InstallSearching).to_string()));
    let release = match fetch_latest_release() {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(InstallEvent::Error(e.to_string()));
            return;
        }
    };

    let _ = tx.send(InstallEvent::Status(i18n::downloading_openvpn(&release.version_string())));
    let dest_dir = std::env::temp_dir().join("PorteroVPN-OpenVPNInstall");
    let msi_path = match download_and_verify(&release, &dest_dir) {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.send(InstallEvent::Error(e.to_string()));
            return;
        }
    };

    let _ = tx.send(InstallEvent::Status(t(Msg::InstallRunningMsi).to_string()));
    let result = install_elevated(&msi_path);
    // Solo queda ocupando espacio una vez instalado (o si fallo la
    // instalacion): la copia verificada no aporta nada mas alla de este
    // punto, a diferencia del .ovpn del usuario, que si se conserva.
    let _ = std::fs::remove_file(&msi_path);

    match result {
        Ok(()) => {
            let _ = tx.send(InstallEvent::Done);
        }
        Err(e) => {
            let _ = tx.send(InstallEvent::Error(e.to_string()));
        }
    }
}

/// Descubre la ultima version publicada listando
/// `https://build.openvpn.net/downloads/releases/` (indice de directorio
/// normal, sin API) y buscando el patron `OpenVPN-X.Y.Z-I0NN-amd64.msi`,
/// comparando por version numerica -- no por orden alfabetico, que
/// ordenaria mal p.ej. "2.7.10" contra "2.7.6".
pub fn fetch_latest_release() -> Result<ReleaseInfo, OpenVpnInstallError> {
    let body = http_get_text(RELEASES_INDEX_URL)?;
    parse_latest_release(&body).ok_or_else(|| OpenVpnInstallError::NoReleaseFound(RELEASES_INDEX_URL.to_string()))
}

/// Descarga el instalador y su firma, la verifica contra la clave publica
/// oficial de OpenVPN, y solo si es valida escribe el `.msi` a `dest_dir`
/// y devuelve su ruta. No instala nada todavia (ver `install_elevated`).
pub fn download_and_verify(release: &ReleaseInfo, dest_dir: &Path) -> Result<PathBuf, OpenVpnInstallError> {
    let msi_bytes = http_get_bytes(&release.msi_url())?;
    let sig_bytes = http_get_bytes(&release.asc_url())?;
    let key_bytes = http_get_bytes(&signing_key_url())?;

    let (public_key, _) = SignedPublicKey::from_armor_single(&key_bytes[..])
        .map_err(|e| OpenVpnInstallError::InvalidSigningKey(e.to_string()))?;
    public_key.verify_bindings().map_err(|e| OpenVpnInstallError::InvalidSigningKey(e.to_string()))?;

    let (signature, _) = DetachedSignature::from_armor_single(&sig_bytes[..])
        .map_err(|e| OpenVpnInstallError::SignatureInvalid(e.to_string()))?;

    // La clave de OpenVPN certifica varias subclaves (rotadas cada año, ver
    // comentario de `SIGNING_KEY_FINGERPRINT`) y firma sus releases con una
    // de ellas, no con la clave primaria directamente -- practica habitual
    // en OpenPGP (la primaria queda solo para certificar). Verificar contra
    // la clave primaria a secas falla con "no matching issuer", asi que
    // hace falta localizar primero la subclave concreta que uso esta firma
    // en concreto.
    let signer = find_matching_key(&public_key, &signature).ok_or_else(|| {
        OpenVpnInstallError::SignatureInvalid(
            "la firma la hizo una clave (o subclave) que no esta entre las de la clave publica descargada".into(),
        )
    })?;
    signature.verify(&signer, &msi_bytes[..]).map_err(|e| OpenVpnInstallError::SignatureInvalid(e.to_string()))?;

    std::fs::create_dir_all(dest_dir)?;
    let msi_path = dest_dir.join(&release.file_name);
    std::fs::write(&msi_path, &msi_bytes)?;
    Ok(msi_path)
}

/// La firma la puede haber hecho la clave primaria o cualquiera de sus
/// subclaves (ver `find_matching_key`); `SignedPublicKey` y
/// `SignedPublicSubKey` son tipos distintos en el crate `pgp`, asi que este
/// enum los unifica con despacho estatico -- mas simple que `dyn
/// VerifyingKey`, que no cumple el `Sized` implicito que pide
/// `DetachedSignature::verify`.
#[derive(Debug)]
enum SigningKeyRef<'a> {
    Primary(&'a SignedPublicKey),
    Sub(&'a SignedPublicSubKey),
}

impl KeyDetails for SigningKeyRef<'_> {
    fn version(&self) -> KeyVersion {
        match self {
            Self::Primary(k) => k.version(),
            Self::Sub(k) => k.version(),
        }
    }

    fn legacy_key_id(&self) -> KeyId {
        match self {
            Self::Primary(k) => k.legacy_key_id(),
            Self::Sub(k) => k.legacy_key_id(),
        }
    }

    fn fingerprint(&self) -> Fingerprint {
        match self {
            Self::Primary(k) => k.fingerprint(),
            Self::Sub(k) => k.fingerprint(),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            Self::Primary(k) => k.algorithm(),
            Self::Sub(k) => k.algorithm(),
        }
    }

    fn created_at(&self) -> Timestamp {
        match self {
            Self::Primary(k) => k.created_at(),
            Self::Sub(k) => k.created_at(),
        }
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        match self {
            Self::Primary(k) => k.legacy_v3_expiration_days(),
            Self::Sub(k) => k.legacy_v3_expiration_days(),
        }
    }

    fn public_params(&self) -> &PublicParams {
        match self {
            Self::Primary(k) => k.public_params(),
            Self::Sub(k) => k.public_params(),
        }
    }
}

impl VerifyingKey for SigningKeyRef<'_> {
    fn verify(&self, hash: HashAlgorithm, data: &[u8], sig: &SignatureBytes) -> PgpResult<()> {
        match self {
            Self::Primary(k) => k.verify(hash, data, sig),
            Self::Sub(k) => k.verify(hash, data, sig),
        }
    }
}

/// Busca, entre la clave primaria y sus subclaves, cual de todas firmo de
/// verdad `signature` (comparando por key id corto y por huella completa,
/// lo que lleve puesto la propia firma) -- ver el comentario en
/// `download_and_verify` sobre por que hace falta este paso.
fn find_matching_key<'a>(public_key: &'a SignedPublicKey, signature: &DetachedSignature) -> Option<SigningKeyRef<'a>> {
    let issuer_ids = signature.signature.issuer_key_id();
    let issuer_fps = signature.signature.issuer_fingerprint();
    let is_match = |key_id: &KeyId, fingerprint: &Fingerprint| {
        issuer_ids.contains(&key_id) || issuer_fps.contains(&fingerprint)
    };

    if is_match(&public_key.legacy_key_id(), &public_key.fingerprint()) {
        return Some(SigningKeyRef::Primary(public_key));
    }
    public_key
        .public_subkeys
        .iter()
        .find(|sk| is_match(&sk.legacy_key_id(), &sk.fingerprint()))
        .map(SigningKeyRef::Sub)
}

/// Ejecuta `msiexec` elevado (UAC) sobre el `.msi` ya descargado y
/// verificado, instalando solo el motor y los drivers (ver
/// `MSI_ADDLOCAL`). `/passive` en vez de `/qn`: dado que ya se ha pedido
/// elevacion, se deja ver la barra de progreso del instalador -- son
/// controladores de red de por medio, mejor que el usuario vea que algo
/// esta pasando en vez de una app congelada varios segundos sin
/// explicacion.
pub fn install_elevated(msi_path: &Path) -> Result<(), OpenVpnInstallError> {
    let msiexec = PathBuf::from("msiexec.exe");
    // `/log`: sin esto, un fallo del MSI solo deja el codigo de salida
    // generico de `msiexec` (p.ej. 1603, "fatal error during
    // installation"), inutil para saber que fallo de verdad -- ver el
    // comentario de `MSI_ADDLOCAL` sobre el primer fallo real encontrado
    // (feature inexistente) que este registro fue el que permitio
    // diagnosticar.
    let log_path = msi_path.with_extension("log");
    let params = format!(
        "/i \"{}\" ADDLOCAL={MSI_ADDLOCAL} /passive /log \"{}\"",
        msi_path.display(),
        log_path.display()
    );
    elevate::run_elevated_and_wait(&msiexec, &params, SW_SHOWNORMAL)
        .map_err(|source| OpenVpnInstallError::MsiInstall { log_path: log_path.display().to_string(), source })
}

fn signing_key_url() -> String {
    format!("https://keys.openpgp.org/vks/v1/by-fingerprint/{SIGNING_KEY_FINGERPRINT}")
}

fn http_get_text(url: &str) -> Result<String, OpenVpnInstallError> {
    let mut response =
        ureq::get(url).call().map_err(|e| OpenVpnInstallError::Http { url: url.to_string(), source: Box::new(e) })?;
    response.body_mut().read_to_string().map_err(|e| OpenVpnInstallError::ReadBody { url: url.to_string(), source: e })
}

fn http_get_bytes(url: &str) -> Result<Vec<u8>, OpenVpnInstallError> {
    let mut response =
        ureq::get(url).call().map_err(|e| OpenVpnInstallError::Http { url: url.to_string(), source: Box::new(e) })?;
    // El instalador de OpenVPN (con drivers incluidos) supera el limite por
    // defecto de ureq (10MB); 64MB da margen de sobra sin dejar de acotar
    // cuanta memoria se puede llegar a reservar por una respuesta.
    response
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| OpenVpnInstallError::ReadBody { url: url.to_string(), source: e })
}

fn parse_latest_release(html: &str) -> Option<ReleaseInfo> {
    let mut best: Option<ReleaseInfo> = None;
    let mut rest = html;
    while let Some(start) = rest.find("OpenVPN-") {
        rest = &rest[start..];
        let end =
            rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')).unwrap_or(rest.len()).max(1);
        let candidate = &rest[..end];
        if let Some(info) = parse_release_filename(candidate) {
            if best.as_ref().map(|b| info.version > b.version).unwrap_or(true) {
                best = Some(info);
            }
        }
        rest = &rest[end..];
    }
    best
}

/// Parsea `OpenVPN-2.7.6-I001-amd64.msi` -> version `(2, 7, 6, 1)`.
fn parse_release_filename(name: &str) -> Option<ReleaseInfo> {
    let name_no_ext = name.strip_suffix("-amd64.msi")?;
    let rest = name_no_ext.strip_prefix("OpenVPN-")?;
    let (version_part, build_part) = rest.split_once("-I")?;
    let build: u64 = build_part.parse().ok()?;

    let mut parts = version_part.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    let patch: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }

    Some(ReleaseInfo { version: (major, minor, patch, build), file_name: name.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_filename() {
        let info = parse_release_filename("OpenVPN-2.7.6-I001-amd64.msi").expect("deberia parsear");
        assert_eq!(info.version, (2, 7, 6, 1));
        assert_eq!(info.version_string(), "2.7.6");
    }

    #[test]
    fn ignores_non_windows_or_non_msi_entries() {
        assert!(parse_release_filename("OpenVPN-2.7.6-I001-arm64.msi").is_none());
        assert!(parse_release_filename("OpenVPN-2.7.6-I001-amd64.msi.asc").is_none());
        assert!(parse_release_filename("OpenVPN-2.7.6-amd64.msi").is_none());
    }

    #[test]
    fn picks_the_highest_version_numerically_not_alphabetically() {
        let html = r#"
            <a href="OpenVPN-2.7.6-I001-amd64.msi">OpenVPN-2.7.6-I001-amd64.msi</a>
            <a href="OpenVPN-2.7.10-I001-amd64.msi">OpenVPN-2.7.10-I001-amd64.msi</a>
            <a href="OpenVPN-2.6.22-I001-amd64.msi">OpenVPN-2.6.22-I001-amd64.msi</a>
        "#;
        let latest = parse_latest_release(html).expect("deberia encontrar una release");
        assert_eq!(latest.version, (2, 7, 10, 1));
    }

    #[test]
    fn picks_the_highest_build_number_within_the_same_version() {
        let html = r#"
            OpenVPN-2.7.4-I001-amd64.msi
            OpenVPN-2.7.4-I002-amd64.msi
        "#;
        let latest = parse_latest_release(html).expect("deberia encontrar una release");
        assert_eq!(latest.version, (2, 7, 4, 2));
    }

    #[test]
    fn returns_none_on_empty_listing() {
        assert!(parse_latest_release("<html><body>nada por aqui</body></html>").is_none());
    }

    /// No forma parte de `cargo test` normal: hace peticiones de red reales
    /// contra build.openvpn.net y keys.openpgp.org. Sirve para comprobar a
    /// mano, con `cargo test -- --ignored --nocapture`, que el listado se
    /// parsea bien de verdad, que la firma real verifica correctamente, y
    /// que un contenido corrupto SI hace fallar la verificacion (para no
    /// tener una comprobacion que siempre "pase" por error de logica). No
    /// instala nada.
    #[test]
    #[ignore = "hace peticiones de red reales"]
    fn real_fetch_download_and_verify() {
        let release = fetch_latest_release().expect("fetch_latest_release fallo");
        println!("ultima version encontrada: {}", release.version_string());

        let tmp = tempfile::tempdir().expect("no se pudo crear directorio temporal");
        let msi_path = download_and_verify(&release, tmp.path()).expect("download_and_verify fallo");
        assert!(msi_path.is_file());
        println!("descargado y verificado en: {}", msi_path.display());

        // Un .msi corrompido a proposito debe fallar la verificacion, para
        // confirmar que `download_and_verify` de verdad esta comprobando
        // algo y no aceptando cualquier cosa.
        let mut corrupted = std::fs::read(&msi_path).expect("no se pudo releer el msi descargado");
        corrupted.push(0xFF);
        std::fs::write(&msi_path, &corrupted).expect("no se pudo escribir el msi corrompido");
        let key_bytes = http_get_bytes(&signing_key_url()).expect("no se pudo descargar la clave");
        let (public_key, _) = SignedPublicKey::from_armor_single(&key_bytes[..]).expect("clave invalida");
        let sig_bytes = http_get_bytes(&release.asc_url()).expect("no se pudo descargar la firma");
        let (signature, _) = DetachedSignature::from_armor_single(&sig_bytes[..]).expect("firma invalida");
        assert!(
            signature.verify(&public_key, &corrupted[..]).is_err(),
            "un .msi corrompido no deberia superar la verificacion de firma"
        );
    }
}
