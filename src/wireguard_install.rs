//! Descarga e instalacion de WireGuard para Windows desde la propia
//! aplicacion, en paralelo a `openvpn_install`.
//!
//! # Por que la verificacion es distinta a la de OpenVPN
//!
//! OpenVPN publica una firma GPG separada y `openvpn_install` la comprueba
//! contra una huella fijada. WireGuard no: sus MSI van firmados con
//! **Authenticode**, la firma va dentro del propio fichero y la valida Windows.
//!
//! No basta con `WinVerifyTrust`. Eso solo dice que el fichero esta firmado por
//! *alguien* con un certificado de confianza y que no se ha manipulado desde
//! entonces; cualquiera con un certificado de firma de codigo lo pasaria. Por
//! eso ademas se comprueba **quien** firma, contra `EXPECTED_SIGNER`, que es el
//! equivalente a fijar la huella GPG en el flujo de OpenVPN. Sin esa segunda
//! comprobacion, un CDN comprometido podria servir un MSI valido pero ajeno.

use std::path::{Path, PathBuf};

use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::elevate;
use crate::i18n::{self, t, Msg};
use crate::openvpn_install::InstallEvent;

const DOWNLOAD_INDEX_URL: &str = "https://download.wireguard.com/windows-client/";

/// Nombre del firmante que debe llevar el MSI. Es el ancla de confianza de
/// todo esto: ver la nota del modulo.
const EXPECTED_SIGNER: &str = "WireGuard LLC";

/// Solo x64: la aplicacion misma solo se distribuye para x64 (ver
/// `ArchitecturesAllowed` en el instalador de Inno Setup).
const MSI_PREFIX: &str = "wireguard-amd64-";

#[derive(Debug, thiserror::Error)]
pub enum WireGuardInstallError {
    #[error("no se pudo consultar {url}: {source}")]
    Http { url: String, source: Box<ureq::Error> },
    #[error("no se pudo leer la respuesta de {url}: {source}")]
    ReadBody { url: String, source: Box<ureq::Error> },
    #[error("no se encontro ninguna version de WireGuard para 64 bits en {DOWNLOAD_INDEX_URL}")]
    NoRelease,
    #[error("no se pudo guardar el instalador descargado: {0}")]
    Save(#[from] std::io::Error),
    #[error("la firma del instalador descargado no es valida: {0}")]
    Signature(String),
    #[error("no se pudo instalar WireGuard (registro en {log_path}): {source}")]
    MsiInstall { log_path: String, source: crate::elevate::ElevationError },
}

/// Version publicada, con su nombre de fichero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub version: String,
    pub file_name: String,
}

impl ReleaseInfo {
    fn url(&self) -> String {
        format!("{DOWNLOAD_INDEX_URL}{}", self.file_name)
    }

    /// Para ordenar versiones numericamente y no alfabeticamente: "1.10" es
    /// posterior a "1.9" aunque ordene antes como texto.
    fn sort_key(&self) -> Vec<u64> {
        self.version.split('.').map(|part| part.parse().unwrap_or(0)).collect()
    }
}

pub fn is_installed() -> bool {
    svc_ipc::wireguard_path::is_installed()
}

/// Mismo reparto que `openvpn_install::spawn_install`: todo el trabajo es
/// sincrono, asi que va en `spawn_blocking` y necesita el runtime ya entrado.
pub fn spawn_install() -> tokio::sync::mpsc::UnboundedReceiver<InstallEvent> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::task::spawn_blocking(move || run_install(tx));
    rx
}

fn run_install(tx: tokio::sync::mpsc::UnboundedSender<InstallEvent>) {
    let _ = tx.send(InstallEvent::Status(t(Msg::WgInstallSearching).to_string()));
    let release = match fetch_latest_release() {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(InstallEvent::Error(e.to_string()));
            return;
        }
    };

    let _ = tx.send(InstallEvent::Status(i18n::downloading_wireguard(&release.version)));
    let dest_dir = std::env::temp_dir().join("PorteroVPN-WireGuardInstall");
    let msi_path = match download_and_verify(&release, &dest_dir) {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.send(InstallEvent::Error(e.to_string()));
            return;
        }
    };

    let _ = tx.send(InstallEvent::Status(t(Msg::WgInstallRunningMsi).to_string()));
    let result = install_elevated(&msi_path);
    // El MSI verificado no aporta nada una vez instalado (o si fallo): se
    // borra siempre, como hace el flujo de OpenVPN.
    let _ = std::fs::remove_dir_all(&dest_dir);

    match result {
        Ok(()) => {
            let _ = tx.send(InstallEvent::Done);
        }
        Err(e) => {
            let _ = tx.send(InstallEvent::Error(e.to_string()));
        }
    }
}

pub fn fetch_latest_release() -> Result<ReleaseInfo, WireGuardInstallError> {
    let html = http_get_text(DOWNLOAD_INDEX_URL)?;
    parse_latest_release(&html).ok_or(WireGuardInstallError::NoRelease)
}

/// Descarga el MSI y **solo lo devuelve si su firma Authenticode es valida y
/// la firma `EXPECTED_SIGNER`**. Si algo falla, el fichero se borra: no debe
/// quedar un instalador sin verificar al alcance de nadie.
pub fn download_and_verify(release: &ReleaseInfo, dest_dir: &Path) -> Result<PathBuf, WireGuardInstallError> {
    std::fs::create_dir_all(dest_dir)?;
    let msi_path = dest_dir.join(&release.file_name);

    let bytes = http_get_bytes(&release.url())?;
    std::fs::write(&msi_path, &bytes)?;

    if let Err(e) = verify_authenticode(&msi_path, EXPECTED_SIGNER) {
        let _ = std::fs::remove_file(&msi_path);
        return Err(e);
    }
    Ok(msi_path)
}

pub fn install_elevated(msi_path: &Path) -> Result<(), WireGuardInstallError> {
    let msiexec = PathBuf::from("msiexec.exe");
    // `/log` por el mismo motivo que en OpenVPN: sin el, un fallo del MSI solo
    // deja un codigo de salida generico que no dice nada.
    let log_path = msi_path.with_extension("log");
    // Sin `ADDLOCAL`: el MSI de WireGuard no tiene features opcionales que
    // elegir, a diferencia del de OpenVPN.
    let params = format!("/i \"{}\" /passive /log \"{}\"", msi_path.display(), log_path.display());
    elevate::run_elevated_and_wait(&msiexec, &params, SW_SHOWNORMAL)
        .map_err(|source| WireGuardInstallError::MsiInstall { log_path: log_path.display().to_string(), source })
}

// ---------------------------------------------------------------------------
// Verificacion Authenticode
// ---------------------------------------------------------------------------

/// Comprueba que `path` tiene una firma Authenticode valida **y** que quien
/// firma es `expected_signer`.
///
/// Las dos mitades hacen falta: `WinVerifyTrust` responde "esta firmado por
/// alguien de confianza y no se ha tocado", que no es lo mismo que "lo firmo
/// WireGuard".
fn verify_authenticode(path: &Path, expected_signer: &str) -> Result<(), WireGuardInstallError> {
    win_verify_trust(path)?;

    let signer = authenticode_signer_name(path)?;
    if signer != expected_signer {
        return Err(WireGuardInstallError::Signature(format!(
            "firmado por \"{signer}\" en vez de \"{expected_signer}\""
        )));
    }
    Ok(())
}

fn to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

fn win_verify_trust(path: &Path) -> Result<(), WireGuardInstallError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    let wide = to_wide(path);

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        // Comprobar revocacion de la cadena entera: un certificado revocado no
        // debe pasar solo porque siga siendo criptograficamente valido.
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file_info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        ..Default::default()
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe { WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _) };

    // Cerrar el estado pase lo que pase: WinVerifyTrust reserva contexto en la
    // llamada de verificacion y hay que devolverselo.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);
    }

    if status != 0 {
        return Err(WireGuardInstallError::Signature(format!(
            "WinVerifyTrust rechazo el fichero (codigo 0x{:08X})",
            status as u32
        )));
    }
    Ok(())
}

/// Nombre para mostrar del certificado que firma el fichero.
fn authenticode_signer_name(path: &Path) -> Result<String, WireGuardInstallError> {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CryptMsgClose, CryptQueryObject, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_CONTENT_TYPE, CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_FORMAT_TYPE, CERT_QUERY_OBJECT_FILE, HCERTSTORE,
    };

    let wide = to_wide(path);

    let mut encoding = CERT_QUERY_ENCODING_TYPE::default();
    let mut content_type = CERT_QUERY_CONTENT_TYPE::default();
    let mut format_type = CERT_QUERY_FORMAT_TYPE::default();
    let mut store = HCERTSTORE::default();
    let mut msg: *mut core::ffi::c_void = std::ptr::null_mut();

    unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr() as *const core::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(&mut encoding),
            Some(&mut content_type),
            Some(&mut format_type),
            Some(&mut store),
            Some(&mut msg),
            None,
        )
        .map_err(|e| WireGuardInstallError::Signature(format!("no se pudo leer la firma: {e}")))?;
    }

    // A partir de aqui hay dos recursos que liberar en todos los caminos de
    // salida, asi que el cuerpo va aparte y la limpieza ocurre siempre.
    let result = unsafe { signer_name_from_message(msg, store) };

    unsafe {
        if !msg.is_null() {
            let _ = CryptMsgClose(Some(msg));
        }
        if !store.is_invalid() {
            let _ = CertCloseStore(store, 0);
        }
    }
    result
}

/// # Safety
/// `msg` y `store` deben ser los que devolvio `CryptQueryObject` y seguir
/// vivos durante toda la llamada.
unsafe fn signer_name_from_message(
    msg: *mut core::ffi::c_void,
    store: windows::Win32::Security::Cryptography::HCERTSTORE,
) -> Result<String, WireGuardInstallError> {
    use windows::Win32::Security::Cryptography::{
        CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgGetParam,
        CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_ENCODING_TYPE,
        CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let firma = |detalle: String| WireGuardInstallError::Signature(detalle);

    // Primero el tamano, luego el contenido: el patron habitual de CryptoAPI.
    let mut size = 0u32;
    CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut size)
        .map_err(|e| firma(format!("no se pudo medir la informacion del firmante: {e}")))?;

    let mut buffer = vec![0u8; size as usize];
    CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, Some(buffer.as_mut_ptr() as *mut _), &mut size)
        .map_err(|e| firma(format!("no se pudo leer la informacion del firmante: {e}")))?;

    let signer = &*(buffer.as_ptr() as *const CMSG_SIGNER_INFO);

    // El mensaje solo trae emisor y numero de serie; con eso se busca el
    // certificado completo dentro del almacen que vino con el fichero.
    let mut cert_info = CERT_INFO { Issuer: signer.Issuer, SerialNumber: signer.SerialNumber, ..Default::default() };

    let cert = CertFindCertificateInStore(
        store,
        CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
        0,
        CERT_FIND_SUBJECT_CERT,
        Some(&mut cert_info as *mut _ as *const core::ffi::c_void),
        None,
    );
    if cert.is_null() {
        return Err(firma("no se encontro el certificado del firmante".to_string()));
    }

    // Igual que antes: pedir tamano y luego contenido. `CertGetNameStringW`
    // devuelve el numero de caracteres incluido el terminador nulo.
    let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
    let name = if len <= 1 {
        String::new()
    } else {
        let mut wide = vec![0u16; len as usize];
        CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut wide));
        String::from_utf16_lossy(&wide[..(len as usize).saturating_sub(1)])
    };

    let _ = CertFreeCertificateContext(Some(cert));

    if name.is_empty() {
        return Err(firma("el certificado del firmante no tiene nombre".to_string()));
    }
    Ok(name)
}

fn http_get_text(url: &str) -> Result<String, WireGuardInstallError> {
    let mut response = ureq::get(url)
        .call()
        .map_err(|e| WireGuardInstallError::Http { url: url.to_string(), source: Box::new(e) })?;
    response
        .body_mut()
        .read_to_string()
        .map_err(|e| WireGuardInstallError::ReadBody { url: url.to_string(), source: Box::new(e) })
}

fn http_get_bytes(url: &str) -> Result<Vec<u8>, WireGuardInstallError> {
    let mut response = ureq::get(url)
        .call()
        .map_err(|e| WireGuardInstallError::Http { url: url.to_string(), source: Box::new(e) })?;
    response
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| WireGuardInstallError::ReadBody { url: url.to_string(), source: Box::new(e) })
}

/// Se queda con la version mas alta de `wireguard-amd64-<version>.msi` que
/// aparezca en el indice de descargas.
fn parse_latest_release(html: &str) -> Option<ReleaseInfo> {
    let mut best: Option<ReleaseInfo> = None;
    let mut rest = html;

    while let Some(start) = rest.find(MSI_PREFIX) {
        let tail = &rest[start..];
        let end = tail.find(".msi").map(|i| i + 4);
        rest = &rest[start + MSI_PREFIX.len()..];

        let Some(end) = end else { continue };
        let file_name = &tail[..end];
        let Some(candidate) = parse_release_filename(file_name) else { continue };

        if best.as_ref().is_none_or(|b| candidate.sort_key() > b.sort_key()) {
            best = Some(candidate);
        }
    }
    best
}

/// `wireguard-amd64-1.1.msi` -> version "1.1". Devuelve `None` para cualquier
/// otra cosa (otras arquitecturas, ficheros de firma, nombres raros).
fn parse_release_filename(name: &str) -> Option<ReleaseInfo> {
    let version = name.strip_prefix(MSI_PREFIX)?.strip_suffix(".msi")?;
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    Some(ReleaseInfo { version: version.to_string(), file_name: name.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Indice real de https://download.wireguard.com/windows-client/, reducido.
    const INDICE: &str = r#"
        <a href="wireguard-installer.exe">wireguard-installer.exe</a>
        <a href="wireguard-amd64-0.5.3.msi">wireguard-amd64-0.5.3.msi</a>
        <a href="wireguard-amd64-1.1.msi">wireguard-amd64-1.1.msi</a>
        <a href="wireguard-arm64-1.1.msi">wireguard-arm64-1.1.msi</a>
        <a href="wireguard-x86-1.1.msi">wireguard-x86-1.1.msi</a>
    "#;

    #[test]
    fn picks_the_latest_amd64_msi() {
        let release = parse_latest_release(INDICE).expect("deberia encontrar una version");
        assert_eq!(release.version, "1.1");
        assert_eq!(release.file_name, "wireguard-amd64-1.1.msi");
        assert_eq!(release.url(), "https://download.wireguard.com/windows-client/wireguard-amd64-1.1.msi");
    }

    /// La aplicacion solo se distribuye para x64: coger un MSI de arm64 o x86
    /// instalaria algo que no sirve en este equipo.
    #[test]
    fn ignores_other_architectures_and_the_generic_installer() {
        assert!(parse_release_filename("wireguard-arm64-1.1.msi").is_none());
        assert!(parse_release_filename("wireguard-x86-1.1.msi").is_none());
        assert!(parse_release_filename("wireguard-installer.exe").is_none());
    }

    /// Ordenar por texto haria "1.9" mas nuevo que "1.10".
    #[test]
    fn versions_are_compared_numerically_not_alphabetically() {
        let html = r#"<a href="wireguard-amd64-1.9.msi"></a><a href="wireguard-amd64-1.10.msi"></a>"#;
        assert_eq!(parse_latest_release(html).unwrap().version, "1.10");
    }

    #[test]
    fn returns_none_when_there_is_nothing_usable() {
        assert!(parse_latest_release("<a href=\"wireguard-installer.exe\"></a>").is_none());
        assert!(parse_latest_release("").is_none());
    }

    /// No forma parte de `cargo test` normal: descarga de red real. Sirve para
    /// comprobar a mano, con `cargo test -- --ignored --nocapture`, que el
    /// indice sigue teniendo el formato esperado y que el MSI publicado pasa
    /// la verificacion de firma con el firmante fijado.
    #[test]
    #[ignore = "hace peticiones de red reales"]
    fn real_fetch_download_and_verify() {
        let release = fetch_latest_release().expect("no se pudo consultar el indice");
        println!("version publicada: {} ({})", release.version, release.file_name);

        let dir = std::env::temp_dir().join("PorteroVPN-WireGuardInstallTest");
        let msi = download_and_verify(&release, &dir).expect("la descarga o la firma fallaron");
        println!("verificado: {}", msi.display());
        println!("firmante: {}", authenticode_signer_name(&msi).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
