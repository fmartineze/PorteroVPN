//! Cifrado de credenciales VPN con DPAPI, ligado al usuario de Windows que
//! las genero (sin `CRYPTPROTECT_LOCAL_MACHINE`), tal como decide el plan
//! (seccion 2): guardado opt-in por perfil, nunca en claro en disco.

use windows::Win32::Foundation::LocalFree;
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows::core::PCWSTR;

/// Entropia adicional fija embebida en el binario: dificulta (no impide,
/// no es criptograficamente critica) que un blob DPAPI de esta app se
/// desencripte fuera de ella, incluso siendo el mismo usuario de Windows.
const APP_ENTROPY: &[u8] = b"PorteroVPN-credential-store-v1";

#[derive(Debug, thiserror::Error)]
pub enum DpapiError {
    #[error("CryptProtectData fallo: {0}")]
    Protect(windows::core::Error),
    #[error("CryptUnprotectData fallo: {0}")]
    Unprotect(windows::core::Error),
}

fn blob_from_slice(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
}

unsafe fn blob_to_vec(blob: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if blob.pbData.is_null() || blob.cbData == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec() }
}

/// Cifra `plaintext` (tipicamente `"usuario\0contrasena"`) para persistir en
/// `ProfileMeta::credentials_blob`.
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let input = blob_from_slice(plaintext);
    let entropy = blob_from_slice(APP_ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(DpapiError::Protect)?;

        let result = blob_to_vec(&output);
        if !output.pbData.is_null() {
            let _ = LocalFree(windows::Win32::Foundation::HLOCAL(output.pbData as *mut _));
        }
        Ok(result)
    }
}

/// Descifra un blob generado por `protect`. Solo funciona si lo invoca el
/// mismo usuario de Windows que lo genero (gratis via DPAPI, sin logica
/// adicional nuestra -- ver plan, seccion 4).
pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let input = blob_from_slice(ciphertext);
    let entropy = blob_from_slice(APP_ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(DpapiError::Unprotect)?;

        let result = blob_to_vec(&output);
        if !output.pbData.is_null() {
            let _ = LocalFree(windows::Win32::Foundation::HLOCAL(output.pbData as *mut _));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_protect_unprotect() {
        let plaintext = b"usuario\0contrasena-secreta";
        let ciphertext = protect(plaintext).expect("protect fallo");
        assert_ne!(ciphertext, plaintext);

        let decrypted = unprotect(&ciphertext).expect("unprotect fallo");
        assert_eq!(decrypted, plaintext);
    }
}
