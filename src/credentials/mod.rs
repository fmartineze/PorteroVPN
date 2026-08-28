//! Credenciales VPN por perfil: guardado opt-in cifrado con DPAPI (plan,
//! seccion 2). Si `remember_credentials` es `false`, este modulo no entra en
//! juego y la GUI simplemente pide usuario/contrasena en cada conexion.

pub mod dpapi;

use crate::i18n::{t, Msg};
use crate::storage::ProfileMeta;

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    #[error(transparent)]
    Dpapi(#[from] dpapi::DpapiError),
    // El texto se resuelve al mostrarlo, no al declararlo: `thiserror` no
    // admite una expresion en `#[error]`, asi que se implementa a mano solo
    // esta variante.
    #[error("{}", t(Msg::ErrStoredCredentialsFormat))]
    InvalidFormat,
}

impl Credentials {
    fn encode(&self) -> Vec<u8> {
        let mut buf = self.username.as_bytes().to_vec();
        buf.push(0);
        buf.extend_from_slice(self.password.as_bytes());
        buf
    }

    fn decode(raw: &[u8]) -> Result<Self, CredentialsError> {
        let separator = raw.iter().position(|&b| b == 0).ok_or(CredentialsError::InvalidFormat)?;
        let username =
            String::from_utf8(raw[..separator].to_vec()).map_err(|_| CredentialsError::InvalidFormat)?;
        let password =
            String::from_utf8(raw[separator + 1..].to_vec()).map_err(|_| CredentialsError::InvalidFormat)?;
        Ok(Self { username, password })
    }
}

pub fn seal(credentials: &Credentials) -> Result<Vec<u8>, CredentialsError> {
    Ok(dpapi::protect(&credentials.encode())?)
}

pub fn unseal(blob: &[u8]) -> Result<Credentials, CredentialsError> {
    let raw = dpapi::unprotect(blob)?;
    Credentials::decode(&raw)
}

pub fn save_for_profile(meta: &mut ProfileMeta, credentials: &Credentials) -> Result<(), CredentialsError> {
    meta.credentials_blob = Some(seal(credentials)?);
    meta.remember_credentials = true;
    Ok(())
}

pub fn load_for_profile(meta: &ProfileMeta) -> Result<Option<Credentials>, CredentialsError> {
    match &meta.credentials_blob {
        Some(blob) => Ok(Some(unseal(blob)?)),
        None => Ok(None),
    }
}

pub fn forget_for_profile(meta: &mut ProfileMeta) {
    meta.credentials_blob = None;
    meta.remember_credentials = false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let creds = Credentials { username: "alice".into(), password: "s3cret".into() };
        let decoded = Credentials::decode(&creds.encode()).unwrap();
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.password, "s3cret");
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let creds = Credentials { username: "alice".into(), password: "s3cret".into() };
        let blob = seal(&creds).expect("seal fallo");
        let unsealed = unseal(&blob).expect("unseal fallo");
        assert_eq!(unsealed.username, "alice");
        assert_eq!(unsealed.password, "s3cret");
    }
}
