//! Contrasena de configuracion que protege la seccion Configuracion/Seguridad
//! (plan, secciones 4 y 6). Hash con Argon2id via el formato PHC estandar,
//! que ya embebe la sal y los parametros -- no hace falta guardarla aparte.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no se pudo generar el hash de la contrasena")]
    Hash,
    #[error("el hash almacenado no es valido")]
    InvalidStoredHash,
    #[error("contrasena incorrecta")]
    WrongPassword,
}

/// Genera el string PHC de argon2id para una contrasena en claro, listo para
/// persistir en `config-password.hash`.
pub fn hash_password(plain_password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain_password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AuthError::Hash)
}

/// Verifica una contrasena en claro contra un hash PHC ya almacenado.
pub fn verify_password(plain_password: &str, stored_phc_hash: &str) -> Result<(), AuthError> {
    let parsed_hash = PasswordHash::new(stored_phc_hash).map_err(|_| AuthError::InvalidStoredHash)?;
    Argon2::default()
        .verify_password(plain_password.as_bytes(), &parsed_hash)
        .map_err(|_| AuthError::WrongPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_password_verifies() {
        let hash = hash_password("correcto-caballo-bateria-grapadora").unwrap();
        assert!(verify_password("correcto-caballo-bateria-grapadora", &hash).is_ok());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let hash = hash_password("correcto-caballo-bateria-grapadora").unwrap();
        assert!(matches!(verify_password("otra-cosa", &hash), Err(AuthError::WrongPassword)));
    }

    #[test]
    fn same_password_produces_different_hashes_due_to_salt() {
        let a = hash_password("misma-contrasena").unwrap();
        let b = hash_password("misma-contrasena").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("misma-contrasena", &a).is_ok());
        assert!(verify_password("misma-contrasena", &b).is_ok());
    }
}
