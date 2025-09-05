#![allow(unsafe_code)]

use crate::errors::ProverError;

/// RAII guard that sets `key=value` on construction and restores
/// the previous value on drop (or removes the variable if none existed).  
/// Construction fails with `EnvVarConflict` when `enabled == false` and
/// the variable is already present.
#[doc(hidden)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct EnvVarGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvVarGuard {
    pub fn new(key: &'static str, value: &str, enabled: bool) -> Result<Self, ProverError> {
        let prev = match std::env::var(key) {
            Ok(existing) if !enabled => {
                return Err(ProverError::EnvVarConflict(key.to_string(), existing));
            }
            Ok(existing) => Some(existing),
            Err(_) => None,
        };

        if enabled {
            unsafe { std::env::set_var(key, value) };
        }

        Ok(Self { key, prev })
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(old) => {
                unsafe { std::env::set_var(self.key, old) };
            }
            None => {
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }
}
