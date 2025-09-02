use alloc::string::String;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TypesError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("license parsing error: {0}")]
    LicenseParse(#[from] spdx::ParseError),
}
