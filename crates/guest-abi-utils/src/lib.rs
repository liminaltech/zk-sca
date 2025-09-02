#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

extern crate alloc;

mod tar;
pub use tar::{TarHeader, block_count, parse_tar_header};

mod merkle_verifier;
pub use merkle_verifier::{ValidPartialArchive, ValidatedFile, validate_merkle_archive};

#[cfg(feature = "std")]
mod merkle_builder;
#[cfg(feature = "std")]
pub use merkle_builder::build_merkle_archive;
