#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::unreadable_literal)]

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
