use alloc::string::String;
use core::str;

#[derive(Clone, Debug)]
pub struct TarHeader {
    pub name: String,
    pub size: usize,
}

/// Parses a 512-byte tar header block to extract the file name and file size.
#[must_use]
pub fn parse_tar_header(block: &[u8; 512]) -> TarHeader {
    let name_bytes = &block[0..100];
    let name_str = str::from_utf8(name_bytes).map_or("", |s| s.trim_end_matches('\0'));
    let name = String::from(name_str);
    let size = parse_octal(&block[124..136]);
    TarHeader { name, size }
}

/// Parses an octal number from a byte slice.
fn parse_octal(input: &[u8]) -> usize {
    let mut result = 0;
    for &b in input {
        if b == 0 || b == b' ' {
            continue;
        }
        result = result * 8 + (b - b'0') as usize;
    }
    result
}

/// How many 512-byte blocks are needed to hold `size` bytes.
#[must_use]
pub const fn block_count(size: usize) -> usize {
    (size + 511) / 512
}
