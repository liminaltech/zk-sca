#![allow(clippy::unused_self)]

use crate::{TarHeader, block_count, parse_tar_header};
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::str;
use hashbrown::HashSet;
use risc0_zkvm::sha::{Impl, Sha256};
use zk_sca_guest_abi::{MerkleLeaf, MerklePathNode, PartialMerkleArchive, ScaError};

type MRes<T> = Result<T, (ScaError, String)>;

#[derive(Clone, Debug)]
pub struct ValidatedFile {
    pub header: TarHeader,
    /// Raw contents (block-verified, depadded).
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct ValidPartialArchive {
    /// All tar headers (authenticated and complete, in original order).
    pub headers: Vec<TarHeader>,
    /// Authenticated, fully-materialized dependency files (header + depadded bytes)
    /// in the order specified by `dependency_file_header_indices`.
    pub files: Vec<ValidatedFile>,
}

/// Convenience: tag any error as `InvalidMerkleArchive`.
macro_rules! err {
    ($msg:expr) => {
        (ScaError::InvalidMerkleArchive, $msg.to_string())
    };
}

macro_rules! ensure {
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return Err($err);
        }
    };
}

/// Validate a [`PartialMerkleArchive`] and return authenticated headers & dependency files.
pub fn validate_merkle_archive(archive: &PartialMerkleArchive) -> MRes<ValidPartialArchive> {
    Verifier {
        archive,
        root: &archive.root_hash,
    }
    .verify()
}

/// Reconstruct the zero-based leaf index from a Merkle proof.
/// Bits are consumed LSB-first; path\[0\] is depth-0.
#[inline]
fn reconstruct_leaf_index(path: &[MerklePathNode]) -> usize {
    path.iter().enumerate().fold(0usize, |acc, (bit, node)| {
        acc | (usize::from(!node.is_left_child) << bit)
    })
}

struct Verifier<'a> {
    archive: &'a PartialMerkleArchive,
    root: &'a [u8; 32],
}

#[allow(clippy::needless_lifetimes)]
impl<'a> Verifier<'a> {
    fn verify(self) -> MRes<ValidPartialArchive> {
        let header_count = self.ensure_count_leaf_is_authentic_and_return_count()?;
        let headers = self.ensure_header_leaves_are_authentic_and_parse(header_count)?;
        self.ensure_header_names_are_unique(&headers)?;

        let files = self.ensure_dependency_blocks_are_authentic(&headers)?;

        Ok(ValidPartialArchive { headers, files })
    }

    fn ensure_count_leaf_is_authentic_and_return_count(&self) -> MRes<usize> {
        let leaf = &self.archive.count_leaf;
        self.verify_leaf_proof(&leaf.data, leaf)?;
        let count_str = str::from_utf8(&leaf.data)
            .map_err(|_| err!("Invalid UTF-8 in count_leaf"))?
            .trim_end_matches('\0');
        count_str
            .parse::<usize>()
            .map_err(|_| err!("Bad header count"))
    }

    fn ensure_header_leaves_are_authentic_and_parse(
        &self,
        expected_count: usize,
    ) -> MRes<Vec<TarHeader>> {
        let leaves = &self.archive.header_leaves;
        self.expect_len("header proofs", leaves.len(), expected_count)?;
        leaves
            .iter()
            .map(|leaf| {
                self.verify_leaf_proof(&leaf.data, leaf)?;
                Ok(parse_tar_header(&leaf.data))
            })
            .collect()
    }

    fn ensure_header_names_are_unique(&self, headers: &[TarHeader]) -> MRes<()> {
        let mut seen: HashSet<&String> = HashSet::new();
        for hdr in headers {
            ensure!(
                seen.insert(&hdr.name),
                err!(format!("Duplicate file name encountered: {0}", hdr.name))
            );
        }
        Ok(())
    }

    /// Authenticate each dependency’s data blocks and return fully-materialized files.
    fn ensure_dependency_blocks_are_authentic(
        &self,
        headers: &[TarHeader],
    ) -> MRes<Vec<ValidatedFile>> {
        let leaves = &self.archive.dependency_file_leaves;
        let header_proofs = &self.archive.header_leaves;
        let dep_indices = &self.archive.dependency_file_header_indices;

        for &idx in dep_indices {
            ensure!(
                idx < headers.len(),
                err!(format!("Bad dependency header index {idx}")),
            );
        }

        let expected_blocks: usize = dep_indices
            .iter()
            .map(|&i| block_count(headers[i].size))
            .sum();
        self.expect_len("data-block proofs", leaves.len(), expected_blocks)?;

        let mut data_iter = leaves.iter();
        let mut files = Vec::new();

        for &hdr_idx in dep_indices {
            let hdr = &headers[hdr_idx];
            let h_leaf = &header_proofs[hdr_idx];
            let needed = block_count(hdr.size);

            let header_leaf_index = reconstruct_leaf_index(&h_leaf.path);
            let mut buf = Vec::with_capacity(hdr.size);

            for offset in 1..=needed {
                let leaf = data_iter.next().ok_or_else(|| err!("Missing data leaf"))?;
                self.verify_leaf_proof(&leaf.data, leaf)?;

                let actual_idx = reconstruct_leaf_index(&leaf.path);
                let expect_idx = header_leaf_index + offset;
                ensure!(
                    actual_idx == expect_idx,
                    err!(format!(
                        "Dependency-file indices out of order: expected {expect_idx}, got {actual_idx}"
                    )),
                );
                buf.extend_from_slice(&leaf.data);
            }
            buf.truncate(hdr.size);

            files.push(ValidatedFile {
                header: hdr.clone(),
                bytes: buf,
            });
        }

        ensure!(data_iter.next().is_none(), err!("Extra data leaves"));
        Ok(files)
    }

    #[inline]
    fn expect_len(&self, what: &str, got: usize, exp: usize) -> MRes<()> {
        ensure!(
            got == exp,
            err!(format!("Expected {exp} {what}, got {got}"))
        );
        Ok(())
    }

    #[inline]
    fn verify_leaf_proof(&self, data: &[u8; 512], proof: &MerkleLeaf) -> MRes<()> {
        ensure!(
            verify_merkle_proof(data, &proof.path, self.root),
            err!("Merkle proof failed for a leaf block"),
        );
        Ok(())
    }
}

/// Check a block’s Merkle path against the archive root (SHA-256, left-duplicate rule).
fn verify_merkle_proof(data: &[u8; 512], path: &Vec<MerklePathNode>, root_hash: &[u8; 32]) -> bool {
    let mut current_hash = Impl::hash_bytes(data);
    for item in path {
        let mut combined = Vec::with_capacity(64);
        if item.is_left_child {
            combined.extend_from_slice(current_hash.as_bytes());
            combined.extend_from_slice(&item.sibling_hash);
        } else {
            combined.extend_from_slice(&item.sibling_hash);
            combined.extend_from_slice(current_hash.as_bytes());
        }
        current_hash = Impl::hash_bytes(&combined);
    }
    current_hash.as_bytes() == root_hash
}
