#![allow(clippy::missing_panics_doc)]

use flate2::read::GzDecoder;
use risc0_zkvm::sha::{Digest, Impl, Sha256};
use std::io::{Cursor, Error as IoError, ErrorKind as IoErrorKind, Read};
use tar::Archive;
use thiserror::Error;
use zk_sca_guest_abi::{
    MerkleLeaf, MerklePathNode, PackageManager, PartialMerkleArchive, SourceBundle,
};

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
    #[error("unsupported TAR format: not USTAR")]
    UnsupportedTarFormat,
    #[error("unsupported package manager")]
    UnsupportedPackageManager,
}

fn tar_err<E: std::fmt::Display>(ctx: &str, err: E) -> IoError {
    IoError::new(IoErrorKind::InvalidData, format!("{ctx}: {err}"))
}

fn ensure_ustar(data: &[u8]) -> Result<(), BuildError> {
    let mut archive = Archive::new(Cursor::new(data));
    let mut entries = archive.entries().map_err(|e| tar_err("TAR error", e))?;
    let entry = entries
        .next()
        .transpose()
        .map_err(|e| tar_err("TAR entry error", e))?
        .ok_or_else(|| IoError::new(IoErrorKind::InvalidData, "no entries in archive"))?;

    if entry.header().as_ustar().is_some() {
        Ok(())
    } else {
        Err(BuildError::UnsupportedTarFormat)
    }
}

/// Creates a [`PartialMerkleArchive`] from a gzipped USTAR archive.
///
/// * Decompresses the bytes and verifies the USTAR format.
/// * Treats each 512-byte block as a leaf; leaf 0 stores the header count.
/// * Builds a SHA-256 Merkle tree, duplicating the final hash when a level is odd.
/// * Returns a partial tree containing only what SCA needs: the count leaf,
///   every header leaf, and the data-block leaves for manifests and lockfiles.
#[allow(clippy::too_many_lines)]
pub fn build_merkle_archive(src_bundle: &SourceBundle) -> Result<PartialMerkleArchive, BuildError> {
    let mut decoder = GzDecoder::new(src_bundle.tar_gz());
    let mut data = Vec::new();
    decoder.read_to_end(&mut data)?;

    ensure_ustar(&data)?;

    let mut archive = Archive::new(Cursor::new(data));

    let want_dep = move |hdr: &tar::Header| {
        let name = hdr
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(match src_bundle.resolved_with().manager() {
            PackageManager::Cargo { .. } => {
                name == "Cargo.toml"
                    || name.ends_with("/Cargo.toml")
                    || name == "Cargo.lock"
                    || name.ends_with("/Cargo.lock")
            }
            _ => return Err(BuildError::UnsupportedPackageManager),
        })
    };

    // Collect raw 512-byte blocks.
    let mut raw_blocks: Vec<[u8; 512]> = Vec::new();
    raw_blocks.push([0u8; 512]);
    let mut header_indices: Vec<usize> = Vec::new();
    let mut dep_raw_indices: Vec<usize> = Vec::new();
    let mut dep_header_indices: Vec<usize> = Vec::new();

    for entry_res in archive.entries().map_err(|e| tar_err("TAR error", e))? {
        let mut entry = entry_res.map_err(|e| tar_err("TAR entry error", e))?;
        let header = entry.header().clone();
        let is_dep_hdr = want_dep(&header)?;

        let hdr_raw_idx = raw_blocks.len();
        raw_blocks.push(*header.as_bytes());
        header_indices.push(hdr_raw_idx);

        let hdr_leaf_pos = header_indices.len() - 1;
        if is_dep_hdr {
            // Record header-leaf position for dependency file.
            dep_header_indices.push(hdr_leaf_pos);
        }

        let mut buf = [0u8; 512];
        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }

            let mut block = buf;
            if n < 512 {
                block[n..].fill(0);
            }

            let data_raw_idx = raw_blocks.len();
            raw_blocks.push(block);

            // Record every dependency file data-block.
            if is_dep_hdr {
                dep_raw_indices.push(data_raw_idx);
            }
        }
    }

    // Build count-leaf.
    let mut count_blk = [0u8; 512];
    let count_str = header_indices.len().to_string();
    count_blk[..count_str.len()].copy_from_slice(count_str.as_bytes());
    raw_blocks[0] = count_blk;

    // Hash all leaves.
    let leaf_hashes: Vec<[u8; 32]> = raw_blocks
        .iter()
        .map(|blk| {
            let d: Digest = *Impl::hash_bytes(blk);
            *AsRef::<[u8; 32]>::as_ref(&d)
        })
        .collect();

    // Build Merkle tree layers.
    let mut layers = vec![leaf_hashes];
    while layers.last().unwrap().len() > 1 {
        let prev = layers.last().unwrap();
        let mut next = Vec::new();
        for pair in prev.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left); // Duplicate last hash when node count is odd.
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left);
            combined[32..].copy_from_slice(&right);
            let pd: Digest = *Impl::hash_bytes(&combined);
            next.push(*AsRef::<[u8; 32]>::as_ref(&pd));
        }
        layers.push(next);
    }
    let root_hash = layers.last().unwrap()[0];

    // Generate Merkle proofs for each leaf.
    let proofs: Vec<Vec<MerklePathNode>> = (0..raw_blocks.len())
        .map(|mut idx| {
            let mut path = Vec::new();
            for level in &layers[..layers.len() - 1] {
                let is_left = idx % 2 == 0;
                let sibling = if is_left {
                    *level.get(idx + 1).unwrap_or(&level[idx])
                } else {
                    level[idx - 1]
                };
                path.push(MerklePathNode {
                    sibling_hash: sibling,
                    is_left_child: is_left,
                });
                idx /= 2; // Ascend one level
            }
            path
        })
        .collect();

    let count_leaf = MerkleLeaf {
        data: count_blk,
        path: proofs[0].clone(),
    };
    let header_leaves = header_indices
        .into_iter()
        .map(|i| MerkleLeaf {
            data: raw_blocks[i],
            path: proofs[i].clone(),
        })
        .collect();
    let dependency_file_leaves = dep_raw_indices
        .into_iter()
        .map(|i| MerkleLeaf {
            data: raw_blocks[i],
            path: proofs[i].clone(),
        })
        .collect();

    Ok(PartialMerkleArchive {
        resolved_with: src_bundle.resolved_with().clone(),
        root_hash,
        count_leaf,
        header_leaves,
        dependency_file_leaves,
        dependency_file_header_indices: dep_header_indices,
    })
}
