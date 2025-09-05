use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zk_sca_types::PackageManagerSpec;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MerklePathNode {
    /// The sibling hash at this step of the authentication path.
    pub sibling_hash: [u8; 32],
    /// True if this node is the left child of its parent pair.
    pub is_left_child: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MerkleLeaf {
    /// A TAR block (512 bytes) that serves as one leaf in the Merkle tree.
    #[serde(with = "BigArray")]
    pub data: [u8; 512],
    /// The Merkle authentication path: ordered sibling nodes from leaf to root.
    pub path: Vec<MerklePathNode>,
}

/// Partial Merkle tree of a full TAR: each 512-B block is a leaf; all header
/// leaves are included, only the dependency-file data-block leaves are included,
/// and leaf 0 stores the host-asserted header count to prevent omission.
#[allow(clippy::too_long_first_doc_paragraph)]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct PartialMerkleArchive {
    /// The package manager used to resolve dependencies.
    pub resolved_with: PackageManagerSpec,
    /// Root hash of the full Merkle tree (count leaf included).
    pub root_hash: [u8; 32],
    /// Leaf at block 0 that asserts the TAR header count.
    pub count_leaf: MerkleLeaf,
    /// Leaves for every TAR header in archive order.
    pub header_leaves: Vec<MerkleLeaf>,
    /// Leaves for the data blocks of dependency files only (e.g., Cargo.toml / Cargo.lock) in archive order.
    pub dependency_file_leaves: Vec<MerkleLeaf>,
    /// Indices into `header_leaves` whose data blocks are in `dependency_file_leaves`.
    pub dependency_file_header_indices: Vec<usize>,
}
