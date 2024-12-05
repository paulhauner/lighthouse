use crate::test_utils::TestRandom;
use crate::{Epoch, Hash256};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Casper FFG checkpoint, used in attestations.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Hash,
    Serialize,
    Deserialize,
    TreeHash,
    TestRandom,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Hash256,
}

/// Use a custom implementation of SSZ to avoid the overhead of the derive macro.
impl Encode for Checkpoint {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.epoch.ssz_append(buf);
        self.root.ssz_append(buf);
    }

    fn ssz_fixed_len() -> usize {
        <Epoch as Decode>::ssz_fixed_len()
            .checked_add(<Hash256 as Decode>::ssz_fixed_len())
            .expect("checkpoint ssz_fixed_len too large")
    }

    fn ssz_bytes_len(&self) -> usize {
        <Self as Encode>::ssz_fixed_len()
    }
}

/// Use a custom implementation of SSZ to avoid the overhead of the derive macro.
impl Decode for Checkpoint {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        <Self as Encode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let expected = <Self as Decode>::ssz_fixed_len();

        let (epoch, root) = bytes
            .split_at_checked(<Epoch as Decode>::ssz_fixed_len())
            .ok_or(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected,
            })?;

        if root.len() != <Hash256 as Decode>::ssz_fixed_len() {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected,
            });
        }

        let epoch = {
            let mut array = [0; 8];
            array.copy_from_slice(epoch);
            u64::from_le_bytes(array)
        };

        Ok(Self {
            epoch: Epoch::new(epoch),
            root: Hash256::from_slice(root),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(Checkpoint);
}
