use crate::test_utils::TestRandom;
use crate::EthSpec;
use arbitrary::Arbitrary;
use rand::RngCore;
use serde::{de, ser::Serializer, Deserialize, Deserializer, Serialize};
use ssz::{encode_length, read_offset, Decode, DecodeError, Encode, BYTES_PER_LENGTH_OFFSET};
use std::marker::PhantomData;
use tree_hash::TreeHash;

#[derive(Default, Debug, Clone)]
pub struct TransactionsOpaque<E> {
    offsets: Vec<usize>,
    bytes: Vec<u8>,
    _phantom: PhantomData<E>,
}

impl<E> TransactionsOpaque<E> {
    pub fn iter<'a>(&'a self) -> TransactionsOpaqueIter<'a> {
        TransactionsOpaqueIter {
            offsets: &self.offsets,
            bytes: &self.bytes,
        }
    }

    fn len_offset_bytes(&self) -> usize {
        self.offsets.len().saturating_mul(BYTES_PER_LENGTH_OFFSET)
    }
}

impl<E: EthSpec> Encode for TransactionsOpaque<E> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let len_offset_bytes = self.len_offset_bytes();
        buf.reserve(self.ssz_bytes_len());
        for offset in &self.offsets {
            let offset = offset.saturating_add(len_offset_bytes);
            buf.extend_from_slice(&encode_length(offset));
        }
        buf.extend_from_slice(&self.bytes);
    }

    fn ssz_bytes_len(&self) -> usize {
        self.len_offset_bytes().saturating_add(self.bytes.len())
    }
}

impl<E: EthSpec> Decode for TransactionsOpaque<E> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_fixed_len() -> usize {
        panic!("TransactionsOpaque is not fixed length");
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }

        let (offset_bytes, value_bytes) = {
            let first_offset = read_offset(bytes)?;
            sanitize_offset(first_offset, None, bytes.len(), Some(first_offset))?;

            if first_offset % BYTES_PER_LENGTH_OFFSET != 0 || first_offset < BYTES_PER_LENGTH_OFFSET
            {
                return Err(DecodeError::InvalidListFixedBytesLen(first_offset));
            }

            bytes
                .split_at_checked(first_offset)
                .ok_or(DecodeError::OffsetOutOfBounds(first_offset))?
        };

        // Disallow lists that have too many transactions.
        let num_items = offset_bytes.len() / BYTES_PER_LENGTH_OFFSET;
        let max_tx_count = <E as EthSpec>::max_transactions_per_payload();
        if num_items > max_tx_count {
            return Err(DecodeError::BytesInvalid(format!(
                "List of {} txs exceeds maximum of {:?}",
                num_items, max_tx_count
            )));
        }

        let max_tx_bytes = <E as EthSpec>::max_bytes_per_transaction();
        let mut offsets = Vec::with_capacity(num_items);
        let mut offset_iter = offset_bytes.chunks(BYTES_PER_LENGTH_OFFSET).peekable();
        while let Some(offset) = offset_iter.next() {
            let offset = read_offset(offset)?;

            // Make the offset assume that the values start at index 0, rather
            // than following the offset bytes.
            let offset = offset
                .checked_sub(offset_bytes.len())
                .ok_or(DecodeError::OffsetIntoFixedPortion(offset))?;

            let next_offset = offset_iter
                .peek()
                .copied()
                .map(read_offset)
                .unwrap_or(Ok(value_bytes.len()))?;

            // Disallow any offset that is lower than the previous.
            let tx_len = next_offset
                .checked_sub(offset)
                .ok_or(DecodeError::OffsetsAreDecreasing(offset))?;

            // Disallow transactions that are too large.
            if tx_len > max_tx_bytes {
                return Err(DecodeError::BytesInvalid(format!(
                    "length of {tx_len} exceeds maximum tx length of {max_tx_bytes}",
                )));
            }

            // Disallow an offset that points outside of the value bytes.
            if offset > value_bytes.len() {
                return Err(DecodeError::OffsetOutOfBounds(offset));
            }

            offsets.push(offset);
        }

        Ok(Self {
            offsets,
            bytes: value_bytes.to_vec(),
            _phantom: PhantomData,
        })
    }
}

pub struct TransactionsOpaqueIter<'a> {
    offsets: &'a [usize],
    bytes: &'a [u8],
}

impl<'a> Iterator for TransactionsOpaqueIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (offset, offsets) = self.offsets.split_first()?;
        let next_offset = offsets.first().copied().unwrap_or(self.bytes.len());
        self.offsets = offsets;
        self.bytes.get(*offset..next_offset)
    }
}

/// Serialization for http requests.
impl<E> Serialize for TransactionsOpaque<E> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        todo!("impl serde serialize")
    }
}

impl<'de, E> Deserialize<'de> for TransactionsOpaque<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!("impl serde deserialize")
    }
}

impl<E> TreeHash for TransactionsOpaque<E> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        todo!("impl tree hash")
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        todo!("impl tree hash")
    }

    fn tree_hash_packing_factor() -> usize {
        todo!("impl tree hash")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        todo!("impl tree hash")
    }
}

impl<E> TestRandom for TransactionsOpaque<E> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        todo!("impl test random")
    }
}

impl<E> Arbitrary<'_> for TransactionsOpaque<E> {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        todo!("impl arbitrary")
    }
}

/// TODO: export from ssz crate.
pub fn sanitize_offset(
    offset: usize,
    previous_offset: Option<usize>,
    num_bytes: usize,
    num_fixed_bytes: Option<usize>,
) -> Result<usize, DecodeError> {
    if num_fixed_bytes.map_or(false, |fixed_bytes| offset < fixed_bytes) {
        Err(DecodeError::OffsetIntoFixedPortion(offset))
    } else if previous_offset.is_none()
        && num_fixed_bytes.map_or(false, |fixed_bytes| offset != fixed_bytes)
    {
        Err(DecodeError::OffsetSkipsVariableBytes(offset))
    } else if offset > num_bytes {
        Err(DecodeError::OffsetOutOfBounds(offset))
    } else if previous_offset.map_or(false, |prev| prev > offset) {
        Err(DecodeError::OffsetsAreDecreasing(offset))
    } else {
        Ok(offset)
    }
}
