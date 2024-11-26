use crate::test_utils::TestRandom;
use crate::EthSpec;
use arbitrary::Arbitrary;
use derivative::Derivative;
use rand::RngCore;
use serde::{ser::Serializer, Deserialize, Deserializer, Serialize};
use ssz::{encode_length, read_offset, Decode, DecodeError, Encode, BYTES_PER_LENGTH_OFFSET};
use std::iter::IntoIterator;
use std::marker::PhantomData;
use tree_hash::{mix_in_length, MerkleHasher, TreeHash};

#[derive(Debug)]
pub enum Error {
    TooManyTransactions,
    TransactionTooBig,
}

#[derive(Debug, Clone, Derivative)]
#[derivative(Default, PartialEq, Hash(bound = "E: EthSpec"))]
pub struct TransactionsOpaque<E> {
    offsets: Vec<usize>,
    bytes: Vec<u8>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> TransactionsOpaque<E> {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn push(&mut self, item: &[u8]) -> Result<(), Error> {
        let max_tx_count = <E as EthSpec>::max_transactions_per_payload();
        let max_tx_bytes = <E as EthSpec>::max_bytes_per_transaction();

        if item.len() > max_tx_bytes {
            Err(Error::TransactionTooBig)
        } else if self.offsets.len() >= max_tx_count {
            Err(Error::TooManyTransactions)
        } else {
            self.offsets.push(self.bytes.len());
            self.bytes.extend_from_slice(item);
            Ok(())
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.into_iter()
    }

    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn len_offset_bytes(&self) -> usize {
        self.offsets.len().saturating_mul(BYTES_PER_LENGTH_OFFSET)
    }
}

impl<E: EthSpec> From<Vec<Vec<u8>>> for TransactionsOpaque<E> {
    fn from(vecs: Vec<Vec<u8>>) -> Self {
        let mut txs = Self::default();
        for vec in vecs {
            txs.push(&vec).unwrap();
        }
        txs
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

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }

        // - `offset_bytes`: first section of bytes with pointers to items.
        // - `value_bytes`: the list items pointed to by `offset_bytes`.
        let (offset_bytes, value_bytes) = {
            let first_offset = read_offset(bytes)?;

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

impl<'a, E> IntoIterator for &'a TransactionsOpaque<E> {
    type Item = &'a [u8];
    type IntoIter = TransactionsOpaqueIter<'a>;

    fn into_iter(self) -> TransactionsOpaqueIter<'a> {
        TransactionsOpaqueIter {
            offsets: &self.offsets,
            bytes: &self.bytes,
        }
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
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        todo!("impl serde serialize")
    }
}

impl<'de, E> Deserialize<'de> for TransactionsOpaque<E> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!("impl serde deserialize")
    }
}

impl<E: EthSpec> TreeHash for TransactionsOpaque<E> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        panic!("transactions should never be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        panic!("transactions should never be packed")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let mut hasher = MerkleHasher::with_leaves(<E as EthSpec>::max_transactions_per_payload());

        for tx in self.iter() {
            // Produce a "leaf" hash of the transaction.
            let leaf = {
                let mut leaf_hasher =
                    MerkleHasher::with_leaves(<E as EthSpec>::max_bytes_per_transaction());
                leaf_hasher
                    .write(tx)
                    .expect("tx too large for hasher write, logic error");
                leaf_hasher
                    .finish()
                    .expect("tx too large for hasher finish, logic error")
            };
            // Add the leaf hash to the main tree.
            hasher
                .write(leaf.as_slice())
                .expect("cannot add leaf to transactions hash tree, logic error");
        }

        let root = hasher
            .finish()
            .expect("cannot finish transactions hash tree, logic error");
        mix_in_length(&root, self.len())
    }
}

impl<E> TestRandom for TransactionsOpaque<E> {
    fn random_for_test(_rng: &mut impl RngCore) -> Self {
        todo!("impl test random")
    }
}

impl<E> Arbitrary<'_> for TransactionsOpaque<E> {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        todo!("impl arbitrary")
    }
}
