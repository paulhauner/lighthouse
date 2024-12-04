use crate::test_utils::TestRandom;
use crate::EthSpec;
use arbitrary::Arbitrary;
use derivative::Derivative;
use rand::RngCore;
use serde::{
    ser::{SerializeSeq, Serializer},
    Deserialize, Deserializer, Serialize,
};
use serde_utils::hex;
use ssz::{encode_length, read_offset, Decode, DecodeError, Encode, BYTES_PER_LENGTH_OFFSET};
use std::iter::IntoIterator;
use std::marker::PhantomData;
use tree_hash::{mix_in_length, MerkleHasher, TreeHash};

/// Max number of transactions in a `TestRandom` instance.
const TEST_RANDOM_MAX_TX_COUNT: usize = 128;
/// Max length of a transaction in a `TestRandom` instance.
const TEST_RANDOM_MAX_TX_BYTES: usize = 1_024;

#[derive(Debug)]
pub enum Error {
    /// Exceeds `EthSpec::max_transactions_per_payload()`
    TooManyTransactions,
    /// Exceeds `EthSpec::max_bytes_per_transaction()`
    TransactionTooBig,
}

/// The list of transactions in an execution payload.
///
/// This data-structure represents the transactions similarly to how they're
/// encoded as SSZ. This makes for fast and low-allocation-count `ssz::Decode`.
#[derive(Debug, Clone, Derivative)]
#[derivative(Default, PartialEq, Hash(bound = "E: EthSpec"))]
pub struct TransactionsOpaque<E> {
    /// Points to the first byte of each transaction in `bytes`.
    offsets: Vec<usize>,
    /// All transactions, concatenated together.
    bytes: Vec<u8>,
    /// `EthSpec` to capture maximum allowed lengths.
    _phantom: PhantomData<E>,
}

impl<E> TransactionsOpaque<E> {
    /// Creates an empty list.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Iterates all transactions in `self`.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.into_iter()
    }

    /// The number of transactions in `self``.
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// True if there are no transactions in `self`.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The length of the offset/fixed-length section of the SSZ bytes, when
    /// serialized.
    fn len_offset_bytes(&self) -> usize {
        self.offsets.len().saturating_mul(BYTES_PER_LENGTH_OFFSET)
    }
}

impl<E: EthSpec> TransactionsOpaque<E> {
    /// Adds an `item` (i.e. transaction) to the list.
    ///
    /// ## Errors
    ///
    /// - If the `item` is longer than `EthSpec::max_bytes_per_transaction()`.
    /// - If the operation would make this list longer than
    ///   `EthSpec::max_transactions_per_payload()`.
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
}

impl<E: EthSpec> From<Vec<Vec<u8>>> for TransactionsOpaque<E> {
    fn from(v: Vec<Vec<u8>>) -> Self {
        let mut txs = Self::default();
        for vec in v {
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

            // Disallow an offset that points outside of the value bytes.
            if offset > value_bytes.len() {
                return Err(DecodeError::OffsetOutOfBounds(offset));
            }

            // Read the next offset (if any) to determine the length of this
            // transaction.
            let next_offset = if let Some(next_offset) = offset_iter.peek() {
                read_offset(next_offset)?
                    .checked_sub(offset_bytes.len())
                    .ok_or(DecodeError::OffsetIntoFixedPortion(offset))?
            } else {
                value_bytes.len()
            };

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

#[derive(Default)]
pub struct Visitor<E> {
    _phantom: PhantomData<E>,
}

impl<'a, E> serde::de::Visitor<'a> for Visitor<E>
where
    E: EthSpec,
{
    type Value = TransactionsOpaque<E>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a list of 0x-prefixed hex bytes")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'a>,
    {
        let mut txs: TransactionsOpaque<E> = <_>::default();

        while let Some(hex_str) = seq.next_element::<&str>()? {
            let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
            txs.push(&bytes).map_err(|e| {
                serde::de::Error::custom(format!("failed to deserialize transaction: {:?}.", e))
            })?;
        }

        Ok(txs)
    }
}

impl<E> Serialize for TransactionsOpaque<E> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for bytes in self {
            seq.serialize_element(&hex::encode(&bytes))?;
        }
        seq.end()
    }
}

impl<'de, E: EthSpec> Deserialize<'de> for TransactionsOpaque<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(Visitor::default())
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
        let max_tx_count = <E as EthSpec>::max_transactions_per_payload();
        let max_tx_len = <E as EthSpec>::max_bytes_per_transaction();
        let bytes_per_leaf = 32;
        let tx_leaf_count = (max_tx_len + bytes_per_leaf - 1) / bytes_per_leaf;

        let mut hasher = MerkleHasher::with_leaves(max_tx_count);

        for tx in self.iter() {
            // Produce a "leaf" hash of the transaction. This is the merkle root
            // of the transaction.
            let leaf = {
                let mut leaf_hasher = MerkleHasher::with_leaves(tx_leaf_count);
                leaf_hasher
                    .write(tx)
                    .expect("tx too large for hasher write, logic error");
                let leaf = leaf_hasher
                    .finish()
                    .expect("tx too large for hasher finish, logic error");
                mix_in_length(&leaf, tx.len())
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

impl<E: EthSpec> TestRandom for TransactionsOpaque<E> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut txs = Self::default();
        let num_txs = rng.next_u32() as usize % TEST_RANDOM_MAX_TX_COUNT;
        for _ in 0..num_txs {
            let tx_len = rng.next_u32() as usize % TEST_RANDOM_MAX_TX_BYTES;
            let mut tx = vec![0; tx_len];
            rng.fill_bytes(&mut tx[..]);
            txs.push(&tx).unwrap();
        }
        txs
    }
}

impl<E> Arbitrary<'_> for TransactionsOpaque<E> {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        todo!("impl arbitrary")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{SeedableRng, XorShiftRng},
        MainnetEthSpec, VariableList,
    };

    type E = MainnetEthSpec;
    pub type ReferenceTransaction<N> = VariableList<u8, N>;
    pub type ReferenceTransactions = VariableList<
        ReferenceTransaction<<E as EthSpec>::MaxBytesPerTransaction>,
        <E as EthSpec>::MaxTransactionsPerPayload,
    >;

    const NUM_RANDOM_VECTORS: usize = 256;

    struct TestVector {
        name: String,
        vector: Vec<Vec<u8>>,
    }

    struct TestVectors {
        vectors: Vec<TestVector>,
    }

    impl Default for TestVectors {
        fn default() -> Self {
            let mut vectors = vec![
                TestVector {
                    name: "empty".into(),
                    vector: vec![],
                },
                TestVector {
                    name: "single_item_single_element".into(),
                    vector: vec![vec![0]],
                },
                TestVector {
                    name: "two_items_single_element".into(),
                    vector: vec![vec![0], vec![1]],
                },
                TestVector {
                    name: "three_items_single_element".into(),
                    vector: vec![vec![0], vec![1], vec![1]],
                },
                TestVector {
                    name: "single_item_multiple_element".into(),
                    vector: vec![vec![0, 1, 2]],
                },
                TestVector {
                    name: "two_items_multiple_element".into(),
                    vector: vec![vec![0, 1, 2], vec![3, 4, 5]],
                },
                TestVector {
                    name: "three_items_multiple_element".into(),
                    vector: vec![vec![0, 1, 2], vec![3, 4], vec![5, 6, 7, 8]],
                },
                TestVector {
                    name: "empty_list_at_start".into(),
                    vector: vec![vec![], vec![3, 4], vec![5, 6, 7, 8]],
                },
                TestVector {
                    name: "empty_list_at_middle".into(),
                    vector: vec![vec![0, 1, 2], vec![], vec![5, 6, 7, 8]],
                },
                TestVector {
                    name: "empty_list_at_end".into(),
                    vector: vec![vec![0, 1, 2], vec![3, 4, 5], vec![]],
                },
                TestVector {
                    name: "two_empty_lists".into(),
                    vector: vec![vec![], vec![]],
                },
                TestVector {
                    name: "three_empty_lists".into(),
                    vector: vec![vec![], vec![], vec![]],
                },
            ];

            let mut rng = XorShiftRng::from_seed([42; 16]);
            for i in 0..NUM_RANDOM_VECTORS {
                let vector = TransactionsOpaque::<E>::random_for_test(&mut rng);
                vectors.push(TestVector {
                    name: format!("random_vector_{i}"),
                    vector: vector.iter().map(|slice| slice.to_vec()).collect(),
                })
            }

            Self { vectors }
        }
    }

    impl TestVectors {
        fn iter(
            &self,
        ) -> impl Iterator<
            Item = (
                String,
                TransactionsOpaque<MainnetEthSpec>,
                ReferenceTransactions,
            ),
        > + '_ {
            self.vectors.iter().map(|vector| {
                let name = vector.name.clone();
                let transactions = TransactionsOpaque::from(vector.vector.clone());

                // Build a equivalent object using
                // `VariableList<VariableList<u8>>`. We can use this for
                // reference testing
                let mut reference = ReferenceTransactions::default();
                for tx in &vector.vector {
                    reference.push(tx.clone().into()).unwrap();
                }

                // Perform basic sanity checking against the reference.
                assert_eq!(transactions.len(), reference.len());
                let mut transactions_iter = transactions.iter();
                let mut reference_iter = reference.iter();
                for _ in 0..transactions.len() {
                    assert_eq!(
                        transactions_iter.next().expect("not enough transactions"),
                        reference_iter
                            .next()
                            .expect("not enough reference txs")
                            .as_ref(),
                        "transaction not equal"
                    );
                }
                assert!(transactions_iter.next().is_none(), "excess transactions");
                assert!(reference_iter.next().is_none(), "excess reference txs");
                drop((transactions_iter, reference_iter));

                (name, transactions, reference)
            })
        }
    }

    #[test]
    fn ssz() {
        for (test, transactions, reference) in TestVectors::default().iter() {
            assert_eq!(
                transactions.as_ssz_bytes(),
                reference.as_ssz_bytes(),
                "{test} - serialization"
            );
            assert_eq!(
                transactions,
                TransactionsOpaque::from_ssz_bytes(&reference.as_ssz_bytes()).unwrap(),
                "{test} - deserialization"
            )
        }
    }

    fn err_from_bytes(bytes: &[u8]) -> DecodeError {
        TransactionsOpaque::<E>::from_ssz_bytes(bytes).unwrap_err()
    }

    /// Helper to build invalid SSZ bytes.
    #[derive(Default)]
    struct InvalidSszBuilder {
        ssz: Vec<u8>,
    }

    impl InvalidSszBuilder {
        // Append a 4-byte offset to self.
        pub fn append_offset(mut self, index: usize) -> Self {
            self.ssz.extend_from_slice(&encode_length(index));
            self
        }

        // Append some misc bytes to self.
        pub fn append_value(mut self, value: &[u8]) -> Self {
            self.ssz.extend_from_slice(value);
            self
        }

        pub fn ssz(&self) -> &[u8] {
            &self.ssz
        }
    }

    #[test]
    fn ssz_malicious() {
        // Highest offset that's still a divisor of 4.
        let max_offset = u32::MAX as usize - 3;

        assert_eq!(
            err_from_bytes(&[0]),
            DecodeError::InvalidLengthPrefix {
                len: 1,
                expected: 4
            }
        );
        assert_eq!(
            err_from_bytes(
                InvalidSszBuilder::default()
                    // This offset points to itself. Illegal.
                    .append_offset(0)
                    .ssz()
            ),
            DecodeError::InvalidListFixedBytesLen(0)
        );
        assert_eq!(
            err_from_bytes(
                InvalidSszBuilder::default()
                    .append_offset(8)
                    // This offset points back to the first offset. Illegal.
                    .append_offset(0)
                    .ssz()
            ),
            DecodeError::OffsetIntoFixedPortion(0)
        );
        assert_eq!(
            err_from_bytes(
                InvalidSszBuilder::default()
                    // This offset is far bigger than the SSZ buffer. Illegal.
                    .append_offset(max_offset)
                    .ssz()
            ),
            DecodeError::OffsetOutOfBounds(max_offset)
        );
        assert!(matches!(
            err_from_bytes(
                InvalidSszBuilder::default()
                    .append_offset(8)
                    // This infers a really huge transaction. Illegal.
                    .append_offset(max_offset)
                    .append_value(&[0])
                    .ssz()
            ),
            DecodeError::BytesInvalid(_)
        ));
        assert_eq!(
            err_from_bytes(
                InvalidSszBuilder::default()
                    .append_offset(8)
                    // This points outside of the given bytes. Illegal.
                    .append_offset(9)
                    .ssz()
            ),
            DecodeError::OffsetOutOfBounds(1)
        );
    }

    #[test]
    fn tree_hash() {
        for (test, transactions, reference) in TestVectors::default().iter() {
            assert_eq!(
                transactions.tree_hash_root(),
                reference.tree_hash_root(),
                "{test}"
            )
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct SerdeWrapper {
        #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
        reference: ReferenceTransactions,
    }

    #[test]
    fn json() {
        for (test, transactions, reference) in TestVectors::default().iter() {
            let reference = SerdeWrapper { reference };

            assert_eq!(
                serde_json::to_string(&transactions).unwrap(),
                serde_json::to_string(&reference).unwrap(),
                "{test} - to json"
            );

            assert_eq!(
                transactions,
                serde_json::from_str(&serde_json::to_string(&reference).unwrap()).unwrap(),
                "{test} - deserialize"
            );
        }
    }

    #[test]
    fn yaml() {
        for (test, transactions, reference) in TestVectors::default().iter() {
            let reference = SerdeWrapper { reference };

            assert_eq!(
                serde_yaml::to_string(&transactions).unwrap(),
                serde_yaml::to_string(&reference).unwrap(),
                "{test} - to json"
            );

            assert_eq!(
                transactions,
                serde_yaml::from_str(&serde_yaml::to_string(&reference).unwrap()).unwrap(),
                "{test} - deserialize"
            );
        }
    }
}
