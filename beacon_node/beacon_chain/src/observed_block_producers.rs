//! Provides the `ObservedBlockProducers` struct which allows for rejecting gossip blocks from
//! validators that have already produced a block.

use parking_lot::RwLock;
use ssz_derive::{Decode, Encode};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::marker::PhantomData;
use types::{BeaconBlock, EthSpec, Slot, Unsigned};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The slot of the provided block is prior to finalization and should not have been provided
    /// to this function. This is an internal error.
    FinalizedBlock { slot: Slot, finalized_slot: Slot },
    /// The function to obtain a set index failed, this is an internal error.
    ValidatorIndexTooHigh(u64),
}

/// Maintains a cache of observed `(block.slot, block.proposer)`.
///
/// The cache supports pruning based upon the finalized epoch. It does not automatically prune, you
/// must call `Self::prune` manually.
///
/// The maximum size of the cache is determined by `slots_since_finality *
/// VALIDATOR_REGISTRY_LIMIT`. This is quite a large size, so it's important that upstream
/// functions only use this cache for blocks with a valid signature. Only allowing valid signed
/// blocks reduces the theoretical maximum size of this cache to `slots_since_finality *
/// active_validator_count`, however in reality that is more like `slots_since_finality *
/// known_distinct_shufflings` which is much smaller.
#[derive(Encode, Decode)]
pub struct SszObservedBlockProducers {
    finalized_slot: Slot,
    items_keys: Vec<Slot>,
    items_values: Vec<Vec<u64>>,
}
#[derive(Debug)]
pub struct ObservedBlockProducers<E: EthSpec> {
    finalized_slot: RwLock<Slot>,
    items: RwLock<HashMap<Slot, HashSet<u64>>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ObservedBlockProducers<E> {
    /// Instantiates `Self` with `finalized_slot == 0`.
    fn default() -> Self {
        Self {
            finalized_slot: RwLock::new(Slot::new(0)),
            items: RwLock::new(HashMap::new()),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> ObservedBlockProducers<E> {
    /// Observe that the `block` was produced by `block.proposer_index` at `block.slot`. This will
    /// update `self` so future calls to it indicate that this block is known.
    ///
    /// The supplied `block` **MUST** be signature verified (see struct-level documentation).
    ///
    /// ## Errors
    ///
    /// - `block.proposer_index` is greater than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `block.slot` is equal to or less than the latest pruned `finalized_slot`.
    pub fn observe_proposer(&self, block: &BeaconBlock<E>) -> Result<bool, Error> {
        self.sanitize_block(block)?;

        let did_not_exist = self
            .items
            .write()
            .entry(block.slot)
            .or_insert_with(|| HashSet::with_capacity(E::SlotsPerEpoch::to_usize()))
            .insert(block.proposer_index);

        Ok(!did_not_exist)
    }

    /// Returns `Ok(true)` if the `block` has been observed before, `Ok(false)` if not. Does not
    /// update the cache, so calling this function multiple times will continue to return
    /// `Ok(false)`, until `Self::observe_proposer` is called.
    ///
    /// ## Errors
    ///
    /// - `block.proposer_index` is greater than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `block.slot` is equal to or less than the latest pruned `finalized_slot`.
    pub fn proposer_has_been_observed(&self, block: &BeaconBlock<E>) -> Result<bool, Error> {
        self.sanitize_block(block)?;

        let exists = self
            .items
            .read()
            .get(&block.slot)
            .map_or(false, |set| set.contains(&block.proposer_index));

        Ok(exists)
    }

    /// Returns `Ok(())` if the given `block` is sane.
    fn sanitize_block(&self, block: &BeaconBlock<E>) -> Result<(), Error> {
        if block.proposer_index > E::ValidatorRegistryLimit::to_u64() {
            return Err(Error::ValidatorIndexTooHigh(block.proposer_index));
        }

        let finalized_slot = *self.finalized_slot.read();
        if finalized_slot > 0 && block.slot <= finalized_slot {
            return Err(Error::FinalizedBlock {
                slot: block.slot,
                finalized_slot,
            });
        }

        Ok(())
    }

    /// Removes all observations of blocks equal to or earlier than `finalized_slot`.
    ///
    /// Stores `finalized_slot` in `self`, so that `self` will reject any block that has a slot
    /// equal to or less than `finalized_slot`.
    ///
    /// No-op if `finalized_slot == 0`.
    pub fn prune(&self, finalized_slot: Slot) {
        if finalized_slot == 0 {
            return;
        }

        *self.finalized_slot.write() = finalized_slot;
        self.items
            .write()
            .retain(|slot, _set| *slot > finalized_slot);
    }

    /// Returns a `SszObservedBlockProducers`, which contains all necessary information to restore the state
    /// of `Self` at some later point.
    pub fn to_ssz_container(&self) -> SszObservedBlockProducers {
        let finalized_slot = *self.finalized_slot.read();

        let items_keys: Vec<Slot> = self.items.read().keys().cloned().collect();

        let items_values: Vec<Vec<u64>> = self
            .items
            .read()
            .values()
            .map(|item| Vec::from_iter(item.clone()))
            .collect();

        SszObservedBlockProducers {
            finalized_slot,
            items_keys,
            items_values,
        }
    }

    /// Creates a new `Self` from the given `SszObservedBlockProducers`, restoring `Self` to the same state of
    /// the `Self` that created the `SszObservedBlockProducers`.
    pub fn from_ssz_container(ssz_container: &SszObservedBlockProducers) -> Result<Self, Error> {
        let finalized_slot = RwLock::new(ssz_container.finalized_slot);

        let keys = ssz_container.items_keys.clone();

        let values: Vec<HashSet<u64>> = ssz_container
            .items_values
            .clone()
            .iter()
            .map(|item| HashSet::from_iter(item.clone()))
            .collect();

        let items: RwLock<HashMap<Slot, HashSet<u64>>> =
            RwLock::new(keys.into_iter().zip(values.into_iter()).collect());

        Ok(Self {
            finalized_slot,
            items,
            _phantom: PhantomData,
        })
    }
}

impl<E: EthSpec> PartialEq<ObservedBlockProducers<E>> for ObservedBlockProducers<E> {
    fn eq(&self, other: &ObservedBlockProducers<E>) -> bool {
        (*self.finalized_slot.read() == *other.finalized_slot.read())
            && ((*self.items.read()).keys().len() == (*other.items.read()).keys().len())
            && ((*self.items.read()).values().len() == (*other.items.read()).values().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};
    use types::MainnetEthSpec;

    type E = MainnetEthSpec;

    fn get_block(slot: u64, proposer: u64) -> BeaconBlock<E> {
        let mut block = BeaconBlock::empty(&E::default_spec());
        block.slot = slot.into();
        block.proposer_index = proposer;
        block
    }

    #[test]
    fn store_round_trip() {
        let store = ObservedBlockProducers::default();
        let block = &get_block(0, 0);
        store.observe_proposer(block).expect("block to be accepted");

        let bytes = store.to_ssz_container().as_ssz_bytes();

        assert_eq!(
            Ok(store),
            ObservedBlockProducers::from_ssz_container(
                &SszObservedBlockProducers::from_ssz_bytes(&bytes).expect("should decode")
            ),
            "should encode/decode to/from ssz container"
        )
    }

    #[test]
    fn pruning() {
        let cache = ObservedBlockProducers::default();

        assert_eq!(*cache.finalized_slot.read(), 0, "finalized slot is zero");
        assert_eq!(cache.items.read().len(), 0, "no slots should be present");

        // Slot 0, proposer 0
        let block_a = &get_block(0, 0);

        assert_eq!(
            cache.observe_proposer(block_a),
            Ok(false),
            "can observe proposer, indicates proposer unobserved"
        );

        /*
         * Preconditions.
         */

        assert_eq!(*cache.finalized_slot.read(), 0, "finalized slot is zero");
        assert_eq!(
            cache.items.read().len(),
            1,
            "only one slot should be present"
        );
        assert_eq!(
            cache
                .items
                .read()
                .get(&Slot::new(0))
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present"
        );

        /*
         * Check that a prune at the genesis slot does nothing.
         */

        cache.prune(Slot::new(0));

        assert_eq!(*cache.finalized_slot.read(), 0, "finalized slot is zero");
        assert_eq!(
            cache.items.read().len(),
            1,
            "only one slot should be present"
        );
        assert_eq!(
            cache
                .items
                .read()
                .get(&Slot::new(0))
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present"
        );

        /*
         * Check that a prune empties the cache
         */

        cache.prune(E::slots_per_epoch().into());
        assert_eq!(
            *cache.finalized_slot.read(),
            Slot::from(E::slots_per_epoch()),
            "finalized slot is updated"
        );
        assert_eq!(cache.items.read().len(), 0, "no items left");

        /*
         * Check that we can't insert a finalized block
         */

        // First slot of finalized epoch, proposer 0
        let block_b = &get_block(E::slots_per_epoch(), 0);

        assert_eq!(
            cache.observe_proposer(block_b),
            Err(Error::FinalizedBlock {
                slot: E::slots_per_epoch().into(),
                finalized_slot: E::slots_per_epoch().into(),
            }),
            "cant insert finalized block"
        );

        assert_eq!(cache.items.read().len(), 0, "block was not added");

        /*
         * Check that we _can_ insert a non-finalized block
         */

        let three_epochs = E::slots_per_epoch() * 3;

        // First slot of finalized epoch, proposer 0
        let block_b = &get_block(three_epochs, 0);

        assert_eq!(
            cache.observe_proposer(block_b),
            Ok(false),
            "can insert non-finalized block"
        );

        assert_eq!(
            cache.items.read().len(),
            1,
            "only one slot should be present"
        );
        assert_eq!(
            cache
                .items
                .read()
                .get(&Slot::new(three_epochs))
                .expect("the three epochs slot should be present")
                .len(),
            1,
            "only one proposer should be present"
        );

        /*
         * Check that a prune doesnt wipe later blocks
         */

        let two_epochs = E::slots_per_epoch() * 2;
        cache.prune(two_epochs.into());

        assert_eq!(
            *cache.finalized_slot.read(),
            Slot::from(two_epochs),
            "finalized slot is updated"
        );

        assert_eq!(
            cache.items.read().len(),
            1,
            "only one slot should be present"
        );
        assert_eq!(
            cache
                .items
                .read()
                .get(&Slot::new(three_epochs))
                .expect("the three epochs slot should be present")
                .len(),
            1,
            "only one proposer should be present"
        );
    }

    #[test]
    fn simple_observations() {
        let cache = ObservedBlockProducers::default();

        // Slot 0, proposer 0
        let block_a = &get_block(0, 0);

        assert_eq!(
            cache.proposer_has_been_observed(block_a),
            Ok(false),
            "no observation in empty cache"
        );
        assert_eq!(
            cache.observe_proposer(block_a),
            Ok(false),
            "can observe proposer, indicates proposer unobserved"
        );
        assert_eq!(
            cache.proposer_has_been_observed(block_a),
            Ok(true),
            "observed block is indicated as true"
        );
        assert_eq!(
            cache.observe_proposer(block_a),
            Ok(true),
            "observing again indicates true"
        );

        assert_eq!(*cache.finalized_slot.read(), 0, "finalized slot is zero");
        assert_eq!(
            cache.items.read().len(),
            1,
            "only one slot should be present"
        );
        assert_eq!(
            cache
                .items
                .read()
                .get(&Slot::new(0))
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present"
        );

        // Slot 1, proposer 0
        let block_b = &get_block(1, 0);

        assert_eq!(
            cache.proposer_has_been_observed(block_b),
            Ok(false),
            "no observation for new slot"
        );
        assert_eq!(
            cache.observe_proposer(block_b),
            Ok(false),
            "can observe proposer for new slot, indicates proposer unobserved"
        );
        assert_eq!(
            cache.proposer_has_been_observed(block_b),
            Ok(true),
            "observed block in slot 1 is indicated as true"
        );
        assert_eq!(
            cache.observe_proposer(block_b),
            Ok(true),
            "observing slot 1 again indicates true"
        );

        assert_eq!(*cache.finalized_slot.read(), 0, "finalized slot is zero");
        assert_eq!(cache.items.read().len(), 2, "two slots should be present");
        assert_eq!(
            cache
                .items
                .read()
                .get(&Slot::new(0))
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present in slot 0"
        );
        assert_eq!(
            cache
                .items
                .read()
                .get(&Slot::new(1))
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present in slot 1"
        );

        // Slot 0, proposer 1
        let block_c = &get_block(0, 1);

        assert_eq!(
            cache.proposer_has_been_observed(block_c),
            Ok(false),
            "no observation for new proposer"
        );
        assert_eq!(
            cache.observe_proposer(block_c),
            Ok(false),
            "can observe new proposer, indicates proposer unobserved"
        );
        assert_eq!(
            cache.proposer_has_been_observed(block_c),
            Ok(true),
            "observed new proposer block is indicated as true"
        );
        assert_eq!(
            cache.observe_proposer(block_c),
            Ok(true),
            "observing new proposer again indicates true"
        );

        assert_eq!(*cache.finalized_slot.read(), 0, "finalized slot is zero");
        assert_eq!(cache.items.read().len(), 2, "two slots should be present");
        assert_eq!(
            cache
                .items
                .read()
                .get(&Slot::new(0))
                .expect("slot zero should be present")
                .len(),
            2,
            "two proposers should be present in slot 0"
        );
        assert_eq!(
            cache
                .items
                .read()
                .get(&Slot::new(1))
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present in slot 1"
        );
    }
}
