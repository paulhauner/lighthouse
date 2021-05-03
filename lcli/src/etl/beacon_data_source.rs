use environment::null_logger;
use std::path::Path;
use std::sync::Arc;
use store::{iter::BlockRootsIterator, HotColdDB, LevelDB, StoreConfig};
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot};

pub use store::config::DEFAULT_SLOTS_PER_RESTORE_POINT;

pub struct BeaconDataSource<E: EthSpec> {
    store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>,
    split_slot: Slot,
}

impl<E: EthSpec> BeaconDataSource<E> {
    pub fn lighthouse_database<P: AsRef<Path>>(
        hot_path: P,
        cold_path: P,
        slots_per_restore_point: u64,
        spec: ChainSpec,
    ) -> Result<Self, String> {
        let mut config = StoreConfig::default();
        config.slots_per_restore_point = slots_per_restore_point;

        let null_migrator = |_, _, _| Ok(());

        let store: Arc<HotColdDB<E, _, _>> = HotColdDB::open(
            hot_path.as_ref(),
            cold_path.as_ref(),
            null_migrator,
            config,
            spec,
            null_logger()?,
        )
        .map_err(|e| format!("Unable to open database: {:?}", e))?;

        let split_slot = store.get_split_slot();

        Ok(Self { store, split_slot })
    }

    pub fn get_latest_state(&self) -> Result<BeaconState<E>, String> {
        self.store
            .load_cold_state_by_slot(self.split_slot)
            .map_err(|e| format!("Unable to read split slot state: {:?}", e))
    }

    pub fn block_roots_in_range(
        &self,
        start_epoch: Epoch,
        end_epoch: Epoch,
    ) -> Result<Vec<Hash256>, String> {
        let split_state = self.get_latest_state()?;

        let latest_known_epoch = self.split_slot.epoch(E::slots_per_epoch());

        if latest_known_epoch < end_epoch {
            return Err(format!(
                "End epoch is {} but latest finalized epoch is {}",
                end_epoch, latest_known_epoch
            ));
        }

        let mut block_roots: Vec<Hash256> =
            BlockRootsIterator::owned(self.store.clone(), split_state)
                .map(|result| result.expect("should get info for slot"))
                .skip_while(|(_, slot)| slot.epoch(E::slots_per_epoch()) > end_epoch)
                .take_while(|(_, slot)| slot.epoch(E::slots_per_epoch()) >= start_epoch)
                .map(|(root, _)| root)
                .collect();

        block_roots.dedup();
        block_roots.reverse();

        Ok(block_roots)
    }

    pub fn get_block(&self, root: &Hash256) -> Result<Option<SignedBeaconBlock<E>>, String> {
        self.store
            .get_item(root)
            .map_err(|e| format!("Failed to get block from store: {:?}", e))
    }

    pub fn get_state_by_slot(&self, slot: Slot) -> Result<BeaconState<E>, String> {
        self.store
            .load_cold_state_by_slot(slot)
            .map_err(|e| format!("Failed to get state from store: {:?}", e))
    }
}
