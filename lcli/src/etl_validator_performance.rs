use clap::ArgMatches;
use environment::null_logger;
use state_processing::{per_block_processing, per_slot_processing, BlockSignatureStrategy};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use store::{iter::BlockRootsIterator, HotColdDB, StoreConfig};
use types::{BeaconState, Epoch, EthSpec, Hash256, SignedBeaconBlock};

#[derive(Default, Clone, Debug)]
struct ValidatorPerformance {
    pub attestation_hits: usize,
    pub attestation_misses: usize,
    pub head_attestation_hits: usize,
    pub head_attestation_misses: usize,
    pub target_attestation_hits: usize,
    pub target_attestation_misses: usize,
    pub head_attester_when_first_slot_empty: usize,
    pub delays: HashMap<u64, u64>,
}

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let hot_path: PathBuf = clap_utils::parse_required(matches, "chain-db")?;
    let cold_path: PathBuf = clap_utils::parse_required(matches, "freezer-db")?;
    let output_path: PathBuf = clap_utils::parse_required(matches, "output")?;
    let epochs: Epoch = clap_utils::parse_required(matches, "epochs")?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(output_path)
        .expect("unable to open file");

    let mut config = StoreConfig::default();
    config.slots_per_restore_point = 2048;

    let spec = T::default_spec();

    let store: Arc<HotColdDB<T, _, _>> = Arc::new(
        HotColdDB::open(&hot_path, &cold_path, config, spec.clone(), null_logger()?)
            .map_err(|e| format!("Unable to open database: {:?}", e))?,
    );

    let split_slot = store.get_split_slot();
    let split_state = store
        .load_cold_state_by_slot(split_slot)
        .expect("error reading db");

    let mut perfs = vec![ValidatorPerformance::default(); split_state.validators.len()];

    let latest_slot = split_slot;
    let latest_epoch = latest_slot.epoch(T::slots_per_epoch());
    let earliest_epoch = latest_epoch - epochs;

    eprintln!(
        "Latest slot in freezer DB is {} (epoch {})",
        latest_slot, latest_epoch
    );

    eprintln!("Collecting {} epochs of blocks", epochs);

    let mut block_roots: Vec<Hash256> = BlockRootsIterator::owned(store.clone(), split_state)
        .map(|result| result.expect("should get info for slot"))
        .take_while(|(_, slot)| slot.epoch(T::slots_per_epoch()) >= earliest_epoch)
        .map(|(root, _)| root)
        .collect();

    block_roots.dedup();
    block_roots.reverse();

    let blocks = block_roots
        .iter()
        .map(|root| {
            store
                .get_item::<SignedBeaconBlock<T>>(&root)
                .expect("failed to get block from store")
                .expect("block is not in store")
        })
        .collect::<Vec<_>>();

    eprintln!("Starting replay of {} blocks", blocks.len());

    let mut state = store
        .load_cold_state_by_slot(blocks.first().expect("no blocks to apply").message.slot - 1)
        .expect("error reading pre state");

    let state_root_from_prev_block = |i: usize, state: &BeaconState<T>| {
        if i > 0 {
            let prev_block = &blocks[i - 1].message;
            if prev_block.slot == state.slot {
                Some(prev_block.state_root)
            } else {
                None
            }
        } else {
            None
        }
    };

    for (i, block) in blocks.iter().enumerate() {
        while state.slot < block.message.slot {
            let state_root = state_root_from_prev_block(i, &state);

            if let Some(summary) =
                per_slot_processing(&mut state, state_root, &spec).expect("per slot processing")
            {
                eprintln!(
                    "Processing {} performance summaries for epoch {}",
                    summary.statuses.len(),
                    state.previous_epoch()
                );

                let prev_epoch_target_slot =
                    state.previous_epoch().start_slot(T::slots_per_epoch());
                let penultimate_epoch_end_slot = prev_epoch_target_slot;
                let first_slot_empty = state.get_block_root(prev_epoch_target_slot).unwrap()
                    == state.get_block_root(penultimate_epoch_end_slot).unwrap();

                for (i, s) in summary.statuses.into_iter().enumerate() {
                    let perf = perfs.get_mut(i).expect("no perf for validator");
                    if s.is_active_in_previous_epoch {
                        if s.is_previous_epoch_attester {
                            perf.attestation_hits += 1;
                        } else {
                            perf.attestation_misses += 1;
                        }

                        if s.is_previous_epoch_head_attester {
                            perf.head_attestation_hits += 1;
                        } else {
                            perf.head_attestation_misses += 1;
                        }

                        if s.is_previous_epoch_target_attester {
                            perf.target_attestation_hits += 1;
                        } else {
                            perf.target_attestation_misses += 1;
                        }

                        if let Some(inclusion_info) = s.inclusion_info {
                            *perf.delays.entry(inclusion_info.delay).or_default() += 1
                        }

                        if first_slot_empty && s.is_previous_epoch_head_attester {
                            perf.head_attester_when_first_slot_empty += 1
                        }
                    }
                }
            }
        }

        per_block_processing(
            &mut state,
            &block,
            None,
            BlockSignatureStrategy::NoVerification,
            &spec,
        )
        .expect("per block processing");
    }

    eprintln!("Writing {} validators to CSV file", perfs.len());

    write!(
        file,
        "validator_index,\
        attestation_hits,\
        attestation_misses,\
        head_attestation_hits,\
        head_attestation_misses,\
        target_attestation_hits,\
        target_attestation_misses,\
        delay_avg,\
        head_attester_when_first_slot_empty\n"
    )
    .unwrap();

    for (i, perf) in perfs.into_iter().enumerate() {
        let mut count = 0;
        let mut sum = 0;
        for (delay, n) in perf.delays.iter() {
            count += n;
            sum += delay * n;
        }

        write!(
            file,
            "{},{},{},{},{},{},{},{},{}\n",
            i,
            perf.attestation_hits,
            perf.attestation_misses,
            perf.head_attestation_hits,
            perf.head_attestation_misses,
            perf.target_attestation_hits,
            perf.target_attestation_misses,
            if count == 0 {
                0_f64
            } else {
                sum as f64 / count as f64
            },
            perf.head_attester_when_first_slot_empty
        )
        .unwrap();
    }

    Ok(())
}
