use crate::etl::beacon_data_source::{BeaconDataSource, DEFAULT_SLOTS_PER_RESTORE_POINT};
use clap::ArgMatches;
use state_processing::{per_block_processing, per_slot_processing, BlockSignatureStrategy};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use types::{BeaconState, Epoch, EthSpec, SignedBeaconBlock};

#[derive(Default, Clone, Debug)]
struct ValidatorPerformance {
    pub attestation_hits: usize,
    pub attestation_misses: usize,
    pub head_attestation_hits: usize,
    pub head_attestation_misses: usize,
    pub target_attestation_hits: usize,
    pub target_attestation_misses: usize,
    pub first_slot_head_attester_when_first_slot_empty: usize,
    pub first_slot_head_attester_when_first_slot_not_empty: usize,
    pub delays: HashMap<u64, u64>,
}

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let hot_path: PathBuf = clap_utils::parse_required(matches, "chain-db")?;
    let cold_path: PathBuf = clap_utils::parse_required(matches, "freezer-db")?;
    let output_path: PathBuf = clap_utils::parse_required(matches, "output")?;
    let start_epoch: Epoch = clap_utils::parse_required(matches, "start-epoch")?;
    let end_epoch: Epoch = clap_utils::parse_required(matches, "end-epoch")?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(output_path)
        .expect("unable to open file");

    let spec = T::default_spec();

    let beacon_data_source: BeaconDataSource<T> = BeaconDataSource::lighthouse_database(
        hot_path,
        cold_path,
        DEFAULT_SLOTS_PER_RESTORE_POINT,
        spec.clone(),
    )?;
    let store = beacon_data_source.store.clone();

    let split_state = beacon_data_source.split_slot_state()?;
    let mut perfs = vec![ValidatorPerformance::default(); split_state.validators.len()];

    eprintln!(
        "Collecting {} epochs of blocks",
        (end_epoch - start_epoch) + 1
    );

    let block_roots = beacon_data_source.block_roots_in_range(start_epoch, end_epoch)?;

    let blocks = block_roots
        .iter()
        .map(|root| {
            store
                .get_item::<SignedBeaconBlock<T>>(&root)
                .expect("failed to get block from store")
                .expect("block is not in store")
        })
        .collect::<Vec<_>>();

    if blocks.is_empty() {
        return Err("Query did not return any blocks".to_string());
    }

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
                let penultimate_epoch_end_slot = prev_epoch_target_slot - 1;
                let first_slot_empty = state.get_block_root(prev_epoch_target_slot).unwrap()
                    == state.get_block_root(penultimate_epoch_end_slot).unwrap();

                let first_slot_attesters = {
                    let committee_count = state
                        .get_committee_count_at_slot(prev_epoch_target_slot)
                        .unwrap();
                    let mut indices = HashSet::new();
                    for committee_index in 0..committee_count {
                        let committee = state
                            .get_beacon_committee(prev_epoch_target_slot, committee_index)
                            .unwrap();
                        for validator_index in committee.committee {
                            indices.insert(validator_index);
                        }
                    }
                    indices
                };

                for (i, s) in summary.statuses.into_iter().enumerate() {
                    let perf = perfs.get_mut(i).expect("no perf for validator");
                    if s.is_active_in_previous_epoch {
                        if s.is_previous_epoch_attester {
                            perf.attestation_hits += 1;

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

                            if first_slot_attesters.contains(&i) {
                                if first_slot_empty {
                                    perf.first_slot_head_attester_when_first_slot_empty += 1
                                } else {
                                    perf.first_slot_head_attester_when_first_slot_not_empty += 1
                                }
                            }

                            if let Some(inclusion_info) = s.inclusion_info {
                                *perf.delays.entry(inclusion_info.delay).or_default() += 1
                            }
                        } else {
                            perf.attestation_misses += 1;
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
        first_slot_head_attester_when_first_slot_empty,\
        first_slot_head_attester_when_first_slot_not_empty\n"
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
            "{},{},{},{},{},{},{},{},{},{}\n",
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
            perf.first_slot_head_attester_when_first_slot_empty,
            perf.first_slot_head_attester_when_first_slot_not_empty
        )
        .unwrap();
    }

    Ok(())
}
