use crate::etl::beacon_data_source::{BeaconDataSource, DEFAULT_SLOTS_PER_RESTORE_POINT};
use clap::ArgMatches;
use state_processing::{per_block_processing, per_slot_processing, BlockSignatureStrategy};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use types::{BeaconState, Epoch, EthSpec};

#[derive(Default, Clone, Debug)]
struct ValidatorPerformance {
    /// The validator had an attestation included on-chain.
    pub attestation_hits: usize,
    /// Inverse of `attestation_hits`.
    pub attestation_misses: usize,
    /// The validator had an attestation included on-chain which matched the "head" vote.
    pub head_attestation_hits: usize,
    /// Inverse of `head_attestation_hits`.
    pub head_attestation_misses: usize,
    /// The validator had an attestation included on-chain which matched the "target" vote.
    pub target_attestation_hits: usize,
    /// Inverse of `target_attestation_hits`.
    pub target_attestation_misses: usize,
    /// The validator achieved a `head_attestation_hits` point when the first slot of the epoch was
    /// a skip-slot.
    ///
    /// This is generally *not useful*, it was used to try and debug late blocks on mainnet.
    pub first_slot_head_attester_when_first_slot_empty: usize,
    /// The validator achieved a `head_attestation_hits` point when the first slot of the epoch was
    /// *not* a skip-slot.
    ///
    /// This is generally *not useful*, it was used to try and debug late blocks on mainnet.
    pub first_slot_head_attester_when_first_slot_not_empty: usize,
    /// Set to `Some(true)` if the validator was active (i.e., eligible to attest) in all observed
    /// states.
    pub always_active: Option<bool>,
    /// A map of `inclusion_distance -> count`, indicating how many times the validator achieved
    /// each inclusion distance.
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

    let latest_state = beacon_data_source.get_latest_state()?;
    let mut perfs = vec![ValidatorPerformance::default(); latest_state.validators.len()];

    eprintln!(
        "Collecting {} epochs of blocks",
        (end_epoch - start_epoch) + 1
    );

    let block_roots = beacon_data_source.block_roots_in_range(start_epoch, end_epoch)?;

    let blocks = block_roots
        .iter()
        .map(|root| {
            beacon_data_source
                .get_block(root)?
                .ok_or_else(|| format!("Unable to find block {}", root))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if blocks.is_empty() {
        return Err("Query did not return any blocks".to_string());
    }

    eprintln!("Starting replay of {} blocks", blocks.len());

    let mut state = beacon_data_source
        .get_state_by_slot(blocks.first().expect("no blocks to apply").message.slot - 1)?;

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
                let penultimate_epoch_end_slot = prev_epoch_target_slot.saturating_sub(1_u64);
                let first_slot_empty = state
                    .get_block_root(prev_epoch_target_slot)
                    .map_err(|e| format!("Unable to get prev epoch block root: {:?}", e))?
                    == state
                        .get_block_root(penultimate_epoch_end_slot)
                        .map_err(|e| format!("Unable to get penultimate block root: {:?}", e))?;

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
                        if perf.always_active.is_none() {
                            perf.always_active = Some(true);
                        }

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
                    } else {
                        perf.always_active = Some(false);
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
        always_active,\
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
            "{},{},{},{},{},{},{},{},{},{},{}\n",
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
            perf.always_active.unwrap_or(false),
            perf.first_slot_head_attester_when_first_slot_empty,
            perf.first_slot_head_attester_when_first_slot_not_empty
        )
        .unwrap();
    }

    Ok(())
}
