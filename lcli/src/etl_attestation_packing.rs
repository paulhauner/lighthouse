use clap::ArgMatches;
use environment::null_logger;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use store::{iter::BlockRootsIterator, HotColdDB, StoreConfig};
use types::{Epoch, EthSpec, Graffiti, Hash256, SignedBeaconBlock, Slot};

type CommitteePosition = usize;
type Committee = u64;
type UniqueVote = (Slot, Committee, CommitteePosition);

struct InclusionInfo {
    inclusion_distance: u64,
    block_proposer: u64,
    block_graffiti: Graffiti,
}

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let hot_path: PathBuf = clap_utils::parse_required(matches, "chain-db")?;
    let cold_path: PathBuf = clap_utils::parse_required(matches, "freezer-db")?;
    let output_path: PathBuf = clap_utils::parse_required(matches, "output")?;
    let start_epoch: Epoch = clap_utils::parse_required(matches, "start-epoch")?;
    let end_epoch: Epoch = clap_utils::parse_required(matches, "end-epoch")?;
    let filter_unique_inclusions_above: Option<usize> =
        clap_utils::parse_optional(matches, "filter-unique-inclusions-above")?;

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

    let latest_slot = split_slot;
    let latest_known_epoch = latest_slot.epoch(T::slots_per_epoch());

    if latest_known_epoch < end_epoch {
        return Err(format!(
            "End epoch is {} but latest finalized epoch is {}",
            end_epoch, latest_known_epoch
        ));
    }

    eprintln!(
        "Latest slot in freezer DB is {} (epoch {})",
        latest_slot, end_epoch
    );

    eprintln!(
        "Collecting {} epochs of blocks",
        (end_epoch - start_epoch) + 1
    );

    let mut block_roots: Vec<Hash256> = BlockRootsIterator::owned(store.clone(), split_state)
        .map(|result| result.expect("should get info for slot"))
        .skip_while(|(_, slot)| slot.epoch(T::slots_per_epoch()) > end_epoch)
        .take_while(|(_, slot)| slot.epoch(T::slots_per_epoch()) >= start_epoch)
        .map(|(root, _)| root)
        .collect();

    block_roots.dedup();
    block_roots.reverse();

    if block_roots.is_empty() {
        return Err("Query did not return any blocks".to_string());
    }

    eprintln!("Starting inspection of {} blocks", block_roots.len());

    let mut unique_votes: HashMap<UniqueVote, InclusionInfo> = <_>::default();
    let mut proposer_graffiti: HashMap<(u64, Graffiti), usize> = <_>::default();

    let mut current_epoch = None;
    for &block_root in &block_roots {
        let signed_block = store
            .get_item::<SignedBeaconBlock<T>>(&block_root)
            .expect("failed to get block from store")
            .expect("block is not in store");
        let block = &signed_block.message;

        let block_epoch = block.slot.epoch(T::slots_per_epoch());
        if let Some(current_epoch) = current_epoch {
            // If the block is in a new epoch, collapse the votes from old epochs into the
            // `proposer_graffiti` map. This reduces the amount of memory used at runtime.
            //
            // We know we can collapse the old votes into the `proposer_graffiti` map since they're
            // so old that they can't be included in any new blocks.
            if block_epoch > current_epoch {
                unique_votes.retain(|(slot, _, _), info| {
                    if slot.epoch(T::slots_per_epoch()) + 2 <= block_epoch {
                        *proposer_graffiti
                            .entry((info.block_proposer, info.block_graffiti))
                            .or_insert(0) += 1;
                        false
                    } else {
                        true
                    }
                })
            }
        }
        current_epoch = Some(block_epoch);

        for attestation in &block.body.attestations {
            let data = &attestation.data;
            for (committee_position, voted) in attestation.aggregation_bits.iter().enumerate() {
                if voted {
                    let unique_vote = (data.slot, data.index, committee_position);
                    let inclusion_distance = block
                        .slot
                        .as_u64()
                        .checked_sub(data.slot.as_u64())
                        .expect("block slot not less than attestation slot");

                    if unique_votes.get(&unique_vote).map_or(true, |existing| {
                        existing.inclusion_distance > inclusion_distance
                    }) {
                        unique_votes.insert(
                            unique_vote,
                            InclusionInfo {
                                inclusion_distance,
                                block_proposer: block.proposer_index,
                                block_graffiti: block.body.graffiti,
                            },
                        );
                    }
                }
            }
        }
    }

    for (_, info) in unique_votes.iter() {
        *proposer_graffiti
            .entry((info.block_proposer, info.block_graffiti))
            .or_insert(0) += 1;
    }

    let num_blocks = block_roots.len();
    let num_votes: usize = proposer_graffiti.len();

    eprintln!(
        "Writing data from {} blocks and {} unique proposer/graffiti to CSV file",
        num_blocks, num_votes
    );

    write!(
        file,
        "proposer_index,\
        unique_vote_inclusions,\
        graffiti\n"
    )
    .unwrap();

    for ((proposer_index, graffiti), unique_vote_inclusions) in proposer_graffiti {
        if filter_unique_inclusions_above.map_or(false, |max| unique_vote_inclusions > max) {
            // No need to write this to file.
            continue;
        }

        write!(
            file,
            "{:?},{},{}\n",
            proposer_index,
            unique_vote_inclusions,
            graffiti.as_utf8_or_hex()
        )
        .unwrap();
    }

    Ok(())
}
