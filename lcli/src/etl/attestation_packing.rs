use crate::etl::beacon_data_source::{BeaconDataSource, DEFAULT_SLOTS_PER_RESTORE_POINT};
use clap::ArgMatches;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use types::{Epoch, EthSpec, Graffiti, Slot};

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

    let spec = T::default_spec();

    let beacon_data_source: BeaconDataSource<T> = BeaconDataSource::lighthouse_database(
        hot_path,
        cold_path,
        DEFAULT_SLOTS_PER_RESTORE_POINT,
        spec.clone(),
    )?;

    eprintln!(
        "Collecting {} epochs of blocks",
        (end_epoch - start_epoch) + 1
    );

    let block_roots = beacon_data_source.block_roots_in_range(start_epoch, end_epoch)?;

    if block_roots.is_empty() {
        return Err("Query did not return any blocks".to_string());
    }

    eprintln!("Starting inspection of {} blocks", block_roots.len());

    let mut unique_votes: HashMap<UniqueVote, InclusionInfo> = <_>::default();
    let mut proposer_graffiti: HashMap<(u64, Graffiti), usize> = <_>::default();

    let mut current_epoch = None;
    for &block_root in &block_roots {
        let signed_block = beacon_data_source
            .get_block(&block_root)?
            .ok_or_else(|| format!("Unable to find block {}", block_root))?;
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
            graffiti.as_utf8_lossy()
        )
        .unwrap();
    }

    Ok(())
}
