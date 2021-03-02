use clap::ArgMatches;
use environment::null_logger;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use store::{iter::BlockRootsIterator, HotColdDB, StoreConfig};
use types::{Epoch, EthSpec, Graffiti, Hash256, SignedBeaconBlock, Slot};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let hot_path: PathBuf = clap_utils::parse_required(matches, "chain-db")?;
    let cold_path: PathBuf = clap_utils::parse_required(matches, "freezer-db")?;
    let output_path: PathBuf = clap_utils::parse_required(matches, "output")?;
    let start_epoch: Epoch = clap_utils::parse_required(matches, "start-epoch")?;
    let end_epoch: Epoch = clap_utils::parse_required(matches, "end-epoch")?;
    let filter_unique_votes_above: Option<usize> =
        clap_utils::parse_optional(matches, "filter-unique-votes-above")?;

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

    // We declare that a unique vote is the following tuple:
    //
    // `(attestation.data.slot, committee_index, aggregation_bits_index)`
    let mut unique_votes: HashMap<Hash256, HashSet<(Slot, u64, usize)>> = HashMap::new();

    struct BlockInfo {
        proposer: u64,
        graffiti: Graffiti,
    }

    let mut proposers: HashMap<Hash256, BlockInfo> = HashMap::new();

    for block_root in block_roots {
        let block = store
            .get_item::<SignedBeaconBlock<T>>(&block_root)
            .expect("failed to get block from store")
            .expect("block is not in store");

        proposers.insert(
            block_root,
            BlockInfo {
                proposer: block.message.proposer_index,
                graffiti: block.message.body.graffiti,
            },
        );

        for attestation in &block.message.body.attestations {
            let data = &attestation.data;
            for (committee_index, voted) in attestation.aggregation_bits.iter().enumerate() {
                if voted {
                    unique_votes
                        .entry(data.beacon_block_root)
                        .or_default()
                        .insert((data.slot, data.index, committee_index));
                }
            }
        }
    }

    let num_blocks = proposers.len();
    let num_votes: usize = unique_votes.iter().map(|(_, set)| set.len()).sum();

    eprintln!(
        "Writing data from {} blocks and {} unique votes to CSV file",
        num_blocks, num_votes
    );

    write!(
        file,
        "block_root,\
        unique_votes,\
        proposer_index,\
        graffiti\n"
    )
    .unwrap();

    for (block_root, votes) in unique_votes {
        let unique_votes = votes.len();

        if filter_unique_votes_above.map_or(false, |max| unique_votes > max) {
            // No need to write this to file.
            continue;
        }

        // If we don't know the proposer/graffiti then it means the voted-for block is not in the
        // chain.
        let (proposer_index, graffiti) = proposers
            .get(&block_root)
            .map(|info| (info.proposer.to_string(), info.graffiti.as_utf8_or_hex()))
            .unwrap_or_else(|| ("".to_string(), "".to_string()));

        write!(
            file,
            "{:?},{},{},{}\n",
            block_root,
            votes.len(),
            proposer_index,
            graffiti
        )
        .unwrap();
    }

    Ok(())
}
