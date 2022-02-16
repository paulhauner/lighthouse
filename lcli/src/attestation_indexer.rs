use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use eth2::types::GenericResponse;
use state_processing::per_block_processing::{
    verify_attestation_for_block_inclusion, VerifySignatures,
};
use std::fs::File;
use std::path::PathBuf;
use types::*;

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let block_json_path: PathBuf = parse_required(matches, "block")?;
    let state_json_path: PathBuf = parse_required(matches, "state")?;

    let mut block_json_file =
        File::open(&block_json_path).map_err(|_| "Unable to open file".to_string())?;
    let mut state_json_file =
        File::open(&state_json_path).map_err(|_| "Unable to open file".to_string())?;

    let block_response: GenericResponse<SignedBeaconBlock<T>> =
        serde_json::from_reader(&mut block_json_file)
            .map_err(|e| format!("Unable to parse block: {:?}", e))?;
    let state_response: GenericResponse<BeaconState<T>> =
        serde_json::from_reader(&mut state_json_file)
            .map_err(|e| format!("Unable to parse statelock: {:?}", e))?;

    let block = block_response.data;
    let mut state = state_response.data;

    let spec = T::default_spec();
    state
        .build_all_caches(&spec)
        .map_err(|e| format!("Failed to build caches: {:?}", e))?;

    let indexed_attestations = block
        .message()
        .body()
        .attestations()
        .iter()
        .map(|attestation| {
            verify_attestation_for_block_inclusion(
                &state,
                attestation,
                VerifySignatures::False,
                &spec,
            )
        })
        .collect::<Result<Vec<IndexedAttestation<T>>, _>>()
        .map_err(|e| format!("Failed to index attestation: {:?}", e))?;

    let attestation_index: Option<usize> = parse_optional(matches, "attestation-index")?;

    if let Some(attestation_index) = attestation_index {
        if attestation_index >= indexed_attestations.len() {
            return Err(format!(
                "Attestation index {} is OOB of attestations length of {}",
                attestation_index,
                indexed_attestations.len()
            ));
        }
    }

    for (i, attestation) in indexed_attestations.into_iter().enumerate() {
        if attestation_index.map_or(true, |requested| requested == i) {
            let json = serde_json::to_string(&attestation)
                .map_err(|e| format!("Failed to serialize attn: {:?}", e))?;
            println!("index: {}", i);
            println!("{}", json);
        }
    }

    Ok(())
}
