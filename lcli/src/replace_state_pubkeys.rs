use account_utils::{eth2_keystore::keypair_from_secret, mnemonic_from_phrase};
use clap::ArgMatches;
use eth2_network_config::Eth2NetworkConfig;
use eth2_wallet::bip39::Seed;
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType};
use ssz::Encode;
use ssz_types::VariableList;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use tree_hash::TreeHash;
use types::{BeaconState, EthSpec, Unsigned};

pub fn run<T: EthSpec>(testnet_dir: PathBuf, matches: &ArgMatches) -> Result<(), String> {
    let path = matches
        .value_of("ssz-state")
        .ok_or("ssz-state not specified")?
        .parse::<PathBuf>()
        .map_err(|e| format!("Unable to parse ssz-state: {}", e))?;

    let mnemonic_phrase = matches
        .value_of("mnemonic")
        .ok_or("mnemonic not specified")?;

    let truncate_len: Option<usize> = clap_utils::parse_optional(matches, "truncate")?;

    let eth2_network_config = Eth2NetworkConfig::load(testnet_dir)?;
    let spec = &eth2_network_config.chain_spec::<T>()?;

    let mut state: BeaconState<T> = {
        let mut file = File::open(&path).map_err(|e| format!("Unable to open file: {}", e))?;

        let mut ssz = vec![];

        file.read_to_end(&mut ssz)
            .map_err(|e| format!("Unable to read file: {}", e))?;

        BeaconState::from_ssz_bytes(&ssz, spec)
            .map_err(|e| format!("Unable to decode SSZ: {:?}", e))?
    };

    state.as_base().expect("does not yet support altair states");

    if let Some(len) = truncate_len {
        *state.validators_mut() = truncate_variable_list(state.validators().clone(), len);
        *state.balances_mut() = truncate_variable_list(state.balances().clone(), len);
    }
    *state.genesis_validators_root_mut() = state.validators().tree_hash_root();
    *state.eth1_deposit_index_mut() = state.validators().len() as u64;
    state.eth1_data_mut().deposit_count = state.validators().len() as u64;

    let mnemonic = mnemonic_from_phrase(mnemonic_phrase)?;
    let seed = Seed::new(&mnemonic, "");

    for (index, validator) in state.validators_mut().iter_mut().enumerate() {
        let (secret, _) =
            recover_validator_secret_from_mnemonic(seed.as_bytes(), index as u32, KeyType::Voting)
                .map_err(|e| format!("Unable to generate validator key: {:?}", e))?;

        let keypair = keypair_from_secret(secret.as_bytes())
            .map_err(|e| format!("Unable build keystore: {:?}", e))?;

        eprintln!("{}: {}", index, keypair.pk);

        validator.pubkey = keypair.pk.into();
    }

    let mut file = File::create(path).map_err(|e| format!("Unable to create file: {}", e))?;

    file.write_all(&state.as_ssz_bytes())
        .map_err(|e| format!("Unable to write to file: {}", e))?;

    Ok(())
}

pub fn truncate_variable_list<T, N: Unsigned>(
    original: VariableList<T, N>,
    len: usize,
) -> VariableList<T, N> {
    let mut output = Vec::from(original);
    output.truncate(len);
    output.into()
}
