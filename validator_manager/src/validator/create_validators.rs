use super::common::*;
use account_utils::{
    random_password_string, read_mnemonic_from_cli, read_password_from_user, ZeroizeString,
};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use eth2::lighthouse_vc::std_types::KeystoreJsonStr;
use eth2_keystore::Keystore;
use eth2_wallet::WalletBuilder;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use types::*;

pub const CMD: &str = "create";
pub const OUTPUT_PATH_FLAG: &str = "output-path";
pub const DEPOSIT_GWEI_FLAG: &str = "deposit-gwei";
pub const DISABLE_DEPOSITS_FLAG: &str = "disable-deposits";
pub const COUNT_FLAG: &str = "count";
pub const STDIN_INPUTS_FLAG: &str = "stdin-inputs";
pub const FIRST_INDEX_FLAG: &str = "first-index";
pub const MNEMONIC_FLAG: &str = "mnemonic-path";
pub const SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG: &str = "specify-voting-keystore-password";
pub const ETH1_WITHDRAWAL_ADDRESS_FLAG: &str = "eth1-withdrawal-address";
pub const IGNORE_DUPLICATES_FLAG: &str = "ignore-duplicates";
pub const GAS_LIMIT_FLAG: &str = "gas-limit";
pub const FEE_RECIPIENT_FLAG: &str = "suggested-fee-recipient";
pub const BUILDER_PROPOSALS_FLAG: &str = "builder-proposals";

pub const VALIDATORS_FILENAME: &str = "validators.json";
pub const DEPOSITS_FILENAME: &str = "deposits.json";

struct ValidatorKeystore {
    voting_keystore: Keystore,
    voting_keystore_password: ZeroizeString,
    voting_pubkey_bytes: PublicKeyBytes,
    fee_recipient: Option<Address>,
    gas_limit: Option<u64>,
    builder_proposals: Option<bool>,
    enabled: Option<bool>,
}

struct ValidatorsAndDeposits {
    validators: Vec<ValidatorSpecification>,
    deposits: Option<Vec<StandardDepositDataJson>>,
}

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Creates new validators from BIP-39 mnemonic.")
        .arg(
            Arg::with_name(OUTPUT_PATH_FLAG)
                .long(OUTPUT_PATH_FLAG)
                .value_name("DIRECTORY")
                .help(
                    "The path to a directory where the validator and (optionally) deposits \
                    files will be created. The directory will be created if it does not exist.",
                )
                .conflicts_with(DISABLE_DEPOSITS_FLAG)
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DEPOSIT_GWEI_FLAG)
                .long(DEPOSIT_GWEI_FLAG)
                .value_name("DEPOSIT_GWEI")
                .help(
                    "The GWEI value of the deposit amount. Defaults to the minimum amount \
                    required for an active validator (MAX_EFFECTIVE_BALANCE)",
                )
                .conflicts_with(DISABLE_DEPOSITS_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(FIRST_INDEX_FLAG)
                .long(FIRST_INDEX_FLAG)
                .value_name("FIRST_INDEX")
                .help("The first of consecutive key indexes you wish to recover.")
                .takes_value(true)
                .required(false)
                .default_value("0"),
        )
        .arg(
            Arg::with_name(COUNT_FLAG)
                .long(COUNT_FLAG)
                .value_name("VALIDATOR_COUNT")
                .help("The number of validators to create, regardless of how many already exist")
                .conflicts_with("at-most")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(MNEMONIC_FLAG)
                .long(MNEMONIC_FLAG)
                .value_name("MNEMONIC_PATH")
                .help("If present, the mnemonic will be read in from this file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(STDIN_INPUTS_FLAG)
                .takes_value(false)
                .hidden(cfg!(windows))
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
        )
        .arg(
            Arg::with_name(DISABLE_DEPOSITS_FLAG)
                .long(DISABLE_DEPOSITS_FLAG)
                .value_name("PATH")
                .help(
                    "When provided don't generate the deposits JSON file that is \
                    commonly used for submitting validator deposits via a web UI. \
                    Using this flag will save several seconds per validator if the \
                    user has an alternate strategy for submitting deposits.",
                ),
        )
        .arg(
            Arg::with_name(SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG)
                .long(SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG)
                .value_name("STRING")
                .takes_value(true)
                .help(
                    "If present, the user will be prompted to enter the voting keystore \
                    password that will be used to encrypt the voting keystores. If this \
                    flag is not provided, a random password will be used. It is not \
                    necessary to keep backups of voting keystore passwords if the \
                    mnemonic is safely backed up.",
                ),
        )
        .arg(
            Arg::with_name(ETH1_WITHDRAWAL_ADDRESS_FLAG)
                .long(ETH1_WITHDRAWAL_ADDRESS_FLAG)
                .value_name("ETH1_ADDRESS")
                .help(
                    "If this field is set, the given eth1 address will be used to create the \
                    withdrawal credentials. Otherwise, it will generate withdrawal credentials \
                    with the mnemonic-derived withdrawal public key in EIP-2334 format.",
                )
                .conflicts_with(DISABLE_DEPOSITS_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(GAS_LIMIT_FLAG)
                .long(GAS_LIMIT_FLAG)
                .value_name("UINT64")
                .help(
                    "All created validators will use this gas limit. It is recommended \
                    to leave this as the default value by not specifying this flag.",
                )
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(FEE_RECIPIENT_FLAG)
                .long(FEE_RECIPIENT_FLAG)
                .value_name("ETH1_ADDRESS")
                .help(
                    "All created validators will use this value for the suggested \
                    fee recipient. Omit this flag to use the default value from the VC.",
                )
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(BUILDER_PROPOSALS_FLAG)
                .long(BUILDER_PROPOSALS_FLAG)
                .help(
                    "When provided, all created validators will attempt to create \
                    blocks via builder rather than the local EL.",
                )
                .required(false),
        )
}

pub async fn cli_run<'a, T: EthSpec>(
    matches: &'a ArgMatches<'a>,
    mut env: Environment<T>,
) -> Result<(), String> {
    let spec = &env.core_context().eth2_config.spec;
    let output_path: PathBuf = clap_utils::parse_required(matches, OUTPUT_PATH_FLAG)?;

    if !output_path.exists() {
        fs::create_dir(&output_path)
            .map_err(|e| format!("Failed to create {:?} directory: {:?}", output_path, e))?;
    } else if !output_path.is_dir() {
        return Err(format!("{:?} must be a directory", output_path));
    }

    let validators_path = output_path.join(VALIDATORS_FILENAME);
    if validators_path.exists() {
        return Err(format!(
            "{:?} already exists, refusing to overwrite",
            validators_path
        ));
    }
    let deposits_path = output_path.join(DEPOSITS_FILENAME);
    if deposits_path.exists() {
        return Err(format!(
            "{:?} already exists, refusing to overwrite",
            deposits_path
        ));
    }

    let validators_and_deposits = build_validator_spec_from_cli(matches, spec)?;

    write_to_json_file(&validators_path, &validators_and_deposits.validators)?;

    if let Some(deposits) = validators_and_deposits.deposits {
        write_to_json_file(&deposits_path, &validators_and_deposits.validators)?;
    }

    Ok(())
}

fn write_to_json_file<P: AsRef<Path>, S: Serialize>(path: P, contents: &S) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Failed to open {:?}: {:?}", path.as_ref(), e))?;
    serde_json::to_writer(&mut file, contents)
        .map_err(|e| format!("Failed to write JSON to {:?}: {:?}", path.as_ref(), e))
}

pub fn build_validator_spec_from_cli<'a>(
    matches: &'a ArgMatches<'a>,
    spec: &ChainSpec,
) -> Result<ValidatorsAndDeposits, String> {
    let deposit_gwei = clap_utils::parse_optional(matches, DEPOSIT_GWEI_FLAG)?
        .unwrap_or(spec.max_effective_balance);
    let first_index: u32 = clap_utils::parse_required(matches, FIRST_INDEX_FLAG)?;
    let count: u32 = clap_utils::parse_required(matches, COUNT_FLAG)?;
    let mnemonic_path: Option<PathBuf> = clap_utils::parse_optional(matches, MNEMONIC_FLAG)?;
    let stdin_inputs = cfg!(windows) || matches.is_present(STDIN_INPUTS_FLAG);
    let disable_deposits = matches.is_present(DISABLE_DEPOSITS_FLAG);
    let specify_voting_keystore_password =
        matches.is_present(SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG);
    let eth1_withdrawal_address: Option<Address> =
        clap_utils::parse_optional(matches, ETH1_WITHDRAWAL_ADDRESS_FLAG)?;
    let ignore_duplicates = matches.is_present(IGNORE_DUPLICATES_FLAG);
    let builder_proposals = matches.is_present(BUILDER_PROPOSALS_FLAG);
    let fee_recipient: Option<Address> = clap_utils::parse_optional(matches, FEE_RECIPIENT_FLAG)?;
    let gas_limit: Option<u64> = clap_utils::parse_optional(matches, GAS_LIMIT_FLAG)?;

    let mnemonic = read_mnemonic_from_cli(mnemonic_path, stdin_inputs)?;
    let voting_keystore_password = if specify_voting_keystore_password {
        eprintln!("Please enter a voting keystore password when prompted.");
        Some(read_password_from_user(stdin_inputs)?)
    } else {
        None
    };

    /*
     * Generate a wallet to be used for HD key generation.
     */

    // A random password is always appropriate for the wallet since it is ephemeral.
    let wallet_password = random_password_string();
    // A random password is always appropriate for the withdrawal keystore since we don't ever store
    // it anywhere.
    let withdrawal_keystore_password = random_password_string();
    let mut wallet =
        WalletBuilder::from_mnemonic(&mnemonic, wallet_password.as_ref(), "".to_string())
            .map_err(|e| format!("Unable create seed from mnemonic: {:?}", e))?
            .build()
            .map_err(|e| format!("Unable to create wallet: {:?}", e))?;

    /*
     * Start deriving individual validators.
     */

    let mut validators = Vec::with_capacity(count as usize);
    let mut deposits = disable_deposits.then(|| vec![]);

    for (i, derivation_index) in (first_index..first_index + count).enumerate() {
        // If the voting keystore password was not provided by the user then use a unique random
        // string for each validator.
        let voting_keystore_password =
            voting_keystore_password.unwrap_or_else(|| random_password_string());

        // Set the wallet to the appropriate derivation index.
        wallet
            .set_nextaccount(derivation_index)
            .map_err(|e| format!("Failure to set validator derivation index: {:?}", e))?;

        // Derive the keystore from the HD wallet.
        let keystores = wallet
            .next_validator(
                wallet_password.as_ref(),
                voting_keystore_password.as_ref(),
                withdrawal_keystore_password.as_ref(),
            )
            .map_err(|e| format!("Failed to derive keystore {}: {:?}", i, e))?;
        let voting_keystore = keystores.voting;

        if let Some(deposits) = &mut deposits {
            // Decrypt the voting keystore so a deposit message can be signed.
            let voting_keypair = voting_keystore
                .decrypt_keypair(voting_keystore_password.as_ref())
                .map_err(|e| format!("Failed to decrypt voting keystore {}: {:?}", i, e))?;

            let withdrawal_credentials = if let Some(eth1_withdrawal_address) =
                eth1_withdrawal_address
            {
                WithdrawalCredentials::eth1(eth1_withdrawal_address, &spec)
            } else {
                // Decrypt the withdrawal keystore so withdrawal credentials can be created. It's
                // not strictly necessary to decrypt the keystore since we can read the pubkey
                // directly from the keystore. However we decrypt the keystore to be more certain
                // that we have access to the withdrawal keys.
                let withdrawal_keypair = keystores
                    .withdrawal
                    .decrypt_keypair(withdrawal_keystore_password.as_ref())
                    .map_err(|e| format!("Failed to decrypt withdrawal keystore {}: {:?}", i, e))?;
                WithdrawalCredentials::bls(&withdrawal_keypair.pk, &spec)
            };

            // Create a JSON structure equivalent to the one generated by
            // `ethereum/staking-deposit-cli`.
            let json_deposit = StandardDepositDataJson::new(
                &voting_keypair,
                withdrawal_credentials.into(),
                deposit_gwei,
                &spec,
            )?;

            deposits.push(json_deposit);
        }

        let validator = ValidatorSpecification {
            voting_keystore: KeystoreJsonStr(voting_keystore),
            voting_keystore_password: voting_keystore_password.clone(),
            fee_recipient,
            gas_limit,
            builder_proposals: Some(builder_proposals),
            enabled: Some(true),
        };
        validators.push(validator);
    }

    Ok(ValidatorsAndDeposits {
        validators,
        deposits,
    })
}
