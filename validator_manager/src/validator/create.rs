use super::common::*;
use account_utils::{
    random_password_string, read_mnemonic_from_cli, read_password_from_user, ZeroizeString,
};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use eth2::{
    lighthouse_vc::{
        http_client::ValidatorClientHttpClient,
        std_types::{ImportKeystoresRequest, KeystoreJsonStr},
        types::UpdateFeeRecipientRequest,
    },
    SensitiveUrl,
};
use eth2_keystore::Keystore;
use eth2_wallet::{
    bip39::{Language, Mnemonic},
    WalletBuilder,
};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use types::*;

pub const CMD: &str = "create";
pub const DEPOSIT_GWEI_FLAG: &str = "deposit-gwei";
pub const JSON_DEPOSIT_DATA_PATH: &str = "json-deposit-data-path";
pub const COUNT_FLAG: &str = "count";
pub const STDIN_INPUTS_FLAG: &str = "stdin-inputs";
pub const FIRST_INDEX_FLAG: &str = "first-index";
pub const MNEMONIC_FLAG: &str = "mnemonic-path";
pub const SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG: &str = "specify-voting-keystore-password";
pub const ETH1_WITHDRAWAL_ADDRESS_FLAG: &str = "eth1-withdrawal-address";
pub const VALIDATOR_CLIENT_URL_FLAG: &str = "validator-client-url";
pub const VALIDATOR_CLIENT_TOKEN_FLAG: &str = "validator-client-token";
pub const IGNORE_DUPLICATES_FLAG: &str = "ignore-duplicates";
pub const GAS_LIMIT_FLAG: &str = "gas-limit";
pub const FEE_RECIPIENT_FLAG: &str = "suggested-fee-recipient";
pub const BUILDER_PROPOSALS_FLAG: &str = "builder-proposals";

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
            Arg::with_name(DEPOSIT_GWEI_FLAG)
                .long(DEPOSIT_GWEI_FLAG)
                .value_name("DEPOSIT_GWEI")
                .help(
                    "The GWEI value of the deposit amount. Defaults to the minimum amount \
                    required for an active validator (MAX_EFFECTIVE_BALANCE)",
                )
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
            Arg::with_name(JSON_DEPOSIT_DATA_PATH)
                .long(JSON_DEPOSIT_DATA_PATH)
                .value_name("PATH")
                .help(
                    "When provided, outputs a JSON file containing deposit data which \
                    is equivalent to the 'deposit-data-*.json' file used by the \
                    staking-deposit-cli tool.",
                )
                .takes_value(true),
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
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VALIDATOR_CLIENT_URL_FLAG)
                .long(VALIDATOR_CLIENT_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API. \
                    If this value is not supplied then a 'dry run' will be conducted where \
                    no changes are made to the validator client.",
                )
                .requires(VALIDATOR_CLIENT_TOKEN_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VALIDATOR_CLIENT_TOKEN_FLAG)
                .long(VALIDATOR_CLIENT_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the validator client.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(IGNORE_DUPLICATES_FLAG)
                .takes_value(false)
                .long(IGNORE_DUPLICATES_FLAG)
                .help(
                    "If present, ignore any validators which already exist on the VC. \
                    Without this flag, the process will terminate without making any changes. \
                    This flag should be used with caution, whilst it does not directly cause \
                    slashable conditions, it might be an indicator that something is amiss. \
                    Users should also be careful to avoid submitting duplicate deposits for \
                    validators that already exist on the VC.",
                ),
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
                .required(false)
                .required(false),
        )
}

pub async fn cli_run<'a, T: EthSpec>(
    matches: &'a ArgMatches<'a>,
    mut env: Environment<T>,
) -> Result<(), String> {
    let spec = &env.core_context().eth2_config.spec;

    let create_spec = build_validator_spec_from_cli(matches, spec)?;
    enact_spec(create_spec, spec).await
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
    let json_deposit_data_path: Option<PathBuf> =
        clap_utils::parse_optional(matches, JSON_DEPOSIT_DATA_PATH)?;
    let specify_voting_keystore_password =
        matches.is_present(SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG);
    let eth1_withdrawal_address: Option<Address> =
        clap_utils::parse_optional(matches, ETH1_WITHDRAWAL_ADDRESS_FLAG)?;
    let vc_url: Option<SensitiveUrl> =
        clap_utils::parse_optional(matches, VALIDATOR_CLIENT_URL_FLAG)?;
    let vc_token_path: Option<PathBuf> =
        clap_utils::parse_optional(matches, VALIDATOR_CLIENT_TOKEN_FLAG)?;
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
    let mut deposits = Some(vec![]).filter(|_| json_deposit_data_path.is_some());

    for (i, derivation_index) in (first_index..first_index + count).enumerate() {
        let voting_keystore_password =
            voting_keystore_password.unwrap_or_else(|| random_password_string());

        wallet
            .set_nextaccount(derivation_index)
            .map_err(|e| format!("Failure to set validator derivation index: {:?}", e))?;

        let keystores = wallet
            .next_validator(
                wallet_password.as_ref(),
                voting_keystore_password.as_ref(),
                withdrawal_keystore_password.as_ref(),
            )
            .map_err(|e| format!("Failed to derive keystore {}: {:?}", i, e))?;
        let voting_keystore = keystores.voting;
        let voting_keypair = voting_keystore
            .decrypt_keypair(voting_keystore_password.as_ref())
            .map_err(|e| format!("Failed to decrypt voting keystore {}: {:?}", i, e))?;

        if let Some(deposits) = &mut deposits {
            let withdrawal_credentials = if let Some(eth1_withdrawal_address) =
                eth1_withdrawal_address
            {
                WithdrawalCredentials::eth1(eth1_withdrawal_address, &spec)
            } else {
                let withdrawal_keypair = keystores
                    .withdrawal
                    .decrypt_keypair(withdrawal_keystore_password.as_ref())
                    .map_err(|e| format!("Failed to decrypt withdrawal keystore {}: {:?}", i, e))?;
                WithdrawalCredentials::bls(&withdrawal_keypair.pk, &spec)
            };

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

pub async fn enact_spec<'a>(create_spec: CreateSpec, spec: &ChainSpec) -> Result<(), String> {
    let CreateSpec {
        mnemonic,
        validator_client_url,
        validator_client_token_path,
        json_deposit_data_path,
        ignore_duplicates,
        validators,
    } = create_spec;

    let count = validators.len();

    let mnemonic = Mnemonic::from_phrase(&mnemonic, Language::English)
        .map_err(|e| format!("Failed to parse mnemonic from create spec: {:?}", e))?;

    let http_client = match (validator_client_url, validator_client_token_path) {
        (Some(vc_url), Some(vc_token_path)) => {
            let token_bytes = fs::read(&vc_token_path)
                .map_err(|e| format!("Failed to read {:?}: {:?}", vc_token_path, e))?;
            let token_string = String::from_utf8(token_bytes)
                .map_err(|e| format!("Failed to parse {:?} as utf8: {:?}", vc_token_path, e))?;
            let http_client = ValidatorClientHttpClient::new(vc_url.clone(), token_string)
                .map_err(|e| {
                    format!(
                        "Could not instantiate HTTP client from URL and secret: {:?}",
                        e
                    )
                })?;

            // Perform a request to check that the connection works
            let remote_keystores = http_client
                .get_keystores()
                .await
                .map_err(|e| format!("Failed to list keystores on VC: {:?}", e))?;
            eprintln!(
                "Validator client is reachable at {} and reports {} validators",
                vc_url,
                remote_keystores.data.len()
            );

            Some(http_client)
        }
        (None, None) => None,
        _ => {
            return Err(format!(
                "Inconsistent use of {} and {}",
                VALIDATOR_CLIENT_URL_FLAG, VALIDATOR_CLIENT_TOKEN_FLAG
            ))
        }
    };

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

    let mut validator_keystores = Vec::with_capacity(count);

    eprintln!("Starting key generation. Each validator may take several seconds.");

    for (i, validator) in validators.into_iter().enumerate() {
        let CreateValidatorSpec {
            voting_keystore,
            voting_keystore_password,
            fee_recipient,
            gas_limit,
            builder_proposals,
            enabled,
        } = validator;

        let voting_keystore = voting_keystore.0;

        let voting_keypair = voting_keystore
            .decrypt_keypair(voting_keystore_password.as_ref())
            .map_err(|e| format!("Failed to decrypt voting keystore {}: {:?}", i, e))?;
        let voting_pubkey_bytes = voting_keypair.pk.clone().into();

        // Check to see if this validator already exists in the VC.
        if let Some(http_client) = &http_client {
            let remote_keystores = http_client
                .get_keystores()
                .await
                .map_err(|e| format!("Failed to list keystores on VC: {:?}", e))?;

            if remote_keystores
                .data
                .iter()
                .find(|keystore| keystore.validating_pubkey == voting_pubkey_bytes)
                .is_some()
            {
                if ignore_duplicates {
                    eprintln!(
                        "Validator {:?} already exists in the VC, be cautious of submitting \
                        duplicate deposits",
                        IGNORE_DUPLICATES_FLAG
                    );
                } else {
                    return Err(format!(
                        "Duplicate validator {:?} detected, see --{} for more information",
                        voting_keypair.pk, IGNORE_DUPLICATES_FLAG
                    ));
                }
            }
        }

        eprintln!(
            "{}/{}: {:?}",
            i.saturating_add(1),
            count,
            &voting_keypair.pk
        );

        validator_keystores.push(ValidatorKeystore {
            voting_keystore,
            voting_keystore_password,
            voting_pubkey_bytes,
            fee_recipient,
            gas_limit,
            builder_proposals,
            enabled,
        });
    }

    if let Some(http_client) = http_client {
        eprintln!(
            "Generated {} keystores. Starting to submit keystores to VC, \
            each keystore may take several seconds",
            count
        );

        for (i, validator_keystore) in validator_keystores.into_iter().enumerate() {
            let ValidatorKeystore {
                voting_keystore,
                voting_keystore_password,
                voting_pubkey_bytes,
                fee_recipient,
                gas_limit,
                builder_proposals,
                enabled,
            } = validator_keystore;

            let request = ImportKeystoresRequest {
                keystores: vec![KeystoreJsonStr(voting_keystore)],
                passwords: vec![voting_keystore_password],
                // New validators have no slashing protection history.
                slashing_protection: None,
            };

            if let Err(e) = http_client.post_keystores(&request).await {
                eprintln!(
                    "Failed to upload batch {}. Some keys were imported whilst \
                    others may not have been imported. A potential solution is to use the \
                    --{} flag, however care should be taken to ensure that there are no \
                    duplicate deposits submitted.",
                    i, IGNORE_DUPLICATES_FLAG
                );
                // Return here *without* writing the deposit JSON file. This might help prevent
                // users from submitting duplicate deposits or deposits for validators that weren't
                // initialized on a VC.
                //
                // Next the the user runs with the --ignore-duplicates flag there should be a new,
                // complete deposit JSON file created.
                return Err(format!("Key upload failed: {:?}", e));
            }

            if let Some(fee_recipient) = fee_recipient {
                http_client
                    .post_fee_recipient(
                        &voting_pubkey_bytes,
                        &UpdateFeeRecipientRequest {
                            ethaddress: fee_recipient,
                        },
                    )
                    .await
                    .map_err(|e| format!("Failed to update fee recipient on VC: {:?}", e))?;
            }

            if gas_limit.is_some() || builder_proposals.is_some() || enabled.is_some() {
                http_client
                    .patch_lighthouse_validators(
                        &voting_pubkey_bytes,
                        enabled,
                        gas_limit,
                        builder_proposals,
                    )
                    .await
                    .map_err(|e| format!("Failed to update lighthouse validator on VC: {:?}", e))?;
            }

            eprintln!("Uploaded keystore {} of {} to the VC", i + 1, count);
        }
    }

    // If configured, create a single JSON file which contains deposit data information for all
    // validators.
    if let Some(json_deposit_data_path) = json_deposit_data_path {
        let json_deposits = json_deposits.ok_or("Internal error: JSON deposit data is None")?;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&json_deposit_data_path)
            .map_err(|e| format!("Unable to create {:?}: {:?}", json_deposit_data_path, e))?;

        serde_json::to_writer(&mut file, &json_deposits)
            .map_err(|e| format!("Unable write JSON to {:?}: {:?}", json_deposit_data_path, e))?;
    }

    Ok(())
}
