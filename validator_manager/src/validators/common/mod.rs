use account_utils::ZeroizeString;
use eth2::lighthouse_vc::std_types::{InterchangeJsonStr, KeystoreJsonStr};
use eth2::SensitiveUrl;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tree_hash::TreeHash;
use types::*;

/// When the `ethereum/staking-deposit-cli` tool generates deposit data JSON, it adds a
/// `deposit_cli_version` to protect the web-based "Launchpad" tool against a breaking change that
/// was introduced in `ethereum/staking-deposit-cli`. Lighthouse don't really have a version that it
/// can use here, so we choose a static string that is:
///
/// 1. High enough that it's accepted by Launchpad.
/// 2. Weird enough to identify Lighthouse.
const LIGHTHOUSE_DEPOSIT_CLI_VERSION: &str = "20.18.20";

#[derive(Serialize, Deserialize)]
pub struct ValidatorSpecification {
    pub voting_keystore: KeystoreJsonStr,
    pub voting_keystore_password: ZeroizeString,
    pub slashing_protection: Option<InterchangeJsonStr>,
    pub fee_recipient: Option<Address>,
    pub gas_limit: Option<u64>,
    pub builder_proposals: Option<bool>,
    pub enabled: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateSpec {
    pub mnemonic: String,
    pub validator_client_url: Option<SensitiveUrl>,
    pub validator_client_token_path: Option<PathBuf>,
    pub json_deposit_data_path: Option<PathBuf>,
    pub ignore_duplicates: bool,
    pub validators: Vec<ValidatorSpecification>,
}

/// The structure generated by the `staking-deposit-cli` which has become a quasi-standard for
/// browser-based deposit submission tools (e.g., the Ethereum Launchpad and Lido).
///
/// We assume this code as the canonical definition:
///
/// https://github.com/ethereum/staking-deposit-cli/blob/76ed78224fdfe3daca788d12442b3d1a37978296/staking_deposit/credentials.py#L131-L144
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StandardDepositDataJson {
    #[serde(with = "public_key_bytes_without_0x_prefix")]
    pub pubkey: PublicKeyBytes,
    #[serde(with = "hash256_without_0x_prefix")]
    pub withdrawal_credentials: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub amount: u64,
    #[serde(with = "signature_bytes_without_0x_prefix")]
    pub signature: SignatureBytes,
    #[serde(with = "bytes_4_without_0x_prefix")]
    pub fork_version: [u8; 4],
    pub network_name: String,
    #[serde(with = "hash256_without_0x_prefix")]
    pub deposit_message_root: Hash256,
    #[serde(with = "hash256_without_0x_prefix")]
    pub deposit_data_root: Hash256,
    pub deposit_cli_version: String,
}

impl StandardDepositDataJson {
    pub fn new(
        keypair: &Keypair,
        withdrawal_credentials: Hash256,
        amount: u64,
        spec: &ChainSpec,
    ) -> Result<Self, String> {
        let deposit_data = {
            let mut deposit_data = DepositData {
                pubkey: keypair.pk.clone().into(),
                withdrawal_credentials,
                amount,
                signature: SignatureBytes::empty(),
            };
            deposit_data.signature = deposit_data.create_signature(&keypair.sk, spec);
            deposit_data
        };

        let deposit_message_root = deposit_data.as_deposit_message().tree_hash_root();
        let deposit_data_root = deposit_data.tree_hash_root();

        let DepositData {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
        } = deposit_data;

        Ok(Self {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            fork_version: spec.genesis_fork_version,
            network_name: spec
                .config_name
                .clone()
                .ok_or("The network specification does not have a CONFIG_NAME set")?,
            deposit_message_root,
            deposit_data_root,
            deposit_cli_version: LIGHTHOUSE_DEPOSIT_CLI_VERSION.to_string(),
        })
    }
}

macro_rules! without_0x_prefix {
    ($mod_name: ident, $type: ty) => {
        pub mod $mod_name {
            use super::*;
            use std::str::FromStr;

            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = $type;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("ascii hex without a 0x prefix")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    <$type>::from_str(&format!("0x{}", v)).map_err(serde::de::Error::custom)
                }
            }

            /// Serialize with quotes.
            pub fn serialize<S>(value: &$type, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let with_prefix = format!("{:?}", value);
                let without_prefix = with_prefix
                    .strip_prefix("0x")
                    .ok_or_else(|| serde::ser::Error::custom("serialization is missing 0x"))?;
                serializer.serialize_str(&without_prefix)
            }

            /// Deserialize with quotes.
            pub fn deserialize<'de, D>(deserializer: D) -> Result<$type, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_str(Visitor)
            }
        }
    };
}

without_0x_prefix!(hash256_without_0x_prefix, Hash256);
without_0x_prefix!(signature_bytes_without_0x_prefix, SignatureBytes);
without_0x_prefix!(public_key_bytes_without_0x_prefix, PublicKeyBytes);

mod bytes_4_without_0x_prefix {
    use serde::de::Error;

    const BYTES_LEN: usize = 4;

    pub fn serialize<S>(bytes: &[u8; BYTES_LEN], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex_string = &hex::encode(&bytes);
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; BYTES_LEN], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let decoded = deserializer.deserialize_str(eth2_serde_utils::hex::HexVisitor)?;

        if decoded.len() != BYTES_LEN {
            return Err(D::Error::custom(format!(
                "expected {} bytes for array, got {}",
                BYTES_LEN,
                decoded.len()
            )));
        }

        let mut array = [0; BYTES_LEN];
        array.copy_from_slice(&decoded);
        Ok(array)
    }
}
