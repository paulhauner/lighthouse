use paste::paste;
use std::env;
use std::path::PathBuf;
use types::{ChainSpec, EthSpecId};

// A macro is used to define this constant so it can be used with `include_bytes!`.
#[macro_export]
macro_rules! predefined_networks_dir {
    () => {
        "built_in_network_configs"
    };
}

pub const PREDEFINED_NETWORKS_DIR: &str = predefined_networks_dir!();
pub const GENESIS_FILE_NAME: &str = "genesis.ssz";
pub const GENESIS_ZIP_FILE_NAME: &str = "genesis.ssz.zip";

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone)]
pub struct Eth2Config {
    pub eth_spec_id: EthSpecId,
    pub spec: ChainSpec,
}

impl Default for Eth2Config {
    fn default() -> Self {
        Self {
            eth_spec_id: EthSpecId::Minimal,
            spec: ChainSpec::minimal(),
        }
    }
}

impl Eth2Config {
    pub fn mainnet() -> Self {
        Self {
            eth_spec_id: EthSpecId::Mainnet,
            spec: ChainSpec::mainnet(),
        }
    }

    pub fn minimal() -> Self {
        Self {
            eth_spec_id: EthSpecId::Minimal,
            spec: ChainSpec::minimal(),
        }
    }
}

/// A directory that can be built by downloading files via HTTP.
///
/// Used by the `eth2_network_config` crate to initialize the network directories during build and
/// access them at runtime.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Eth2NetArchiveAndDirectory<'a> {
    pub name: &'a str,
    pub unique_id: &'a str,
    pub genesis_is_known: bool,
}

impl<'a> Eth2NetArchiveAndDirectory<'a> {
    /// The directory that should be used to store files downloaded for this net.
    pub fn dir(&self) -> PathBuf {
        env::var("CARGO_MANIFEST_DIR")
            .expect("should know manifest dir")
            .parse::<PathBuf>()
            .expect("should parse manifest dir as path")
            .join(PREDEFINED_NETWORKS_DIR)
            .join(self.unique_id)
    }

    pub fn genesis_state_archive(&self) -> PathBuf {
        self.dir().join(GENESIS_ZIP_FILE_NAME)
    }
}

/// Indicates that the `genesis.ssz.zip` file is present on the filesystem. This means that the
/// deposit ceremony has concluded and the final genesis `BeaconState` is known.
const GENESIS_STATE_IS_KNOWN: bool = true;

macro_rules! define_archive {
    ($title: ident, $genesis_is_known: ident) => {
        paste! {
            #[macro_use]
            pub mod $title {
                use super::*;

                pub const ETH2_NET_DIR: Eth2NetArchiveAndDirectory = Eth2NetArchiveAndDirectory {
                    name: stringify!($title),
                    unique_id: stringify!($title),
                    genesis_is_known: $genesis_is_known,
                };

                // A wrapper around `std::include_bytes` which includes a file from a specific network
                // directory. Used by upstream crates to import files at compile time.
                #[macro_export]
                macro_rules! [<include_ $title _file>] {
                    ($base_dir: tt, $filename: tt) => {
                        include_bytes!(concat!(
                            $base_dir,
                            "/",
                            predefined_networks_dir!(),
                            "/",
                            stringify!($title),
                            "/",
                            $filename
                        ))
                    };
                }
            }
        }
    };
}

macro_rules! define_archives {
    ($(($name: ident, $genesis_is_known: ident)),+) => {
        paste! {
            $(
            define_archive!($name, $genesis_is_known);
            )+
            pub const ETH2_NET_DIRS: &[Eth2NetArchiveAndDirectory<'static>] = &[$($name::ETH2_NET_DIR,)+];
        }
    };
}

// Add a new "built-in" network by adding it to the list below.
//
// ## Notes
//
// - The last entry must not end with a comma.
// - The network must also be added in the `eth2_network_config` crate.
define_archives!(
    (mainnet, GENESIS_STATE_IS_KNOWN),
    (pyrmont, GENESIS_STATE_IS_KNOWN),
    (prater, GENESIS_STATE_IS_KNOWN)
);
