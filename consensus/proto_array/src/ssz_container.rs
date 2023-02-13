use crate::proto_array::ProposerBoost;
use crate::{
    proto_array::{ProtoArray, ProtoNode},
    proto_array_fork_choice::{ElasticList, ExecutionStatus, ProtoArrayForkChoice, VoteTracker},
    Error, JustifiedBalances,
};
use ssz::{four_byte_option_impl, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use std::convert::TryFrom;
use superstruct::superstruct;
use types::{AttestationShufflingId, Checkpoint, Hash256, Slot};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_checkpoint, Checkpoint);
four_byte_option_impl!(four_byte_option_usize, usize);

/// This struct is used for persisting a `ProtoNode` to disk. We use this
/// separate struct to avoid adding the getter/setter function complexity to the
/// fork choice code.
#[superstruct(
    variants(V13, V14),
    variant_attributes(derive(PartialEq, Clone, Debug, Encode, Decode)),
    no_enum
)]
pub struct PersistedProtoNode {
    /// The `slot` is not necessary for `ProtoArray`, it just exists so external components can
    /// easily query the block slot. This is useful for upstream fork choice logic.
    pub slot: Slot,
    /// The `state_root` is not necessary for `ProtoArray` either, it also just exists for upstream
    /// components (namely attestation verification).
    pub state_root: Hash256,
    /// The root that would be used for the `attestation.data.target.root` if a LMD vote was cast
    /// for this block.
    ///
    /// The `target_root` is not necessary for `ProtoArray` either, it also just exists for upstream
    /// components (namely fork choice attestation verification).
    pub target_root: Hash256,
    pub current_epoch_shuffling_id: AttestationShufflingId,
    pub next_epoch_shuffling_id: AttestationShufflingId,
    pub root: Hash256,
    #[ssz(with = "four_byte_option_usize")]
    pub parent: Option<usize>,
    // V13 has the finalized and justified checkpoints as optional.
    #[superstruct(only(V13))]
    #[ssz(with = "four_byte_option_checkpoint")]
    pub justified_checkpoint: Option<Checkpoint>,
    #[superstruct(only(V13))]
    #[ssz(with = "four_byte_option_checkpoint")]
    pub finalized_checkpoint: Option<Checkpoint>,
    // V14 has non-optional finalized and justified checkpoints.
    #[superstruct(only(V14))]
    pub justified_checkpoint: Checkpoint,
    #[superstruct(only(V14))]
    pub finalized_checkpoint: Checkpoint,
    pub weight: u64,
    #[ssz(with = "four_byte_option_usize")]
    pub best_child: Option<usize>,
    #[ssz(with = "four_byte_option_usize")]
    pub best_descendant: Option<usize>,
    /// Indicates if an execution node has marked this block as valid. Also contains the execution
    /// block hash.
    pub execution_status: ExecutionStatus,
    #[ssz(with = "four_byte_option_checkpoint")]
    pub unrealized_justified_checkpoint: Option<Checkpoint>,
    #[ssz(with = "four_byte_option_checkpoint")]
    pub unrealized_finalized_checkpoint: Option<Checkpoint>,
}

macro_rules! from_impl {
    ($from: ident, $to: ident) => {
        impl From<$from> for $to {
            fn from(node: $from) -> Self {
                Self {
                    slot: node.slot,
                    state_root: node.state_root,
                    target_root: node.target_root,
                    current_epoch_shuffling_id: node.current_epoch_shuffling_id,
                    next_epoch_shuffling_id: node.next_epoch_shuffling_id,
                    root: node.root,
                    parent: node.parent,
                    justified_checkpoint: node.justified_checkpoint,
                    finalized_checkpoint: node.finalized_checkpoint,
                    weight: node.weight,
                    best_child: node.best_child,
                    best_descendant: node.best_descendant,
                    execution_status: node.execution_status,
                    unrealized_justified_checkpoint: node.unrealized_justified_checkpoint,
                    unrealized_finalized_checkpoint: node.unrealized_finalized_checkpoint,
                }
            }
        }
    };
}

from_impl!(PersistedProtoNodeV14, ProtoNode);
from_impl!(ProtoNode, PersistedProtoNodeV14);

#[superstruct(
    variants(V13, V14),
    variant_attributes(derive(Encode, Decode)),
    no_enum
)]
pub struct SszContainer {
    pub votes: Vec<VoteTracker>,
    pub balances: Vec<u64>,
    pub prune_threshold: usize,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    #[superstruct(only(V13))]
    pub nodes: Vec<PersistedProtoNodeV13>,
    #[superstruct(only(V14))]
    pub nodes: Vec<PersistedProtoNodeV14>,
    pub indices: Vec<(Hash256, usize)>,
    pub previous_proposer_boost: ProposerBoost,
}

impl From<&ProtoArrayForkChoice> for SszContainerV14 {
    fn from(from: &ProtoArrayForkChoice) -> Self {
        let proto_array = &from.proto_array;

        Self {
            votes: from.votes.0.clone(),
            balances: from.balances.effective_balances.clone(),
            prune_threshold: proto_array.prune_threshold,
            justified_checkpoint: proto_array.justified_checkpoint,
            finalized_checkpoint: proto_array.finalized_checkpoint,
            nodes: proto_array.nodes.iter().cloned().map(Into::into).collect(),
            indices: proto_array.indices.iter().map(|(k, v)| (*k, *v)).collect(),
            previous_proposer_boost: proto_array.previous_proposer_boost,
        }
    }
}

impl TryFrom<SszContainerV14> for ProtoArrayForkChoice {
    type Error = Error;

    fn try_from(from: SszContainerV14) -> Result<Self, Error> {
        let proto_array = ProtoArray {
            prune_threshold: from.prune_threshold,
            justified_checkpoint: from.justified_checkpoint,
            finalized_checkpoint: from.finalized_checkpoint,
            nodes: from.nodes.into_iter().map(Into::into).collect(),
            indices: from.indices.into_iter().collect::<HashMap<_, _>>(),
            previous_proposer_boost: from.previous_proposer_boost,
        };

        Ok(Self {
            proto_array,
            votes: ElasticList(from.votes),
            balances: JustifiedBalances::from_effective_balances(from.balances)?,
        })
    }
}
