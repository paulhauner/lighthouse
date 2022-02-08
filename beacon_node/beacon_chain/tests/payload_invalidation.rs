// #![cfg(not(debug_assertions))]

use beacon_chain::{
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
    BlockError, ExecutionPayloadError,
};
use types::*;

const VALIDATOR_COUNT: usize = 32;

type E = MainnetEthSpec;

#[derive(PartialEq)]
enum Payload {
    Valid,
    Invalid { latest_valid_hash: Option<Hash256> },
    Syncing,
}

struct InvalidPayloadRig {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
}

impl InvalidPayloadRig {
    fn new() -> Self {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(0));

        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .spec(spec)
            .deterministic_keypairs(VALIDATOR_COUNT)
            .mock_execution_layer()
            .fresh_ephemeral_store()
            .build();

        // Move to slot 1.
        harness.advance_slot();

        Self { harness }
    }

    fn block_hash(&self, block_root: Hash256) -> Hash256 {
        self.harness
            .chain
            .get_block(&block_root)
            .unwrap()
            .unwrap()
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .block_hash
    }

    fn fork_choice(&self) {
        self.harness.chain.fork_choice().unwrap();
    }

    fn move_to_terminal_block(&self) {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();
        mock_execution_layer
            .server
            .execution_block_generator()
            .move_to_terminal_block()
            .unwrap();
    }

    fn import_block(&mut self, is_valid: Payload) -> Hash256 {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();

        let head = self.harness.chain.head().unwrap();
        let state = head.beacon_state;
        let slot = state.slot() + 1;
        let (block, _post_state) = self.harness.make_block(state, slot);
        let block_root = block.canonical_root();

        match is_valid {
            Payload::Valid | Payload::Syncing => {
                if is_valid == Payload::Syncing {
                    mock_execution_layer.server.all_payloads_syncing();
                } else {
                    mock_execution_layer.server.full_payload_verification();
                }
                let root = self.harness.process_block(slot, block.clone()).unwrap();

                let execution_status = self
                    .harness
                    .chain
                    .fork_choice
                    .read()
                    .get_block(&root.into())
                    .unwrap()
                    .execution_status;

                match is_valid {
                    Payload::Syncing => assert!(execution_status.is_not_verified()),
                    Payload::Valid => assert!(execution_status.is_valid()),
                    Payload::Invalid { .. } => unreachable!(),
                }

                assert_eq!(
                    self.harness.chain.get_block(&block_root).unwrap().unwrap(),
                    block,
                    "block from db must match block imported"
                );
            }
            Payload::Invalid { latest_valid_hash } => {
                let latest_valid_hash = latest_valid_hash
                    .unwrap_or_else(|| self.block_hash(block.message().parent_root()));

                mock_execution_layer
                    .server
                    .all_payloads_invalid(latest_valid_hash);

                match self.harness.process_block(slot, block) {
                    Err(BlockError::ExecutionPayloadError(
                        ExecutionPayloadError::RejectedByExecutionEngine,
                    )) => (),
                    Err(other) => {
                        panic!("expected invalid payload, got {:?}", other)
                    }
                    Ok(_) => panic!("block with invalid payload was imported"),
                };

                assert!(
                    self.harness
                        .chain
                        .fork_choice
                        .read()
                        .get_block(&block_root)
                        .is_none(),
                    "invalid block must not exist in fork choice"
                );
                assert!(
                    self.harness.chain.get_block(&block_root).unwrap().is_none(),
                    "invalid block cannot be accessed via get_block"
                );
            }
        }

        block_root
    }
}

#[test]
fn payload_valid_invalid_syncing() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

    rig.import_block(Payload::Valid);
    rig.import_block(Payload::Invalid {
        latest_valid_hash: None,
    });
    rig.import_block(Payload::Syncing);
}

#[test]
fn invalid_during_processing() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

    let roots = &[
        rig.import_block(Payload::Valid),
        rig.import_block(Payload::Invalid {
            latest_valid_hash: None,
        }),
        rig.import_block(Payload::Valid),
    ];

    // 0 should be present in the chain.
    assert!(rig.harness.chain.get_block(&roots[0]).unwrap().is_some());
    // 1 should *not* be present in the chain.
    assert_eq!(rig.harness.chain.get_block(&roots[1]).unwrap(), None);
    // 2 should be the head.
    let head = rig.harness.chain.head_info().unwrap();
    assert_eq!(head.block_root, roots[2]);
}

#[test]
fn invalid_after_optimistic_sync() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

    let mut roots = vec![
        rig.import_block(Payload::Syncing),
        rig.import_block(Payload::Syncing),
        rig.import_block(Payload::Syncing),
    ];

    for root in &roots {
        assert!(rig.harness.chain.get_block(root).unwrap().is_some());
    }

    // 2 should be the head.
    let head = rig.harness.chain.head_info().unwrap();
    assert_eq!(head.block_root, roots[2]);

    roots.push(rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(rig.block_hash(roots[1])),
    }));

    // Running fork choice is necessary since a block has been invalidated.
    rig.fork_choice();

    // 1 should be the head, since 2 was invalidated.
    let head = rig.harness.chain.head_info().unwrap();
    assert_eq!(head.block_root, roots[1]);
}
