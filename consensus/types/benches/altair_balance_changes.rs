#![allow(deprecated)]

use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use eth2::{types::StateId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use ssz::Encode;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use types::{BeaconState, EthSpec, MainnetEthSpec, Validator};

const BEACON_NODE_URL: &'static str = "http://localhost:5052";
const STATE_SLOT: u64 = 1772320;

fn get_state<E: EthSpec>() -> BeaconState<E> {
    let client = BeaconNodeHttpClient::new(
        SensitiveUrl::parse(BEACON_NODE_URL).expect("BEACON_NODE_URL must be valid"),
        Timeouts::set_all(Duration::from_secs(10)),
    );

    let rt = Runtime::new().unwrap();

    let response = rt.block_on(async {
        client
            .get_debug_beacon_states::<E>(StateId::Slot(STATE_SLOT.into()))
            .await
            .expect("beacon node should not error")
            .expect("beacon node should have state")
    });

    response.data
}

fn all_benches(c: &mut Criterion) {
    let spec = Arc::new(MainnetEthSpec::default_spec());

    let mut state = get_state::<MainnetEthSpec>();
    state.build_all_caches(&spec).expect("should build caches");
    let state_bytes = state.as_ssz_bytes();

    let validator_count = state.validators().len();

    let inner_state = state.clone();
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("encode/beacon_state", move |b| {
            b.iter_batched_ref(
                || inner_state.clone(),
                |state| black_box(state.as_ssz_bytes()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("decode/beacon_state", move |b| {
            b.iter_batched_ref(
                || (state_bytes.clone(), spec.clone()),
                |(bytes, spec)| {
                    let state: BeaconState<MainnetEthSpec> =
                        BeaconState::from_ssz_bytes(&bytes, &spec).expect("should decode");
                    black_box(state)
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let inner_state = state.clone();
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("clone/beacon_state", move |b| {
            b.iter_batched_ref(
                || inner_state.clone(),
                |state| black_box(state.clone()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let inner_state = state.clone();
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("clone/tree_hash_cache", move |b| {
            b.iter_batched_ref(
                || inner_state.clone(),
                |state| black_box(state.tree_hash_cache().clone()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let inner_state = state.clone();
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new(
            "initialized_cached_tree_hash_without_changes/beacon_state",
            move |b| {
                b.iter_batched_ref(
                    || inner_state.clone(),
                    |state| black_box(state.update_tree_hash_cache()),
                    criterion::BatchSize::SmallInput,
                )
            },
        )
        .sample_size(10),
    );

    let mut inner_state = state.clone();
    inner_state.drop_all_caches().unwrap();
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("non_initialized_cached_tree_hash/beacon_state", move |b| {
            b.iter_batched_ref(
                || inner_state.clone(),
                |state| {
                    black_box(
                        state
                            .update_tree_hash_cache()
                            .expect("should update tree hash"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let inner_state = state.clone();
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new(
            "initialized_cached_tree_hash_with_new_validators/beacon_state",
            move |b| {
                b.iter_batched_ref(
                    || {
                        let mut state = inner_state.clone();
                        for _ in 0..16 {
                            state
                                .validators_mut()
                                .push(Validator::default())
                                .expect("should push validatorj");
                            state
                                .balances_mut()
                                .push(32_000_000_000)
                                .expect("should push balance");
                        }
                        state
                    },
                    |state| black_box(state.update_tree_hash_cache()),
                    criterion::BatchSize::SmallInput,
                )
            },
        )
        .sample_size(10),
    );
}

criterion_group!(benches, all_benches,);
criterion_main!(benches);
