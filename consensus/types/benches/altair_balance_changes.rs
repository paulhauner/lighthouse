#![allow(deprecated)]

use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use eth2::{types::StateId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use types::{BeaconState, CloneConfig, EthSpec, MainnetEthSpec};

const BEACON_NODE_URL: &'static str = "http://localhost:5052";
const STATE_SLOT: u64 = 1783731;
const SYNC_COMMITTEE_SIZE: usize = 512;

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
    let _ = state.update_tree_hash_cache().unwrap();

    let clean_state = state.clone_with(CloneConfig::all());

    let mut dirty_state = state;

    for chunk in dirty_state.balances_mut().chunks_mut(SYNC_COMMITTEE_SIZE) {
        chunk[0] += 1
    }

    do_benches(c, "clean", clean_state);
    do_benches(c, "dirty", dirty_state);
}

fn do_benches<E: EthSpec>(c: &mut Criterion, title: &str, state: BeaconState<E>) {
    let inner_state = state.clone();
    c.bench(
        title,
        Benchmark::new("cached_tree_hash/initialized_cache", move |b| {
            b.iter_batched_ref(
                || inner_state.clone(),
                |state| black_box(state.update_tree_hash_cache()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let mut inner_state = state.clone();
    inner_state.drop_all_caches().unwrap();
    c.bench(
        title,
        Benchmark::new("cached_tree_hash/non_initialized_cache", move |b| {
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
}

criterion_group!(benches, all_benches,);
criterion_main!(benches);
