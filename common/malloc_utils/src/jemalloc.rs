//! Set the allocator to `jemalloc`.
//!
//! Due to `jemalloc` requiring configuration at compile time or immediately upon runtime
//! initialisation it is configured via a Cargo config file in `.cargo/config.toml`.
//!
//! The `jemalloc` tuning can be overridden by:
//!
//! A) `JEMALLOC_SYS_WITH_MALLOC_CONF` at compile-time.
//! B) `_RJEM_MALLOC_CONF` at runtime.
use metrics::{
    set_gauge, set_gauge_vec, try_create_int_gauge, try_create_int_gauge_vec, IntGauge, IntGaugeVec,
};
use std::sync::LazyLock;
use tikv_jemalloc_ctl::{arenas, epoch, raw, stats, Access, AsName, Error};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Metrics for jemalloc.
pub static NUM_ARENAS: LazyLock<metrics::Result<IntGauge>> =
    LazyLock::new(|| try_create_int_gauge("jemalloc_num_arenas", "The number of arenas in use"));
pub static BYTES_ALLOCATED: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("jemalloc_bytes_allocated", "Equivalent to stats.allocated")
});
pub static BYTES_ACTIVE: LazyLock<metrics::Result<IntGauge>> =
    LazyLock::new(|| try_create_int_gauge("jemalloc_bytes_active", "Equivalent to stats.active"));
pub static BYTES_MAPPED: LazyLock<metrics::Result<IntGauge>> =
    LazyLock::new(|| try_create_int_gauge("jemalloc_bytes_mapped", "Equivalent to stats.mapped"));
pub static BYTES_METADATA: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("jemalloc_bytes_metadata", "Equivalent to stats.metadata")
});
pub static BYTES_RESIDENT: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("jemalloc_bytes_resident", "Equivalent to stats.resident")
});
pub static BYTES_RETAINED: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("jemalloc_bytes_retained", "Equivalent to stats.retained")
});
pub static NUM_ALLOCATIONS: LazyLock<metrics::Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "jemalloc_num_allocations",
        "Equivalent to stats.nmalloc",
        &["arena"],
    )
});
pub static NUM_DEALLOCATIONS: LazyLock<metrics::Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "jemalloc_num_deallocations",
        "Equivalent to stats.ndalloc",
        &["arena"],
    )
});

pub fn scrape_jemalloc_metrics() {
    scrape_jemalloc_metrics_fallible().unwrap()
}

pub fn scrape_jemalloc_metrics_fallible() -> Result<(), Error> {
    // Advance the epoch so that the underlying statistics are updated.
    epoch::advance()?;

    let num_arenas = arenas::narenas::read()?;
    set_gauge(&NUM_ARENAS, num_arenas as i64);
    set_gauge(&BYTES_ALLOCATED, stats::allocated::read()? as i64);
    set_gauge(&BYTES_ACTIVE, stats::active::read()? as i64);
    set_gauge(&BYTES_MAPPED, stats::mapped::read()? as i64);
    set_gauge(&BYTES_METADATA, stats::metadata::read()? as i64);
    set_gauge(&BYTES_RESIDENT, stats::resident::read()? as i64);
    set_gauge(&BYTES_RETAINED, stats::retained::read()? as i64);

    for arena in 0..num_arenas {
        unsafe {
            let nmalloc_req = format!("stats.arenas.{arena}.small.nmalloc");
            if let Ok(nmalloc) = raw::read::<usize>(nmalloc_req.as_bytes()) {
                set_gauge_vec(
                    &NUM_ALLOCATIONS,
                    &[&format!("arena_{arena}")],
                    nmalloc as i64,
                );
            }

            let ndalloc_req = format!("stats.arenas.{arena}.small.ndalloc");
            if let Ok(ndalloc) = raw::read::<usize>(ndalloc_req.as_bytes()) {
                set_gauge_vec(
                    &NUM_DEALLOCATIONS,
                    &[&format!("arena_{arena}")],
                    ndalloc as i64,
                );
            }
        }
    }

    Ok(())
}

pub fn page_size() -> Result<usize, Error> {
    // Full list of keys: https://jemalloc.net/jemalloc.3.html
    "arenas.page\0".name().read()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn page_size_ok() {
        assert!(page_size().is_ok());
    }
}
