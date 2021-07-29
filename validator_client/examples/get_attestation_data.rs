use eth2::{reqwest::ClientBuilder, types::BlockId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use std::time::{Duration, Instant};

/// Specific timeout constants for HTTP requests involved in different validator duties.
/// This can help ensure that proper endpoint fallback occurs.
const HTTP_ATTESTATION_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_ATTESTER_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_PROPOSAL_TIMEOUT_QUOTIENT: u32 = 2;
const HTTP_PROPOSER_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;

#[async_std::main]
async fn main() -> std::io::Result<()> {
    let slot_duration = Duration::from_secs(12);

    let beacon_node_http_client = ClientBuilder::new()
        // Set default timeout to be the full slot duration.
        .timeout(slot_duration)
        .build()
        .unwrap();

    let timeouts = Timeouts {
        attestation: slot_duration / HTTP_ATTESTATION_TIMEOUT_QUOTIENT,
        attester_duties: slot_duration / HTTP_ATTESTER_DUTIES_TIMEOUT_QUOTIENT,
        proposal: slot_duration / HTTP_PROPOSAL_TIMEOUT_QUOTIENT,
        proposer_duties: slot_duration / HTTP_PROPOSER_DUTIES_TIMEOUT_QUOTIENT,
    };

    let url = SensitiveUrl::parse("http://localhost:5052").unwrap();
    let beacon_node =
        BeaconNodeHttpClient::from_components(url.clone(), beacon_node_http_client, timeouts);

    let slot = beacon_node
        .get_beacon_headers_block_id(BlockId::Head)
        .await
        .unwrap()
        .unwrap()
        .data
        .header
        .message
        .slot;

    let committee_index = 0;

    let attestation_data_start = Instant::now();

    let _response = beacon_node
        .get_validator_attestation_data(slot, committee_index)
        .await
        .map(|result| result.data)
        .unwrap();

    dbg!(Instant::now().duration_since(attestation_data_start));

    Ok(())
}
