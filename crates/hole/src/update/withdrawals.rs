//! Fetching the withdrawal list. Parsing and verifying it is [`hole_common::withdrawals`], which the
//! signing tool shares.

use super::error::UpdateError;
use super::verify::download_text;

use hole_common::withdrawals::parse_signed;

pub use hole_common::withdrawals::{Withdrawal, WithdrawalListError, Withdrawals};

/// Where the list lives. Shipped clients freeze this URL.
const LIST_URL: &str = "https://raw.githubusercontent.com/bindreams/hole/main/static/hole.yaml";

/// Fetch and verify the list. Blocking: call from `spawn_blocking`.
pub fn fetch_withdrawals() -> Result<Withdrawals, UpdateError> {
    fetch_withdrawals_at(LIST_URL)
}

/// [`fetch_withdrawals`] from `url`, verified with the shipped key: only a test names another URL.
fn fetch_withdrawals_at(url: &str) -> Result<Withdrawals, UpdateError> {
    let text = download_text(url)?;
    Ok(parse_signed(&text)?)
}

#[cfg(test)]
#[path = "withdrawals_tests.rs"]
mod withdrawals_tests;
