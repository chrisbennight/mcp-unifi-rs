use crate::{
    ApiError,
    traffic::{ActivityReport, ApplicationActivity},
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Default, Serialize)]
pub struct Bytes {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
#[derive(Serialize)]
pub struct ClientRow {
    pub mac: String,
    pub name: Option<String>,
    pub bytes: Bytes,
}
fn invalid(message: &str) -> ApiError {
    ApiError::Decode(message.into())
}
fn valid_mac(value: &str) -> bool {
    // The length is fixed, so it is checked first and nothing is allocated
    // from caller-controlled text: a long value is rejected on its length
    // rather than after being split apart.
    if value.len() != 17 {
        return false;
    }
    let mut octets = value.split(':');
    let mut first_byte = None;
    let mut all_zero = true;
    for index in 0..6 {
        let Some(octet) = octets.next() else {
            return false;
        };
        // The digits are checked before parsing rather than inferred from a
        // successful parse: the integer parser accepts a leading sign, so
        // `+2` would otherwise pass as a two-character octet.
        if octet.len() != 2 || !octet.chars().all(|digit| digit.is_ascii_hexdigit()) {
            return false;
        }
        let Ok(byte) = u8::from_str_radix(octet, 16) else {
            return false;
        };
        if index == 0 {
            first_byte = Some(byte);
        }
        all_zero &= byte == 0;
    }
    if octets.next().is_some() {
        return false;
    }
    // The low bit of the first octet marks a group address, and the all-zero
    // address is the placeholder a controller reports when it has none.
    // Neither names one client.
    first_byte.is_some_and(|byte| byte & 1 == 0) && !all_zero
}

/// Checked, complete client/application totals without display truncation.
/// # Errors
/// Rejects invalid identities, duplicate counters and arithmetic overflow.
pub fn activity_totals(
    report: &ActivityReport,
) -> Result<(Vec<ClientRow>, Bytes, Bytes), ApiError> {
    let mut seen = BTreeSet::new();
    let mut clients = Vec::new();
    let mut total = Bytes::default();
    for row in &report.client_usage_by_app {
        if row.usage_by_app.is_empty() {
            return Err(invalid("activity client has no reported counters"));
        }
        let mac = row.client.mac.trim().to_ascii_lowercase();
        if !valid_mac(&mac) || !seen.insert(mac.clone()) {
            return Err(invalid(
                "activity response contains invalid or duplicate client identities",
            ));
        }
        let bytes = sum(&row.usage_by_app)?;
        add(&mut total, &bytes)?;
        clients.push(ClientRow {
            mac,
            name: row.client.name.clone(),
            bytes,
        });
    }
    Ok((clients, total, sum(&report.total_usage_by_app)?))
}

fn sum(rows: &[ApplicationActivity]) -> Result<Bytes, ApiError> {
    let mut total = Bytes::default();
    let mut seen = BTreeSet::new();
    for row in rows {
        if !seen.insert((row.category, row.application)) {
            return Err(invalid(
                "activity response contains duplicate application counters",
            ));
        }
        add(
            &mut total,
            &Bytes {
                rx_bytes: row.bytes_received,
                tx_bytes: row.bytes_transmitted,
            },
        )?;
    }
    Ok(total)
}

fn add(total: &mut Bytes, value: &Bytes) -> Result<(), ApiError> {
    total.rx_bytes = total
        .rx_bytes
        .checked_add(value.rx_bytes)
        .ok_or_else(|| invalid("activity byte total overflow"))?;
    total.tx_bytes = total
        .tx_bytes
        .checked_add(value.tx_bytes)
        .ok_or_else(|| invalid("activity byte total overflow"))?;
    Ok(())
}
