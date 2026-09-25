//! Synthetic Network 10.6.106 system-log pages for loopback fixtures.

pub const ROUTE: &str = "/proxy/network/v2/api/site/default/system-log/all";

pub fn page(data: serde_json::Value, total: u64) -> serde_json::Value {
    let size = data.as_array().expect("fixture array").len() as u64;
    let mut page = serde_json::json!({
        "page_number": 0,
        "total_element_count": total,
        "total_page_count": total.div_ceil(size.max(1)),
    });
    page["data"] = data;
    page
}
