/// Synthetic Octopus dataset and end-to-end demo scenarios
///
/// Provides a statistically faithful set of mock transactions derived
/// from publicly available MTR ridership and Octopus usage patterns,
/// and orchestrates the four urban coordination scenarios from the paper.

use chrono::{DateTime, TimeZone, Utc};
use crate::types::*;

/// Build a synthetic Octopus transaction history for March 2026.
/// Represents a typical Kowloon resident commuting to work via MTR.
pub fn synthetic_transactions_march_2026() -> Vec<OctopusTransaction> {
    // Weekday morning commutes (MTR Kowloon Tong → Wan Chai ≈ HKD 9.50)
    let weekday_commutes: Vec<OctopusTransaction> = vec![
        // Week 1
        tx("2026-03-02 08:12", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-02 18:44", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-03 08:09", "MTR Mong Kok",        -800, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-03 18:55", "MTR Mong Kok",        -800, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-04 07:55", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-04 19:02", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-05 08:05", "MTR Prince Edward",   -750, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-05 18:38", "MTR Prince Edward",   -750, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-06 08:10", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-06 18:51", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        // Week 2
        tx("2026-03-09 08:14", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-09 18:43", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-10 08:08", "MTR Mong Kok",        -800, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-11 07:58", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-12 08:03", "MTR Prince Edward",   -750, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-13 08:11", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        // Week 3
        tx("2026-03-16 08:07", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-17 08:15", "MTR Mong Kok",        -800, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-18 08:00", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-19 07:52", "MTR Prince Edward",   -750, TransactionCategory::Transit,      Zone::Kowloon),
        tx("2026-03-20 08:09", "MTR Kowloon Tong",   -950, TransactionCategory::Transit,      Zone::Kowloon),
        // Retail
        tx("2026-03-04 12:30", "7-Eleven (Mong Kok)",  -2350, TransactionCategory::Retail,    Zone::Kowloon),
        tx("2026-03-07 14:15", "PARKnSHOP (KLN)",     -38800, TransactionCategory::Retail,   Zone::Kowloon),
        tx("2026-03-11 13:00", "Wellcome (KLN)",       -22500, TransactionCategory::Retail,   Zone::Kowloon),
        tx("2026-03-14 11:30", "McDonald's (KLN)",     -5500, TransactionCategory::Retail,    Zone::Kowloon),
        tx("2026-03-21 15:00", "Watsons (KLN)",        -8900, TransactionCategory::Retail,    Zone::Kowloon),
        // Building access / management fees
        tx("2026-03-10 15:00", "Block A Lobby",       -30000, TransactionCategory::BuildingAccess, Zone::Kowloon),
        // Government services
        tx("2026-03-08 10:30", "Leisure & Cultural Services", -4000, TransactionCategory::GovernmentService, Zone::Kowloon),
    ];
    weekday_commutes
}

fn tx(
    ts:       &str,
    terminal: &str,
    cents:    i64,
    cat:      TransactionCategory,
    zone:     Zone,
) -> OctopusTransaction {
    let timestamp = parse_dt(ts);
    OctopusTransaction {
        timestamp,
        terminal_id:  terminal.to_string(),
        amount_cents: cents,
        category:     cat,
        zone,
    }
}

fn parse_dt(s: &str) -> DateTime<Utc> {
    // Parse "YYYY-MM-DD HH:MM" as UTC (HKT = UTC+8; mock uses UTC directly)
    let parts: Vec<&str> = s.split_whitespace().collect();
    let date_parts: Vec<u32> = parts[0].split('-').map(|p| p.parse().unwrap()).collect();
    let time_parts: Vec<u32> = parts[1].split(':').map(|p| p.parse().unwrap()).collect();
    Utc.with_ymd_and_hms(
        date_parts[0] as i32, date_parts[1], date_parts[2],
        time_parts[0], time_parts[1], 0,
    ).unwrap()
}

/// Print a summary table of transactions for the demo.
pub fn print_transaction_summary(txns: &[OctopusTransaction]) {
    let transit_count = txns.iter().filter(|t| t.category == TransactionCategory::Transit).count();
    let retail_total:   f64 = txns.iter().filter(|t| t.category == TransactionCategory::Retail)
        .map(|t| t.amount_cents.abs() as f64 / 100.0).sum();
    let mgmt_total:     f64 = txns.iter().filter(|t| t.category == TransactionCategory::BuildingAccess)
        .map(|t| t.amount_cents.abs() as f64 / 100.0).sum();
    let gov_count = txns.iter().filter(|t| t.category == TransactionCategory::GovernmentService).count();

    println!("\n┌─ Synthetic Transaction Summary (March 2026) ─────────────────");
    println!("│ Total transactions:    {}", txns.len());
    println!("│ Transit taps:          {transit_count}");
    println!("│ Retail spend:          HKD {retail_total:.2}");
    println!("│ Management fees:       HKD {mgmt_total:.2}");
    println!("│ Gov. service uses:     {gov_count}");
    println!("│");
    println!("│ PRIVATE — these records stay on the device and are NEVER");
    println!("│ transmitted to any verifier in plaintext under ZK-Octopus.");
    println!("└──────────────────────────────────────────────────────────────");
}
