use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use std::io::Write;

use crate::cve::*;

pub fn print_cves_colored(cves: &[CVE], force_color: bool) {
    let choice = if force_color {
        ColorChoice::Always
    } else {
        ColorChoice::Auto
    };
    let mut stdout = StandardStream::stdout(choice);

    for cve in cves {
        if let Err(e) = print_one(&mut stdout, cve) {
            eprintln!("write error: {}", e);
            break;
        }
    }
}

fn print_one<W: WriteColor + Write>(w: &mut W, cve: &CVE) -> Result<(), std::io::Error> {
    // CVE ID
    w.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
    write!(w, "{}", cve.cve_id)?;
    w.reset()?;
    write!(w, "\t")?;

    // Description
    if let Some(desc) = cve.description_en() {
        if let Some(first_line) = desc.lines().next() {
            w.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;
            write!(w, "{}", first_line)?;
            w.reset()?;
        }
    }

    // Severity badge
    write!(w, "\t[")?;
    let (sev_color, label) = match cve.severity {
        Severity::Critical => (Color::Red, "CRITICAL"),
        Severity::High => (Color::Red, "HIGH"),
        Severity::Medium => (Color::Yellow, "MEDIUM"),
        Severity::Low => (Color::Green, "LOW"),
        Severity::None => (Color::Cyan, "NONE"),
        Severity::Unknown => (Color::Cyan, "UNKNOWN"),
    };
    w.set_color(ColorSpec::new().set_fg(Some(sev_color)).set_bold(true))?;
    write!(w, "{}", label)?;
    w.reset()?;
    if let Some(score) = cve.base_score {
        write!(w, " ({:.1})", score)?;
    }
    writeln!(w, "]")?;

    Ok(())
}

pub fn print_data_version(db: &crate::db::Database) -> Result<(), String> {
    let feeds = db.feeds()?;

    // Header
    println!("+======================================+");
    println!("|Database: {}|", "cvedb.sqlite");
    println!("+======================================+");

    // Column headers
    println!("|{:<12}|{:<16}|{:<16}|{:<8}|", "Feed", "Last Modified", "Last Checked", "# CVEs");
    println!("+======================================+");

    for feed in &feeds {
        let lm = feed.last_modified
            .and_then(|ts| {
                if ts == 0.0 { return None; }
                chrono::DateTime::from_timestamp(ts as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
            })
            .unwrap_or_else(|| "never".to_string());

        let lc = feed.last_checked
            .and_then(|ts| {
                if ts == 0.0 { return None; }
                chrono::DateTime::from_timestamp(ts as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
            })
            .unwrap_or_else(|| "never".to_string());

        let count: i64 = db.count_cves(&[feed.rowid]).unwrap_or(0);

        println!("|{:<12}|{:<16}|{:<16}|{:<8}|", feed.name, lm, lc, count);
    }

    println!("+======================================+");
    Ok(())
}
