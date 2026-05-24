use std::path::PathBuf;

use clap::Parser;

mod cve;
mod db;
mod nvd;
mod printing;
mod search;

#[derive(Parser)]
#[command(name = "cvedb", about = "A Common Vulnerabilities and Exposures (CVE) database")]
struct Cli {
    /// search terms to query
    search_term: Vec<String>,

    /// update the database to the latest version; this requires an Internet connection and NVD API key
    #[arg(short = 'u', long)]
    update: bool,

    /// alternative path to load/store the database
    #[arg(short = 'D', long = "database")]
    database: Option<String>,

    /// how to sort the results
    #[arg(short = 's', long, num_args(0..), default_values = &["cve"])]
    sort: Vec<String>,

    /// reverse the ordering of results
    #[arg(short = 'd', long)]
    descending: bool,

    /// only list CVEs published after the given date
    #[arg(short = 'a', long)]
    after: Option<String>,

    /// only list CVEs published before the given date
    #[arg(short = 'b', long)]
    before: Option<String>,

    /// only list CVEs modified after the given date
    #[arg(long = "modified-after")]
    modified_after: Option<String>,

    /// only list CVEs modified before the given date
    #[arg(long = "modified-before")]
    modified_before: Option<String>,

    /// search by software/hardware vendor
    #[arg(long)]
    vendor: Option<String>,

    /// search by version
    #[arg(long = "software-version")]
    software_version: Option<String>,

    /// output full results as JSON
    #[arg(long)]
    json: bool,

    /// force ANSI colored output
    #[arg(long)]
    ansi: bool,

    /// print the version and exit
    #[arg(short = 'v', long)]
    version: bool,

    /// print the version of each of the CVE data feeds and exit
    #[arg(long = "data-version")]
    data_version: bool,
}

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config").join("cvedb").join("cvedb.sqlite")
}

fn parse_date(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    // Try ISO 8601 first
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    // Try just a year
    if s.len() == 4 && s.chars().all(|c| c.is_ascii_digit()) {
        let year: i32 = s.parse().map_err(|_| format!("invalid year: {}", s))?;
        let dt = chrono::NaiveDate::from_ymd_opt(year, 1, 1)
            .ok_or_else(|| format!("invalid year: {}", s))?
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        return Ok(dt);
    }
    // Try YYYY-MM-DD
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(d.and_hms_opt(0, 0, 0).unwrap().and_utc());
    }
    // Try dateutil-style ISO (e.g. "2021-01-01T00:00:00")
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(dt.and_utc());
    }
    Err(format!("invalid date: {}. Use YYYY-MM-DD or ISO 8601.", s))
}

fn main() {
    let cli = Cli::parse();

    if cli.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let db_path = match &cli.database {
        Some(p) => PathBuf::from(p),
        None => default_db_path(),
    };

    // Handle update
    if cli.update {
        match update_database(&db_path) {
            Ok(count) => {
                if count > 0 {
                    eprintln!("Updated {} CVEs", count);
                } else {
                    eprintln!("Database is up to date.");
                }
            }
            Err(e) => {
                eprintln!("Update failed: {}", e);
                std::process::exit(1);
            }
        }
        if cli.search_term.is_empty() && !cli.data_version {
            return;
        }
    }

    // Open database
    let database = match db::Database::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };

    // Handle --data-version
    if cli.data_version {
        if let Err(e) = printing::print_data_version(&database) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        if cli.search_term.is_empty() {
            return;
        }
    }

    // Check if DB has data
    let feeds = match database.feeds() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error reading feeds: {}", e);
            std::process::exit(1);
        }
    };

    let feed_ids: Vec<i64> = feeds.iter().map(|f| f.rowid).collect();
    if feed_ids.is_empty() {
        eprintln!("No CVE data found. Run with --update to download data (requires NVD API key).");
        std::process::exit(1);
    }

    // Build search query
    let mut query_parts: Vec<search::SearchQuery> = Vec::new();

    // Search terms
    for term in &cli.search_term {
        query_parts.push(search::SearchQuery::Term {
            query: term.clone(),
            case_sensitive: false,
        });
    }

    // Date filters
    if let Some(ref date_str) = cli.after {
        match parse_date(date_str) {
            Ok(dt) => query_parts.push(search::SearchQuery::AfterDate {
                field: search::DateField::Published,
                date: dt,
            }),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(ref date_str) = cli.before {
        match parse_date(date_str) {
            Ok(dt) => query_parts.push(search::SearchQuery::BeforeDate {
                field: search::DateField::Published,
                date: dt,
            }),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(ref date_str) = cli.modified_after {
        match parse_date(date_str) {
            Ok(dt) => query_parts.push(search::SearchQuery::AfterDate {
                field: search::DateField::LastModified,
                date: dt,
            }),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(ref date_str) = cli.modified_before {
        match parse_date(date_str) {
            Ok(dt) => query_parts.push(search::SearchQuery::BeforeDate {
                field: search::DateField::LastModified,
                date: dt,
            }),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    // CPE filters
    if cli.vendor.is_some() || cli.software_version.is_some() {
        let cpe = cve::CPE {
            part: None,
            vendor: cli.vendor.clone(),
            product: None,
            version: cli.software_version.clone(),
            update: None,
            edition: None,
            lang: None,
            sw_edition: None,
            target_sw: None,
            target_hw: None,
            other: None,
        };
        query_parts.push(search::SearchQuery::CPE { cpe });
    }

    // Build final query
    let query = if query_parts.is_empty() {
        None
    } else if query_parts.len() == 1 {
        Some(query_parts.into_iter().next().unwrap())
    } else {
        Some(search::SearchQuery::And(query_parts))
    };

    // Parse sort options
    let sorts: Vec<search::Sort> = cli.sort.iter()
        .filter_map(|s| search::Sort::from_name(s))
        .collect();

    // Search
    let cves = if let Some(ref q) = query {
        match database.search_cves(q, &sorts, !cli.descending, &feed_ids, 10000) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Search error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // No query - return all
        let term = search::SearchQuery::Term {
            query: "".to_string(),
            case_sensitive: false,
        };
        match database.search_cves(&term, &sorts, !cli.descending, &feed_ids, 10000) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Search error: {}", e);
                std::process::exit(1);
            }
        }
    };

    // Filter results that don't match in SQL
    let filtered: Vec<cve::CVE> = if let Some(ref q) = query {
        cves.into_iter().filter(|c| q.matches(c)).collect()
    } else {
        cves
    };

    // Print
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
    } else {
        let force_color = cli.ansi || std::env::var("FORCE_COLOR").is_ok();
        printing::print_cves_colored(&filtered, force_color);
    }
}

fn update_database(db_path: &PathBuf) -> Result<usize, String> {
    let api_key = std::env::var("NVD_API_KEY").ok();
    let has_key = api_key.is_some();
    let api = nvd::NvdApi::new(api_key.as_deref().unwrap_or(""));

    let database = db::Database::open(db_path)?;
    let feed_id = database.get_or_create_feed("NVD")?;

    // Check if the NVD feed has been updated before
    let feeds = database.feeds()?;
    let nvd_last_modified = feeds.iter()
        .find(|f| f.name == "NVD")
        .and_then(|f| f.last_modified);

    eprintln!("Fetching CVEs from NVD...");
    let max_per_page = if has_key { 1000 } else { 50 };
    let mut total = 0usize;

    if let Some(last_mod) = nvd_last_modified {
        // Incremental: walk 120-day windows from last_modified to now
        // Incremental: walk 120-day windows from last_modified to now
        let start = chrono::DateTime::from_timestamp(last_mod as i64, 0)
            .unwrap_or_default();
        let now = chrono::Utc::now();
        let mut window_start = start;

        loop {
            let mut window_end = window_start + chrono::Duration::days(119);
            if window_end > now {
                window_end = now;
            }

            let mut start_index = 0;
            loop {
                let cves = api.fetch_cves(Some(window_start), Some(window_end), start_index, max_per_page)?;
                let count = cves.len();
                if count == 0 {
                    break;
                }
                database.insert_cves(feed_id, &cves)?;
                total += count;
                eprintln!("  {} -> {}: stored {} CVEs (total: {})",
                    window_start.format("%Y-%m-%d"), window_end.format("%Y-%m-%d"), count, total);
                if count < max_per_page as usize {
                    break;
                }
                start_index += max_per_page;
                if !has_key {
                    std::thread::sleep(std::time::Duration::from_secs(6));
                }
            }

            if window_end >= now {
                break;
            }
            window_start = window_end;
            if !has_key {
                std::thread::sleep(std::time::Duration::from_secs(6));
            }
        }
    } else {
        // Full fetch: no date filters, paginate by startIndex
        let mut start_index = 0;
        loop {
            let cves = api.fetch_cves(None, None, start_index, max_per_page)?;
            let count = cves.len();
            if count == 0 {
                break;
            }
            database.insert_cves(feed_id, &cves)?;
            total += count;
            eprintln!("  ... stored {} CVEs (total: {})", count, total);

            if count < max_per_page as usize {
                break;
            }
            start_index += max_per_page;
            if !has_key {
                std::thread::sleep(std::time::Duration::from_secs(6));
            }
        }
    }

    // Update feed's last_modified for incremental updates
    if total > 0 || nvd_last_modified.is_none() {
        let now = chrono::Utc::now().timestamp() as f64;
        database.update_feed_last_modified(feed_id, now)?;
    }

    if total > 0 {
        eprintln!("Done. Stored {} CVEs.", total);
    } else {
        eprintln!("Database is up to date.");
    }
    Ok(total)
}
