# CVEdb

Downloads, stores, and searches CVE data from the [National Vulnerability Database](https://nvd.nist.gov/vuln/data-feeds).

**⚠️ This is the Rust version.** The original Python implementation has been superseded. All users should use the Rust binary.

## Features

- Search CVEs by keyword, date range, vendor, or software version
- Colorized terminal output with severity badges
- Incremental database updates via the NVD REST API 2.0
- SQLite-backed storage with WAL mode for concurrent access
- Full CVE database (~350K CVEs) downloaded on first update

## Installation

```console
$ cargo build --release
$ cp target/release/cvedb ~/bin/
```

Or run directly from the project directory:

```console
$ cargo run --release -- --help
```

## Usage

```console
$ cvedb --help
```

Search by keyword:

```console
$ cvedb heartbleed
$ cvedb log4j
```

Filter by date:

```console
$ cvedb --after 2021-01-01 --before 2021-12-31 log4j
```

Search by vendor or software version:

```console
$ cvedb --vendor apache
$ cvedb --vendor apache --software-version 2.4.0
```

Update the database:

```console
$ NVD_API_KEY=your-key cvedb --update
```

Show feed status:

```console
$ cvedb --data-version
```

## NVD API Key

An NVD API key is strongly recommended. Without one, the full fetch is rate-limited to a crawl.

- **With API key**: 2,000 results per page, higher rate limits (full fetch ~1-2 minutes)
- **Without API key**: 50 results per page, 5 requests per 30 seconds (full fetch ~6+ hours)

Get a free API key at [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

Set it via the `NVD_API_KEY` environment variable:

```console
$ export NVD_API_KEY=your-api-key-here
$ cvedb --update
```

## Database

The database is stored at `~/.config/cvedb/cvedb.sqlite` by default. Delete it and re-run `cvedb --update` to start fresh.
