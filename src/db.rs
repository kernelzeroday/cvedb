use rusqlite::{Connection, params};
use std::path::PathBuf;

use crate::cve::*;

pub struct Database {
    conn: Connection,
}

pub struct FeedInfo {
    pub rowid: i64,
    pub name: String,
    pub last_modified: Option<f64>,
    pub last_checked: Option<f64>,
}

impl Database {
    pub fn open(path: &PathBuf) -> Result<Self, String> {
        // Create parent directory if it doesn't exist (matching Python behavior)
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create database directory: {}", e))?;
        }
        let conn = Connection::open(path).map_err(|e| format!("failed to open database: {}", e))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .map_err(|e| format!("failed to set pragmas: {}", e))?;
        let db = Database { conn };
        db.check_schema()?;
        Ok(db)
    }

    fn check_schema(&self) -> Result<(), String> {
        let version: i64 = self.conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|e| format!("failed to read schema version: {}", e))?;
        if version > 2 {
            return Err(format!("unsupported database schema version: {}", version));
        }

        if version < 2 {
            // Ensure feeds table exists
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS feeds (name TEXT NOT NULL UNIQUE, last_modified REAL, last_checked REAL);"
            ).map_err(|e| e.to_string())?;

            // Check if cves table already exists (old Python schema with FK)
            let has_cves: bool = self.conn
                .prepare("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='cves'")
                .and_then(|mut s| s.query_row([], |r| r.get::<_, i64>(0)))
                .map(|c| c > 0)
                .unwrap_or(false);

            if has_cves {
                // Check if the old cves table has FK constraints; if so, recreate
                let has_fk: bool = self.conn
                    .prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='cves'")
                    .and_then(|mut s| s.query_row([], |r| r.get::<_, String>(0)))
                    .map(|sql| sql.contains("REFERENCES"))
                    .unwrap_or(false);

                if has_fk {
                    self.conn.execute_batch(
                        "DROP TABLE IF EXISTS cves_v2;
                         CREATE TABLE cves_v2 (
                             id TEXT NOT NULL,
                             feed INTEGER NOT NULL,
                             published INTEGER NOT NULL,
                             last_modified INTEGER NOT NULL,
                             impact_vector TEXT,
                             base_score REAL,
                             severity INTEGER NOT NULL,
                             configurations TEXT
                         );
                         INSERT INTO cves_v2 SELECT id, feed, published, last_modified, impact_vector, base_score, severity, configurations FROM cves;
                         DROP TABLE cves;
                         ALTER TABLE cves_v2 RENAME TO cves;
                         CREATE UNIQUE INDEX IF NOT EXISTS idx_cves_id ON cves(id);
                         CREATE INDEX IF NOT EXISTS idx_descriptions_cve ON descriptions(cve);
                         CREATE INDEX IF NOT EXISTS idx_refs_cve ON refs(cve);"
                    ).map_err(|e| e.to_string())?;
                } else {
                    // Existing table without FK — just create missing indexes
                    self.conn.execute_batch(
                        "CREATE UNIQUE INDEX IF NOT EXISTS idx_cves_id ON cves(id);
                         CREATE INDEX IF NOT EXISTS idx_descriptions_cve ON descriptions(cve);
                         CREATE INDEX IF NOT EXISTS idx_refs_cve ON refs(cve);"
                    ).map_err(|e| e.to_string())?;
                }
            } else {
                // New database — create all tables
                self.conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS cves (
                         id TEXT NOT NULL,
                         feed INTEGER NOT NULL,
                         published INTEGER NOT NULL,
                         last_modified INTEGER NOT NULL,
                         impact_vector TEXT,
                         base_score REAL,
                         severity INTEGER NOT NULL,
                         configurations TEXT
                     );
                     CREATE TABLE IF NOT EXISTS descriptions (
                         cve TEXT NOT NULL,
                         lang TEXT NOT NULL,
                         description TEXT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS refs (
                         cve TEXT NOT NULL,
                         url TEXT,
                         name TEXT
                     );
                     CREATE UNIQUE INDEX IF NOT EXISTS idx_cves_id ON cves(id);
                     CREATE INDEX IF NOT EXISTS idx_descriptions_cve ON descriptions(cve);
                     CREATE INDEX IF NOT EXISTS idx_refs_cve ON refs(cve);"
                ).map_err(|e| e.to_string())?;
            }

            self.conn.pragma_update(None, "user_version", 2)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn feeds(&self) -> Result<Vec<FeedInfo>, String> {
        let mut stmt = self.conn
            .prepare("SELECT rowid, name, last_modified, last_checked FROM feeds")
            .map_err(|e| e.to_string())?;
        let feeds = stmt.query_map([], |row| {
            Ok(FeedInfo {
                rowid: row.get(0)?,
                name: row.get(1)?,
                last_modified: row.get(2)?,
                last_checked: row.get(3)?,
            })
        }).map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
        Ok(feeds)
    }

    pub fn search_cves(
        &self,
        query: &crate::search::SearchQuery,
        sort: &[crate::search::Sort],
        ascending: bool,
        feed_ids: &[i64],
        limit: usize,
    ) -> Result<Vec<CVE>, String> {
        // Build WHERE clauses
        let mut conditions: Vec<String> = Vec::new();
        let mut sql_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        // Feed filter
        if !feed_ids.is_empty() {
            let placeholders: Vec<String> = feed_ids.iter().map(|_| "?".to_string()).collect();
            conditions.push(format!("c.feed IN ({})", placeholders.join(",")));
            for fid in feed_ids {
                sql_params.push(Box::new(*fid));
            }
        }

        // Build text search condition (handle Term inside And queries)
        fn extract_term_text(q: &crate::search::SearchQuery) -> Option<(&str, bool)> {
            match q {
                crate::search::SearchQuery::Term { query, case_sensitive } => Some((query.as_str(), *case_sensitive)),
                crate::search::SearchQuery::And(queries) => {
                    for sub in queries {
                        if let Some(r) = extract_term_text(sub) {
                            return Some(r);
                        }
                    }
                    None
                }
                _ => None,
            }
        }
        if let Some((term_text, case_sensitive)) = extract_term_text(query) {
            let like_op = if case_sensitive { "LIKE" } else { "LIKE" };
            let q = format!("%{}%", term_text);
            conditions.push(format!(
                "(d.description {} ? OR c.id {} ?)",
                like_op, like_op
            ));
            sql_params.push(Box::new(q.clone()));
            sql_params.push(Box::new(q));
        }

        // Date conditions
        add_date_condition(query, &mut conditions, &mut sql_params);

        // Build ORDER BY
        let order_dir = if ascending { "ASC" } else { "DESC" };
        let mut order_parts: Vec<String> = Vec::new();
        for s in sort {
            let col = match s {
                crate::search::Sort::CVEId => "c.id",
                crate::search::Sort::PublishedDate => "c.published",
                crate::search::Sort::LastModifiedDate => "c.last_modified",
                crate::search::Sort::Impact => "c.base_score",
                crate::search::Sort::Severity => "c.severity",
            };
            order_parts.push(format!("{} {}", col, order_dir));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let order_clause = if order_parts.is_empty() {
            String::from("ORDER BY c.id ASC")
        } else {
            format!("ORDER BY {}", order_parts.join(", "))
        };

        let sql = format!(
            "SELECT DISTINCT c.id, c.feed, c.published, c.last_modified, c.impact_vector, c.base_score, c.severity, c.configurations FROM descriptions d INNER JOIN cves c ON d.cve = c.id {} {} LIMIT ?",
            where_clause, order_clause
        );
        sql_params.push(Box::new(limit as i64));

        let mut stmt = self.conn.prepare(&sql).map_err(|e| e.to_string())?;

        let params_refs: Vec<&dyn rusqlite::types::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let cve_id: String = row.get(0)?;
            let feed: i64 = row.get(1)?;
            let published_ts: i64 = row.get(2)?;
            let modified_ts: i64 = row.get(3)?;
            let impact_vector: Option<String> = row.get(4)?;
            let base_score: Option<f64> = row.get(5)?;
            let severity_int: i64 = row.get(6)?;
            let configurations_str: Option<String> = row.get(7)?;
            Ok((
                cve_id, feed, published_ts, modified_ts, impact_vector,
                base_score, severity_int, configurations_str,
            ))
        }).map_err(|e| e.to_string())?;

        let mut raw: Vec<(String, i64, i64, i64, Option<String>, Option<f64>, i64, Option<String>)> = Vec::new();
        for row in rows {
            raw.push(row.map_err(|e| e.to_string())?);
        }

        // Collect CVE IDs
        let cve_ids: Vec<String> = raw.iter().map(|r| r.0.clone()).collect();

        // Batch fetch descriptions
        let mut desc_map: std::collections::HashMap<String, Vec<Description>> = std::collections::HashMap::new();
        if !cve_ids.is_empty() {
            let placeholders: Vec<String> = cve_ids.iter().map(|_| "?".to_string()).collect();
            let desc_sql = format!("SELECT cve, lang, description FROM descriptions WHERE cve IN ({})", placeholders.join(","));
            let mut desc_stmt = self.conn.prepare(&desc_sql).map_err(|e| e.to_string())?;
            let desc_params: Vec<&dyn rusqlite::types::ToSql> = cve_ids.iter().map(|id| id as &dyn rusqlite::types::ToSql).collect();
            let desc_rows = desc_stmt.query_map(desc_params.as_slice(), |r| {
                let cve: String = r.get(0)?;
                let lang: String = r.get(1)?;
                let value: String = r.get(2)?;
                Ok((cve, Description { lang, value }))
            }).map_err(|e| e.to_string())?;
            for row in desc_rows {
                if let Ok((cve, desc)) = row {
                    desc_map.entry(cve).or_default().push(desc);
                }
            }
        }

        // Batch fetch references
        let mut ref_map: std::collections::HashMap<String, Vec<Reference>> = std::collections::HashMap::new();
        if !cve_ids.is_empty() {
            let placeholders: Vec<String> = cve_ids.iter().map(|_| "?".to_string()).collect();
            let ref_sql = format!("SELECT cve, url, name FROM refs WHERE cve IN ({})", placeholders.join(","));
            let mut ref_stmt = self.conn.prepare(&ref_sql).map_err(|e| e.to_string())?;
            let ref_params: Vec<&dyn rusqlite::types::ToSql> = cve_ids.iter().map(|id| id as &dyn rusqlite::types::ToSql).collect();
            let ref_rows = ref_stmt.query_map(ref_params.as_slice(), |r| {
                let cve: String = r.get(0)?;
                let url: Option<String> = r.get(1)?;
                let name: Option<String> = r.get(2)?;
                Ok((cve, Reference { url, name }))
            }).map_err(|e| e.to_string())?;
            for row in ref_rows {
                if let Ok((cve, reference)) = row {
                    ref_map.entry(cve).or_default().push(reference);
                }
            }
        }

        let mut cves = Vec::new();
        for (cve_id, feed, published_ts, modified_ts, impact_vector,
             base_score, severity_int, configurations_str) in raw {
            let descriptions = desc_map.remove(&cve_id).unwrap_or_default();
            let references = ref_map.remove(&cve_id).unwrap_or_default();

            // Parse configurations
            let configurations = if let Some(ref s) = configurations_str {
                parse_configurations(s).unwrap_or_default()
            } else {
                Vec::new()
            };

            let severity = Severity::from_int(severity_int);

            let published = chrono::DateTime::from_timestamp(published_ts, 0)
                .unwrap_or_default();
            let last_modified = chrono::DateTime::from_timestamp(modified_ts, 0)
                .unwrap_or_default();

            cves.push(CVE {
                cve_id,
                feed,
                published,
                last_modified,
                impact_vector,
                base_score,
                severity,
                descriptions,
                references,
                configurations,
                assigner: None,
            });
        }

        Ok(cves)
    }

    pub fn count_cves(&self, feed_ids: &[i64]) -> Result<i64, String> {
        let placeholders: Vec<String> = feed_ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "SELECT COUNT(*) FROM cves WHERE feed IN ({})",
            placeholders.join(",")
        );
        let params_refs: Vec<&dyn rusqlite::types::ToSql> = feed_ids
            .iter()
            .map(|f| f as &dyn rusqlite::types::ToSql)
            .collect();
        self.conn
            .query_row(&sql, params_refs.as_slice(), |row| row.get(0))
            .map_err(|e| e.to_string())
    }

    #[allow(dead_code)]
    pub fn update_last_checked(&self, feed_id: i64) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp() as f64;
        self.conn
            .execute(
                "UPDATE feeds SET last_checked = ? WHERE rowid = ?",
                params![now, feed_id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_or_create_feed(&self, name: &str) -> Result<i64, String> {
        // Try to find existing feed
        let existing: Option<i64> = self.conn
            .query_row(
                "SELECT rowid FROM feeds WHERE name = ?",
                params![name],
                |row| row.get(0),
            )
            .ok();
        if let Some(id) = existing {
            return Ok(id);
        }
        // Create new feed
        self.conn
            .execute("INSERT INTO feeds (name) VALUES (?)", params![name])
            .map_err(|e| e.to_string())?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn insert_cves(&self, feed_id: i64, cves: &[CVE]) -> Result<(), String> {
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| e.to_string())?;
        for cve in cves {
            let config_str = crate::cve::serialize_configurations(&cve.configurations);
            tx.execute(
                "INSERT OR REPLACE INTO cves (id, feed, published, last_modified, impact_vector, base_score, severity, configurations) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    cve.cve_id,
                    feed_id,
                    cve.published.timestamp(),
                    cve.last_modified.timestamp(),
                    cve.impact_vector,
                    cve.base_score,
                    cve.severity as i64,
                    config_str,
                ],
            ).map_err(|e| format!("failed to insert CVE {}: {}", cve.cve_id, e))?;

            tx.execute("DELETE FROM descriptions WHERE cve = ?", params![cve.cve_id])
                .map_err(|e| e.to_string())?;
            for desc in &cve.descriptions {
                tx.execute(
                    "INSERT INTO descriptions (cve, lang, description) VALUES (?1, ?2, ?3)",
                    params![cve.cve_id, desc.lang, desc.value],
                ).map_err(|e| e.to_string())?;
            }

            tx.execute("DELETE FROM refs WHERE cve = ?", params![cve.cve_id])
                .map_err(|e| e.to_string())?;
            for r in &cve.references {
                tx.execute(
                    "INSERT INTO refs (cve, url, name) VALUES (?1, ?2, ?3)",
                    params![cve.cve_id, r.url, r.name],
                ).map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn update_feed_last_modified(&self, feed_id: i64, ts: f64) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE feeds SET last_modified = ? WHERE rowid = ?",
                params![ts, feed_id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn add_date_condition(
    query: &crate::search::SearchQuery,
    conditions: &mut Vec<String>,
    params: &mut Vec<Box<dyn rusqlite::types::ToSql>>,
) {
    match query {
        crate::search::SearchQuery::BeforeDate { field, date } => {
            let col = match field {
                crate::search::DateField::Published => "c.published",
                crate::search::DateField::LastModified => "c.last_modified",
            };
            conditions.push(format!("{} <= ?", col));
            params.push(Box::new(date.timestamp()));
        }
        crate::search::SearchQuery::AfterDate { field, date } => {
            let col = match field {
                crate::search::DateField::Published => "c.published",
                crate::search::DateField::LastModified => "c.last_modified",
            };
            conditions.push(format!("{} >= ?", col));
            params.push(Box::new(date.timestamp()));
        }
        crate::search::SearchQuery::And(queries) => {
            for q in queries {
                add_date_condition(q, conditions, params);
            }
        }
        _ => {}
    }
}
