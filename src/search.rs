use chrono::{DateTime, Utc};

use crate::cve::{CPE, CVE};

pub enum Sort {
    CVEId,
    PublishedDate,
    LastModifiedDate,
    Impact,
    Severity,
}

impl Sort {
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "cve" => Some(Sort::CVEId),
            "modified" => Some(Sort::LastModifiedDate),
            "published" => Some(Sort::PublishedDate),
            "impact" => Some(Sort::Impact),
            "severity" => Some(Sort::Severity),
            _ => None,
        }
    }
}

pub enum SearchQuery {
    Term {
        query: String,
        case_sensitive: bool,
    },
    BeforeDate {
        field: DateField,
        date: DateTime<Utc>,
    },
    AfterDate {
        field: DateField,
        date: DateTime<Utc>,
    },
    CPE {
        cpe: CPE,
    },
    And(Vec<SearchQuery>),
}

pub enum DateField {
    Published,
    LastModified,
}

impl SearchQuery {
    pub fn matches(&self, cve: &CVE) -> bool {
        match self {
            SearchQuery::Term { query, case_sensitive } => {
                let q = if *case_sensitive { query.clone() } else { query.to_lowercase() };
                for d in &cve.descriptions {
                    let v = if *case_sensitive { d.value.clone() } else { d.value.to_lowercase() };
                    if v.contains(&q) {
                        return true;
                    }
                }
                let id = if *case_sensitive { cve.cve_id.clone() } else { cve.cve_id.to_lowercase() };
                if id.contains(&q) {
                    return true;
                }
                for r in &cve.references {
                    if let Some(ref name) = r.name {
                        let n = if *case_sensitive { name.clone() } else { name.to_lowercase() };
                        if n.contains(&q) {
                            return true;
                        }
                    }
                    if let Some(ref url) = r.url {
                        let u = if *case_sensitive { url.clone() } else { url.to_lowercase() };
                        if u.contains(&q) {
                            return true;
                        }
                    }
                }
                if let Some(ref a) = cve.assigner {
                    if a.contains(&q) {
                        return true;
                    }
                }
                false
            }
            SearchQuery::BeforeDate { field, date } => {
                let dt = match field {
                    DateField::Published => &cve.published,
                    DateField::LastModified => &cve.last_modified,
                };
                dt.date_naive() <= date.date_naive()
            }
            SearchQuery::AfterDate { field, date } => {
                let dt = match field {
                    DateField::Published => &cve.published,
                    DateField::LastModified => &cve.last_modified,
                };
                dt >= date
            }
            SearchQuery::CPE { cpe } => {
                for config in &cve.configurations {
                    if config.matches(cpe) {
                        return true;
                    }
                }
                false
            }
            SearchQuery::And(queries) => queries.iter().all(|q| q.matches(cve)),
        }
    }
}
