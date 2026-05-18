use crate::cve::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::io::Read;

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

#[derive(serde::Deserialize, Debug)]
struct NvdResponse {
    vulnerabilities: Vec<NvdVulnerability>,
    #[serde(rename = "resultsPerPage")]
    #[allow(dead_code)]
    _results_per_page: i32,
    #[serde(rename = "startIndex")]
    #[allow(dead_code)]
    _start_index: i32,
    #[serde(rename = "totalResults")]
    #[allow(dead_code)]
    _total_results: i32,
    #[serde(rename = "format")]
    #[allow(dead_code)]
    _format: String,
    #[serde(rename = "timestamp")]
    _timestamp: String,
    #[serde(rename = "version")]
    _version: String,
}

#[derive(serde::Deserialize, Debug)]
struct NvdVulnerability {
    cve: NvdCveItem,
}

#[derive(serde::Deserialize, Debug)]
struct NvdCveItem {
    id: String,
    #[serde(rename = "sourceIdentifier")]
    source_identifier: Option<String>,
    published: String,
    #[serde(rename = "lastModified")]
    last_modified: String,
    #[serde(rename = "vulnStatus")]
    _vuln_status: Option<String>,
    descriptions: Option<Vec<NvdDescription>>,
    references: Option<Vec<NvdReference>>,
    metrics: Option<HashMap<String, Vec<NvdMetric>>>,
    configurations: Option<Vec<NvdConfiguration>>,
}

#[derive(serde::Deserialize, Debug)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(serde::Deserialize, Debug)]
struct NvdReference {
    url: Option<String>,
    source: Option<String>,
    #[allow(dead_code)]
    tags: Option<Vec<String>>,
    #[serde(rename = "refsource")]
    _refsource: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct NvdMetric {
    #[serde(rename = "cvssData")]
    cvss_data: Option<NvdCvssData>,
    #[allow(dead_code)]
    #[serde(rename = "baseScore")]
    base_score: Option<f64>,
    #[allow(dead_code)]
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct NvdCvssData {
    #[allow(dead_code)]
    version: Option<String>,
    vector_string: Option<String>,
    base_score: Option<f64>,
    #[serde(rename = "baseSeverity")]
    _base_severity: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct NvdConfiguration {
    #[serde(rename = "negate")]
    _negate: Option<bool>,
    nodes: Vec<NvdNode>,
}

#[derive(serde::Deserialize, Debug)]
struct NvdNode {
    operator: Option<String>,
    negate: Option<bool>,
    #[serde(rename = "cpeMatch")]
    cpe_match: Option<Vec<NvdCpeMatch>>,
}

#[derive(serde::Deserialize, Debug)]
struct NvdCpeMatch {
    vulnerable: Option<bool>,
    criteria: String,
    #[serde(rename = "matchCriteriaId")]
    _match_criteria_id: String,
    #[serde(rename = "versionStartIncluding")]
    version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
}

pub struct NvdApi {
    api_key: String,
    client: ureq::Agent,
}

impl NvdApi {
    pub fn new(api_key: &str) -> Self {
        let config = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(30))
            .build();
        NvdApi {
            api_key: api_key.to_string(),
            client: config,
        }
    }

    pub fn fetch_cves(
        &self,
        last_mod_start: Option<DateTime<Utc>>,
        last_mod_end: Option<DateTime<Utc>>,
        start_index: i32,
        results_per_page: i32,
    ) -> Result<Vec<CVE>, String> {
        let mut url = format!("{}?startIndex={}&resultsPerPage={}", NVD_API_BASE, start_index, results_per_page);

        let end = last_mod_end.or_else(|| {
            last_mod_start.map(|_| chrono::Utc::now())
        });
        if let Some(dt) = last_mod_start {
            url.push_str(&format!("&lastModStartDate={}Z", dt.format("%Y-%m-%dT%H:%M:%S%.3f")));
        }
        if let Some(dt) = end {
            url.push_str(&format!("&lastModEndDate={}Z", dt.format("%Y-%m-%dT%H:%M:%S%.3f")));
        }

        let mut req = self.client.get(&url);
        if !self.api_key.is_empty() {
            req = req.set("apiKey", &self.api_key);
        }
        let response = req
            .call()
            .map_err(|e| format!("NVD API request failed: {}", e))?;

        if response.status() != 200 {
            return Err(format!("NVD API returned HTTP {}", response.status()));
        }

        let mut reader = response.into_reader();
        let mut body = String::new();
        reader.read_to_string(&mut body)
            .map_err(|e| format!("failed to read response body: {}", e))?;

        let nvd_resp: NvdResponse = serde_json::from_str(&body)
            .map_err(|e| format!("failed to parse NVD response: {}", e))?;

        let mut cves = Vec::new();
        for vuln in nvd_resp.vulnerabilities {
            if let Some(cve) = parse_nvd_cve(vuln.cve) {
                cves.push(cve);
            }
        }

        Ok(cves)
    }
}

fn parse_nvd_date(s: &str) -> Option<DateTime<Utc>> {
    // NVD API returns dates like "2024-01-15T06:23:19.000" (no timezone, always UTC)
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
}

fn parse_nvd_cve(item: NvdCveItem) -> Option<CVE> {
    let published = parse_nvd_date(&item.published)?;
    let last_modified = parse_nvd_date(&item.last_modified)?;

    let descriptions: Vec<Description> = item.descriptions
        .unwrap_or_default()
        .into_iter()
        .map(|d| Description { lang: d.lang, value: d.value })
        .collect();

    let references: Vec<Reference> = item.references
        .unwrap_or_default()
        .into_iter()
        .map(|r| Reference {
            url: r.url,
            name: r.source,
        })
        .collect();

    // Parse CVSS
    let (impact_vector, base_score, severity) = parse_metrics(&item.metrics);

    // Parse configurations
    let configurations = parse_nvd_configs(&item.configurations);

    Some(CVE {
        cve_id: item.id,
        feed: 0,
        published,
        last_modified,
        impact_vector,
        base_score,
        severity,
        descriptions,
        references,
        configurations,
        assigner: item.source_identifier,
    })
}

fn parse_metrics(
    metrics: &Option<HashMap<String, Vec<NvdMetric>>>,
) -> (Option<String>, Option<f64>, Severity) {
    if let Some(metrics_map) = metrics {
        // Prefer CVSS 3.1, fall back to 3.0, then 2.0
        for key in &["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
            if let Some(metrics_list) = metrics_map.get(*key) {
                if let Some(metric) = metrics_list.first() {
                    let is_cvss3 = key.starts_with("cvssMetricV3");
                    if let Some(ref data) = metric.cvss_data {
                        return (
                            data.vector_string.clone(),
                            data.base_score,
                            if let Some(score) = data.base_score {
                                Severity::from_score(score, is_cvss3)
                            } else {
                                Severity::Unknown
                            },
                        );
                    }
                }
            }
        }
    }
    (None, None, Severity::Unknown)
}

fn parse_nvd_configs(configs: &Option<Vec<NvdConfiguration>>) -> Configurations {
    let mut result = Vec::new();
    if let Some(config_list) = configs {
        for config in config_list {
            let mut children = Vec::new();
            for node in &config.nodes {
                if let Some(ref matches) = node.cpe_match {
                    let mut node_children = Vec::new();
                    for m in matches {
                        if let Ok(cpe) = parse_cpe_fs(&m.criteria) {
                            let vulnerable = m.vulnerable.unwrap_or(true);
                            let child = if m.version_start_including.is_some()
                                || m.version_start_excluding.is_some()
                                || m.version_end_including.is_some()
                                || m.version_end_excluding.is_some()
                            {
                                ConfigurationNode::VersionRange {
                                    wrapped: cpe,
                                    start: m.version_start_including.clone()
                                        .or_else(|| m.version_start_excluding.clone()),
                                    end: m.version_end_including.clone()
                                        .or_else(|| m.version_end_excluding.clone()),
                                    include_start: m.version_start_including.is_some(),
                                    include_end: m.version_end_including.is_some(),
                                }
                            } else {
                                ConfigurationNode::Cpe(cpe)
                            };
                            if vulnerable {
                                node_children.push(child);
                            } else {
                                node_children.push(ConfigurationNode::Negate(Box::new(child)));
                            }
                        }
                    }
                    let negate = node.negate.unwrap_or(false);
                    let op = node.operator.as_deref().unwrap_or("OR");
                    if !node_children.is_empty() {
                        if op == "AND" {
                            children.push(ConfigurationNode::And {
                                children: node_children,
                                negate,
                            });
                        } else {
                            children.push(ConfigurationNode::Or {
                                children: node_children,
                                negate,
                            });
                        }
                    }
                }
            }
            if !children.is_empty() {
                if children.len() == 1 {
                    result.push(children.into_iter().next().unwrap());
                } else {
                    result.push(ConfigurationNode::Or {
                        children,
                        negate: false,
                    });
                }
            }
        }
    }
    result
}
