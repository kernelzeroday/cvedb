use chrono::{DateTime, Utc};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    None = 0,
    Unknown = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl Severity {
    pub fn from_score(score: f64, is_cvss3: bool) -> Self {
        if is_cvss3 {
            if score == 0.0 {
                Severity::None
            } else if score < 4.0 {
                Severity::Low
            } else if score < 7.0 {
                Severity::Medium
            } else if score < 9.0 {
                Severity::High
            } else {
                Severity::Critical
            }
        } else {
            // CVSS2
            if score < 4.0 {
                Severity::Low
            } else if score < 7.0 {
                Severity::Medium
            } else {
                Severity::High
            }
        }
    }

    pub fn from_int(n: i64) -> Self {
        match n {
            0 => Severity::None,
            1 => Severity::Unknown,
            2 => Severity::Low,
            3 => Severity::Medium,
            4 => Severity::High,
            5 => Severity::Critical,
            _ => Severity::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Reference {
    pub url: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Description {
    pub lang: String,
    pub value: String,
}

pub type Configurations = Vec<ConfigurationNode>;

#[derive(Debug, Clone)]
pub enum ConfigurationNode {
    Cpe(CPE),
    And { children: Vec<ConfigurationNode>, negate: bool },
    Or { children: Vec<ConfigurationNode>, negate: bool },
    Negate(Box<ConfigurationNode>),
    VersionRange {
        wrapped: CPE,
        start: Option<String>,
        end: Option<String>,
        include_start: bool,
        include_end: bool,
    },
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum Logical {
    Any,
    NA,
}

impl fmt::Display for Logical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Logical::Any => write!(f, "*"),
            Logical::NA => write!(f, "-"),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    App,
    OS,
    Hardware,
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Part::App => write!(f, "a"),
            Part::OS => write!(f, "o"),
            Part::Hardware => write!(f, "h"),
        }
    }
}

#[allow(dead_code)]
pub type AVString = Option<String>; // None = wildcard/ANY, Some("-") = NA

#[derive(Debug, Clone)]
pub struct CPE {
    pub part: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub update: Option<String>,
    pub edition: Option<String>,
    pub lang: Option<String>,
    pub sw_edition: Option<String>,
    pub target_sw: Option<String>,
    pub target_hw: Option<String>,
    pub other: Option<String>,
}

impl fmt::Display for CPE {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.part.as_deref().unwrap_or("*"),
            self.vendor.as_deref().unwrap_or("*"),
            self.product.as_deref().unwrap_or("*"),
            self.version.as_deref().unwrap_or("*"),
            self.update.as_deref().unwrap_or("*"),
            self.edition.as_deref().unwrap_or("*"),
            self.lang.as_deref().unwrap_or("*"),
            self.sw_edition.as_deref().unwrap_or("*"),
            self.target_sw.as_deref().unwrap_or("*"),
            self.target_hw.as_deref().unwrap_or("*"),
            self.other.as_deref().unwrap_or("*"),
        )
    }
}

impl CPE {
    pub fn matches(&self, other: &CPE) -> bool {
        fields_match(&self.part, &other.part)
            && fields_match(&self.vendor, &other.vendor)
            && fields_match(&self.product, &other.product)
            && fields_match(&self.version, &other.version)
            && fields_match(&self.update, &other.update)
            && fields_match(&self.edition, &other.edition)
            && fields_match(&self.lang, &other.lang)
            && fields_match(&self.sw_edition, &other.sw_edition)
            && fields_match(&self.target_sw, &other.target_sw)
            && fields_match(&self.target_hw, &other.target_hw)
            && fields_match(&self.other, &other.other)
    }
}

fn fields_match(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (None, _) => true,  // wildcard matches anything
        (_, None) => true,
        (Some(a), Some(b)) => {
            if a == "*" || b == "*" {
                return true;
            }
            if a == "-" || b == "-" {
                return false;
            }
            a == b
        }
    }
}

impl ConfigurationNode {
    pub fn matches(&self, cpe: &CPE) -> bool {
        match self {
            ConfigurationNode::Cpe(c) => c.matches(cpe),
            ConfigurationNode::And { children, negate } => {
                let r = children.iter().all(|c| c.matches(cpe));
                if *negate { !r } else { r }
            }
            ConfigurationNode::Or { children, negate } => {
                let r = children.iter().any(|c| c.matches(cpe));
                if *negate { !r } else { r }
            }
            ConfigurationNode::Negate(wrapped) => !wrapped.matches(cpe),
            ConfigurationNode::VersionRange { wrapped, start, end, include_start, include_end } => {
                if let Some(ref ver) = cpe.version {
                    if let Some(ref s) = start {
                        let cmp = ver.as_str();
                        if *include_start {
                            if cmp < s.as_str() { return false; }
                        } else {
                            if cmp <= s.as_str() { return false; }
                        }
                    }
                    if let Some(ref e) = end {
                        let cmp = ver.as_str();
                        if *include_end {
                            if cmp > e.as_str() { return false; }
                        } else {
                            if cmp >= e.as_str() { return false; }
                        }
                    }
                }
                wrapped.matches(cpe)
            }
        }
    }

}

/// Serialize configuration tree to the compact string format
pub fn serialize_configurations(configs: &[ConfigurationNode]) -> String {
    let mut out = String::new();
    serialize_config_list(configs, &mut out);
    out
}

fn serialize_config_list(nodes: &[ConfigurationNode], out: &mut String) {
    out.push_str(&nodes.len().to_string());
    out.push('\n');
    for node in nodes {
        serialize_node(node, out);
    }
}

fn serialize_node(node: &ConfigurationNode, out: &mut String) {
    match node {
        ConfigurationNode::Cpe(cpe) => {
            out.push('c');
            out.push_str(&cpe.to_string());
            out.push('\n');
        }
        ConfigurationNode::And { children, negate } => {
            out.push('a');
            out.push(if *negate { 'I' } else { 'O' });
            serialize_config_list(children, out);
        }
        ConfigurationNode::Or { children, negate } => {
            out.push('o');
            out.push(if *negate { 'I' } else { 'O' });
            serialize_config_list(children, out);
        }
        ConfigurationNode::Negate(wrapped) => {
            out.push('!');
            serialize_node(wrapped, out);
        }
        ConfigurationNode::VersionRange { wrapped, start, end, include_start, include_end } => {
            out.push('v');
            out.push(if *include_start { 'I' } else { 'O' });
            if let Some(s) = start {
                out.push_str(s);
            }
            out.push('\n');
            out.push(if *include_end { 'I' } else { 'O' });
            if let Some(e) = end {
                out.push_str(e);
            }
            out.push('\n');
            serialize_node(&ConfigurationNode::Cpe(wrapped.clone()), out);
        }
    }
}

/// Load configuration tree from serialized format
pub fn parse_configurations(s: &str) -> Result<Configurations, String> {
    let bytes = s.as_bytes();
    let mut pos = 0;
    parse_config_list(bytes, &mut pos)
}

fn parse_config_list(bytes: &[u8], pos: &mut usize) -> Result<Vec<ConfigurationNode>, String> {
    let num = parse_int(bytes, pos)?;
    let mut nodes = Vec::with_capacity(num);
    for _ in 0..num {
        nodes.push(parse_node(bytes, pos)?);
    }
    Ok(nodes)
}

fn parse_node(bytes: &[u8], pos: &mut usize) -> Result<ConfigurationNode, String> {
    if *pos >= bytes.len() {
        return Err("unexpected end of config data".into());
    }
    let uid = bytes[*pos] as char;
    *pos += 1;
    match uid {
        'c' => Ok(ConfigurationNode::Cpe(parse_cpe_line(bytes, pos)?)),
        'C' => {
            // Configurations wrapper: just parse children
            let children = parse_config_list(bytes, pos)?;
            // Wrap everything in an Or (as in the Python code)
            if children.len() == 1 {
                Ok(children.into_iter().next().unwrap())
            } else {
                Ok(ConfigurationNode::Or { children, negate: false })
            }
        }
        'a' | 'o' => {
            let negate = parse_bool(bytes, pos)?;
            let children = parse_config_list(bytes, pos)?;
            if uid == 'a' {
                Ok(ConfigurationNode::And { children, negate })
            } else {
                Ok(ConfigurationNode::Or { children, negate })
            }
        }
        '!' => {
            let wrapped = parse_node(bytes, pos)?;
            Ok(ConfigurationNode::Negate(Box::new(wrapped)))
        }
        'v' => {
            let include_start = parse_bool(bytes, pos)?;
            let start = parse_line_str(bytes, pos);
            let include_end = parse_bool(bytes, pos)?;
            let end = parse_line_str(bytes, pos);
            let wrapped = match parse_node(bytes, pos)? {
                ConfigurationNode::Cpe(c) => c,
                other => return Err(format!("VersionRange wraps non-CPE node: {:?}", other)),
            };
            Ok(ConfigurationNode::VersionRange { wrapped, start, end, include_start, include_end })
        }
        _ => Err(format!("unknown configuration node UID: {:?}", uid)),
    }
}

fn parse_int(bytes: &[u8], pos: &mut usize) -> Result<usize, String> {
    let start = *pos;
    while *pos < bytes.len() && bytes[*pos] >= b'0' && bytes[*pos] <= b'9' {
        *pos += 1;
    }
    if *pos == start {
        return Err("expected integer".into());
    }
    let s = std::str::from_utf8(&bytes[start..*pos])
        .map_err(|e| format!("utf8 error: {}", e))?;
    let n: usize = s.parse()
        .map_err(|e: std::num::ParseIntError| format!("parse error: {}", e))?;
    if *pos < bytes.len() && bytes[*pos] == b'\n' {
        *pos += 1;
    }
    Ok(n)
}

fn parse_bool(bytes: &[u8], pos: &mut usize) -> Result<bool, String> {
    if *pos >= bytes.len() {
        return Err("unexpected end".into());
    }
    let b = bytes[*pos] as char;
    *pos += 1;
    Ok(b == 'I')
}

fn parse_line_str(bytes: &[u8], pos: &mut usize) -> Option<String> {
    let start = *pos;
    while *pos < bytes.len() && bytes[*pos] != b'\n' {
        *pos += 1;
    }
    let s = std::str::from_utf8(&bytes[start..*pos]).ok()?;
    if *pos < bytes.len() {
        *pos += 1;
    }
    if s.is_empty() { None } else { Some(s.to_string()) }
}

fn parse_cpe_line(bytes: &[u8], pos: &mut usize) -> Result<CPE, String> {
    let start = *pos;
    while *pos < bytes.len() && bytes[*pos] != b'\n' {
        *pos += 1;
    }
    let line = std::str::from_utf8(&bytes[start..*pos])
        .map_err(|e| e.to_string())?;
    if *pos < bytes.len() {
        *pos += 1;
    }
    parse_cpe_fs(line.trim())
}

pub fn parse_cpe_fs(fs: &str) -> Result<CPE, String> {
    let parts: Vec<&str> = fs.split(':').collect();
    if parts.len() < 13 || parts[0] != "cpe" || parts[1] != "2.3" {
        return Err(format!("invalid CPE formatted string: {}", fs));
    }
    Ok(CPE {
        part: field(&parts, 2),
        vendor: field(&parts, 3),
        product: field(&parts, 4),
        version: field(&parts, 5),
        update: field(&parts, 6),
        edition: field(&parts, 7),
        lang: field(&parts, 8),
        sw_edition: field(&parts, 9),
        target_sw: field(&parts, 10),
        target_hw: field(&parts, 11),
        other: field(&parts, 12),
    })
}

fn field(parts: &[&str], i: usize) -> Option<String> {
    let v = parts.get(i).copied().unwrap_or("*");
    if v == "*" || v == "-" {
        Some(v.to_string())
    } else {
        Some(v.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct CVE {
    pub cve_id: String,
    #[allow(dead_code)]
    pub feed: i64,
    pub published: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    #[allow(dead_code)]
    pub impact_vector: Option<String>,
    pub base_score: Option<f64>,
    pub severity: Severity,
    pub descriptions: Vec<Description>,
    pub references: Vec<Reference>,
    pub configurations: Configurations,
    pub assigner: Option<String>,
}

impl CVE {
    pub fn description_en(&self) -> Option<&str> {
        for d in &self.descriptions {
            if d.lang == "en" {
                return Some(&d.value);
            }
        }
        self.descriptions.first().map(|d| d.value.as_str())
    }
}
