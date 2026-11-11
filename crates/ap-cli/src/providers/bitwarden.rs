//! Bitwarden CLI credential provider
//!
//! Wraps the `bw` CLI tool to look up credentials, check vault status, and
//! unlock the vault.

use std::process::Command;
use std::sync::OnceLock;

use ap_client::CredentialData;
use secrecy::{ExposeSecret, SecretString, zeroize::Zeroizing};
use serde::Deserialize;
use tracing::info;

use super::{CredentialProvider, CredentialQuery, LookupResult, ProviderScope, ProviderStatus};

/// Fallback path when `bw` is not found on `$PATH` (macOS Homebrew default).
const BW_FALLBACK_PATH: &str = "/opt/homebrew/bin/bw";

/// Bitwarden CLI login item structure.
#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

/// Bitwarden CLI URI structure.
#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

/// Bitwarden CLI item structure.
#[derive(Deserialize)]
struct BwItem {
    id: Option<String>,
    login: Option<BwLogin>,
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "collectionIds", default)]
    collection_ids: Vec<String>,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
}

/// Bitwarden CLI folder, collection or organization (only the fields we need).
#[derive(Deserialize)]
struct BwNamed {
    id: Option<String>,
    name: Option<String>,
}

/// A [`ProviderScope`] whose names have been resolved to Bitwarden IDs.
#[derive(Clone, Default)]
struct ResolvedScope {
    folder_id: Option<String>,
    collection_id: Option<String>,
    organization_id: Option<String>,
}

impl ResolvedScope {
    /// Whether `item` lies inside every restriction of this scope.
    fn contains(&self, item: &BwItem) -> bool {
        self.folder_id
            .as_ref()
            .is_none_or(|f| item.folder_id.as_ref() == Some(f))
            && self
                .collection_id
                .as_ref()
                .is_none_or(|c| item.collection_ids.contains(c))
            && self
                .organization_id
                .as_ref()
                .is_none_or(|o| item.organization_id.as_ref() == Some(o))
    }
}

/// Credential provider backed by the Bitwarden CLI (`bw`).
pub struct BitwardenProvider {
    session: Option<SecretString>,
    /// Cached path to the `bw` binary (resolved once on construction).
    bw_path: Option<String>,
    /// Folder / collection / organization restriction requested by the user.
    scope: ProviderScope,
    /// `scope` with names resolved to IDs (filled by the first lookup that succeeds).
    resolved_scope: OnceLock<ResolvedScope>,
}

impl BitwardenProvider {
    /// Create a new provider, reading `BW_SESSION` from the environment if set.
    pub fn new() -> Self {
        let session = std::env::var("BW_SESSION")
            .ok()
            .filter(|s| !s.is_empty())
            .map(SecretString::from);
        let bw_path = resolve_bw_path();
        Self {
            session,
            bw_path,
            scope: ProviderScope::default(),
            resolved_scope: OnceLock::new(),
        }
    }

    /// Restrict every lookup to the given folder / collection / organization.
    pub fn with_scope(mut self, scope: ProviderScope) -> Self {
        self.scope = scope;
        self
    }

    /// The scope with names resolved to IDs, resolving (and caching) it on first use.
    fn resolved_scope(&self, bw: &str) -> Result<ResolvedScope, String> {
        if let Some(resolved) = self.resolved_scope.get() {
            return Ok(resolved.clone());
        }
        let session = self.session.as_ref().map(|s| s.expose_secret());
        let resolved = ResolvedScope {
            folder_id: resolve_scope_id(bw, session, "folders", self.scope.folder.as_deref())?,
            collection_id: resolve_scope_id(
                bw,
                session,
                "collections",
                self.scope.collection.as_deref(),
            )?,
            organization_id: resolve_scope_id(
                bw,
                session,
                "organizations",
                self.scope.organization.as_deref(),
            )?,
        };
        Ok(self.resolved_scope.get_or_init(|| resolved).clone())
    }
}

/// Find `bw` on `$PATH`, falling back to a well-known location.
/// Returns `None` only if neither is found.
fn resolve_bw_path() -> Option<String> {
    // Check $PATH first — use `where` on Windows, `which` on Unix
    let which_cmd = if cfg!(target_os = "windows") {
        "where"
    } else {
        "which"
    };
    let from_path = Command::new(which_cmd)
        .arg("bw")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            // `where` on Windows may return multiple lines; take the first one
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty());

    if from_path.is_some() {
        return from_path;
    }

    // Fall back to well-known location (macOS Homebrew default)
    if std::path::Path::new(BW_FALLBACK_PATH).exists() {
        Some(BW_FALLBACK_PATH.to_string())
    } else {
        None
    }
}

/// Run `bw unlock` with the given master password and return the session key.
fn run_bw_unlock(bw: &str, password: &str) -> Result<String, String> {
    let output = Command::new(bw)
        .args(["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"])
        .env("BW_MASTER_PASSWORD", password)
        .output()
        .map_err(|e| format!("Failed to run bw unlock: {e}"))?;

    if output.status.success() {
        let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if key.is_empty() {
            Err("bw unlock returned empty session key".to_string())
        } else {
            Ok(key)
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.is_empty() {
            "bw unlock failed".to_string()
        } else {
            stderr
        })
    }
}

/// Run `bw status` and return the parsed status string and user email.
fn check_bw_cli_status(bw: &str, session: Option<&str>) -> (Option<String>, Option<String>) {
    let mut cmd = Command::new(bw);
    cmd.arg("status");
    if let Some(key) = session {
        cmd.env("BW_SESSION", key);
    }

    match cmd.output() {
        Ok(o) if o.status.success() => {
            let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
            let status = json["status"].as_str().map(String::from);
            let user_email = json["userEmail"].as_str().map(String::from);
            (status, user_email)
        }
        _ => (None, None),
    }
}

/// Heuristic: a BW session key is exactly 88 characters of valid base64.
///
/// BW session keys are 64 bytes (two 32-byte keys), base64-encoded → 88 chars
/// with padding.
fn looks_like_session_key(input: &str) -> bool {
    input.len() == 88
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Run `bw <args>` and return its stdout, or `None` (after logging) on failure.
fn run_bw(bw: &str, args: &[&str], session: Option<&str>) -> Option<Vec<u8>> {
    let mut cmd = Command::new(bw);
    cmd.args(args);
    if let Some(key) = session {
        cmd.env("BW_SESSION", key);
    }
    let output = cmd.output().ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Not found") {
            info!("bw {} failed: {}", args.join(" "), stderr);
        }
        return None;
    }
    Some(output.stdout)
}

/// Resolve a folder / collection / organization given by name or ID to its ID.
///
/// `kind` is the `bw list` object type (`folders`, `collections`, `organizations`).
/// Returns `Ok(None)` when no restriction was requested. A name must match
/// exactly one object, otherwise the lookup fails closed.
fn resolve_scope_id(
    bw: &str,
    session: Option<&str>,
    kind: &str,
    value: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if looks_like_uuid(value) {
        return Ok(Some(value.to_ascii_lowercase()));
    }

    let stdout = run_bw(bw, &["list", kind, "--search", value], session)
        .ok_or_else(|| format!("Could not list Bitwarden {kind}"))?;
    let objects: Vec<BwNamed> = serde_json::from_slice(&stdout)
        .map_err(|e| format!("Could not parse Bitwarden {kind}: {e}"))?;
    let mut ids = objects
        .into_iter()
        .filter(|o| o.name.as_deref() == Some(value))
        .filter_map(|o| o.id);
    match (ids.next(), ids.next()) {
        (Some(id), None) => Ok(Some(id)),
        (None, _) => Err(format!("No Bitwarden {kind} named '{value}'")),
        (Some(_), Some(_)) => Err(format!(
            "More than one Bitwarden {kind} named '{value}'; use its ID instead"
        )),
    }
}

/// Whether `input` has the shape of a Bitwarden object ID (a UUID).
fn looks_like_uuid(input: &str) -> bool {
    input.len() == 36
        && input.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Outcome of picking one item out of a `bw list items` result.
#[derive(Debug, PartialEq, Eq)]
enum Selection {
    /// Exactly one item matched; carries its index.
    One(usize),
    /// Nothing matched.
    NoMatch,
    /// More than one item matched; carries the indexes of the candidates.
    Ambiguous(Vec<usize>),
}

/// Turn a list of candidate indexes into a [`Selection`].
fn selection_of(mut candidates: Vec<usize>) -> Selection {
    match candidates.len() {
        0 => Selection::NoMatch,
        1 => Selection::One(candidates.remove(0)),
        _ => Selection::Ambiguous(candidates),
    }
}

/// Pick the item for a domain query, matching the host and port exactly.
///
/// `bw list items --search` is a substring search over names, usernames and
/// URIs, so its result is narrowed here, in order of preference:
///
/// 1. items with a URI whose host and port equal the query's (a query without
///    a port matches only URIs without a port);
/// 2. if the query has no port: items with a URI on that host, on any port;
/// 3. if the query has no port: the sole item the search returned (for example
///    an item that matches by name only).
///
/// The first step that yields any candidate decides, so several candidates
/// there are reported as ambiguous instead of falling through to a looser step.
fn select_by_domain(items: &[BwItem], query: &str) -> Selection {
    let Some(wanted) = uri_parts(query) else {
        return Selection::NoMatch;
    };
    let matching = |same_port: bool| -> Vec<usize> {
        items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                item.login
                    .as_ref()
                    .and_then(|l| l.uris.as_ref())
                    .into_iter()
                    .flatten()
                    .filter_map(|u| u.uri.as_deref().and_then(uri_parts))
                    .any(|have| {
                        have.host == wanted.host && (!same_port || have.port == wanted.port)
                    })
            })
            .map(|(i, _)| i)
            .collect()
    };

    let exact = matching(true);
    if !exact.is_empty() || wanted.port.is_some() {
        return selection_of(exact);
    }
    let same_host = matching(false);
    if !same_host.is_empty() {
        return selection_of(same_host);
    }
    selection_of(if items.len() == 1 { vec![0] } else { vec![] })
}

/// The host (lower-cased) and explicit port of a URI or `host[:port]` string.
#[derive(Debug, PartialEq, Eq)]
struct UriParts {
    host: String,
    port: Option<u16>,
}

/// Split a URI, or a bare `host[:port]`, into host and port.
fn uri_parts(uri: &str) -> Option<UriParts> {
    let after_scheme = uri.split_once("://").map_or(uri, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let hostport = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest);

    let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
        // IPv6 literal, e.g. `[::1]:8080`
        let (host, rest) = bracketed.split_once(']')?;
        (host, rest.strip_prefix(':'))
    } else {
        match hostport.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (hostport, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(UriParts {
        host: host.to_ascii_lowercase(),
        port: port.and_then(|p| p.parse().ok()),
    })
}

/// Look up a credential from the Bitwarden CLI, honouring `scope`.
///
/// Returns `None` when nothing matched or when the match was ambiguous.
fn lookup_credential(
    bw: &str,
    query: &CredentialQuery,
    scope: &ResolvedScope,
    session: Option<&str>,
) -> Option<CredentialData> {
    if let CredentialQuery::Id(id) = query {
        let stdout = run_bw(bw, &["get", "item", id], session)?;
        let item: BwItem = serde_json::from_slice(&stdout).ok()?;
        if !scope.contains(&item) {
            info!("item {id} is outside the configured folder/collection/organization");
            return None;
        }
        return credential_from_item(item);
    }

    let search = match query {
        CredentialQuery::Domain(d) => uri_parts(d)?.host,
        _ => query.search_string().to_string(),
    };
    let mut args = vec!["list", "items", "--search", search.as_str()];
    if let Some(f) = &scope.folder_id {
        args.extend(["--folderid", f]);
    }
    if let Some(c) = &scope.collection_id {
        args.extend(["--collectionid", c]);
    }
    if let Some(o) = &scope.organization_id {
        args.extend(["--organizationid", o]);
    }
    let stdout = run_bw(bw, &args, session)?;
    let mut items: Vec<BwItem> = serde_json::from_slice(&stdout).ok()?;

    let selection = match query {
        CredentialQuery::Domain(d) => select_by_domain(&items, d),
        _ => selection_of((0..items.len()).collect()),
    };
    match selection {
        Selection::One(index) => credential_from_item(items.swap_remove(index)),
        Selection::NoMatch => None,
        Selection::Ambiguous(candidates) => {
            let ids: Vec<&str> = candidates
                .iter()
                .filter_map(|&i| items[i].id.as_deref())
                .collect();
            info!(
                "more than one item matches {query}; request one by id instead: {}",
                ids.join(", ")
            );
            None
        }
    }
}

/// Convert a `bw` item into the credential handed back to the client.
fn credential_from_item(item: BwItem) -> Option<CredentialData> {
    let login = item.login?;

    let uri = login
        .uris
        .as_ref()
        .and_then(|uris| uris.first())
        .and_then(|u| u.uri.clone());

    let domain = uri.as_deref().and_then(domain_from_uri);

    Some(CredentialData {
        username: login.username,
        password: login.password.map(Zeroizing::new),
        totp: login.totp,
        uri,
        notes: None,
        credential_id: item.id,
        domain,
    })
}

/// Extract the domain (host) from a URI string, e.g. `https://example.com/path` → `example.com`.
fn domain_from_uri(uri: &str) -> Option<String> {
    // Strip scheme (e.g. "https://")
    let after_scheme = match uri.split_once("://") {
        Some((_, rest)) => rest,
        None => uri,
    };
    // Strip userinfo (e.g. "user:pass@")
    let after_userinfo = match after_scheme.split_once('@') {
        Some((_, rest)) => rest,
        None => after_scheme,
    };
    // Take host (before any '/' or ':')
    let host = after_userinfo.split(['/', ':']).next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

/// Create a `BitwardenProvider` with explicit fields (for testing without
/// spawning `which`).
#[cfg(test)]
impl BitwardenProvider {
    fn with_session(session: Option<SecretString>) -> Self {
        Self {
            session,
            bw_path: None,
            scope: ProviderScope::default(),
            resolved_scope: OnceLock::new(),
        }
    }
}

impl CredentialProvider for BitwardenProvider {
    fn name(&self) -> &str {
        "Bitwarden"
    }

    fn status(&self) -> ProviderStatus {
        let bw = match &self.bw_path {
            Some(p) => p,
            None => {
                return ProviderStatus::NotInstalled {
                    install_hint: "Install the Bitwarden CLI and add it to your path: https://bitwarden.com/download/#command-line-interface".to_string(),
                };
            }
        };

        let (status_str, user_email) =
            check_bw_cli_status(bw, self.session.as_ref().map(|s| s.expose_secret()));

        match status_str.as_deref() {
            Some("unlocked") => ProviderStatus::Ready {
                user_info: user_email,
            },
            Some("locked") => ProviderStatus::Locked {
                prompt: "Master password or session key".to_string(),
                user_info: user_email,
            },
            Some(other) => ProviderStatus::Unavailable {
                reason: format!("Vault status: {other} — run: bw login"),
            },
            None => ProviderStatus::Unavailable {
                reason: "Could not determine vault status".to_string(),
            },
        }
    }

    fn unlock(&mut self, input: &str) -> Result<(), String> {
        let bw = self.bw_path.as_deref().ok_or("Bitwarden CLI not found")?;

        if looks_like_session_key(input) {
            // Try as a session key first — validate with `bw status`
            let (status, _) = check_bw_cli_status(bw, Some(input));
            if status.as_deref() == Some("unlocked") {
                self.session = Some(SecretString::from(input.to_string()));
                return Ok(());
            }
            // Fall through to try as password if it didn't validate
        }

        // Treat as master password
        let key = run_bw_unlock(bw, input)?;
        self.session = Some(SecretString::from(key));
        Ok(())
    }

    fn lookup(&self, query: &CredentialQuery) -> LookupResult {
        let bw = match &self.bw_path {
            Some(p) => p,
            None => {
                return LookupResult::NotReady {
                    message: "Bitwarden CLI not found".to_string(),
                };
            }
        };

        let scope = match self.resolved_scope(bw) {
            Ok(scope) => scope,
            Err(message) => return LookupResult::NotReady { message },
        };

        match lookup_credential(
            bw,
            query,
            &scope,
            self.session.as_ref().map(|s| s.expose_secret()),
        ) {
            Some(cred) => LookupResult::Found(cred),
            None => {
                // When there's no cached session the vault might still be unlocked
                // natively (e.g. via BW_SESSION in the shell). Check `bw status`
                // to distinguish "not found" from "vault locked".
                if self.session.is_none() {
                    let (status, _) = check_bw_cli_status(bw, None);
                    if status.as_deref() != Some("unlocked") {
                        return LookupResult::NotReady {
                            message: "Vault is locked".to_string(),
                        };
                    }
                }
                LookupResult::NotFound
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- looks_like_session_key() -------------------------------------------

    /// 88 A's — valid base64 of the right length.
    const VALID_KEY: &str =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn session_key_valid() {
        assert_eq!(VALID_KEY.len(), 88);
        assert!(looks_like_session_key(VALID_KEY));
    }

    #[test]
    fn session_key_rejects_wrong_length_and_bad_chars() {
        assert!(!looks_like_session_key(""));
        assert!(!looks_like_session_key("short"));
        assert!(!looks_like_session_key(&VALID_KEY[..87])); // too short
        assert!(!looks_like_session_key("alligator5")); // typical password
        // 88 chars but contains a space
        let mut bad = VALID_KEY.to_string();
        bad.replace_range(40..41, " ");
        assert!(!looks_like_session_key(&bad));
    }

    // -- domain_from_uri() ---------------------------------------------------

    #[test]
    fn domain_from_uri_with_scheme_and_path() {
        assert_eq!(
            domain_from_uri("https://example.com/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn domain_from_uri_with_port() {
        assert_eq!(
            domain_from_uri("https://example.com:8080/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn domain_from_uri_no_scheme() {
        assert_eq!(domain_from_uri("example.com"), Some("example.com".into()));
    }

    #[test]
    fn domain_from_uri_with_userinfo() {
        assert_eq!(
            domain_from_uri("https://user:pass@example.com"),
            Some("example.com".into())
        );
    }

    #[test]
    fn domain_from_uri_empty_host() {
        assert_eq!(domain_from_uri("https://"), None);
    }

    #[test]
    fn domain_from_uri_bare_scheme() {
        assert_eq!(domain_from_uri(""), None);
    }

    // -- uri_parts() ---------------------------------------------------------

    fn parts(host: &str, port: Option<u16>) -> Option<UriParts> {
        Some(UriParts {
            host: host.to_string(),
            port,
        })
    }

    #[test]
    fn uri_parts_host_only() {
        assert_eq!(uri_parts("Example.COM"), parts("example.com", None));
    }

    #[test]
    fn uri_parts_host_and_port() {
        assert_eq!(
            uri_parts("example.com:8443"),
            parts("example.com", Some(8443))
        );
    }

    #[test]
    fn uri_parts_full_url() {
        assert_eq!(
            uri_parts("https://user:pw@example.com:8443/a/b?c=d#e"),
            parts("example.com", Some(8443))
        );
    }

    #[test]
    fn uri_parts_ipv6() {
        assert_eq!(uri_parts("http://[::1]:8080/x"), parts("::1", Some(8080)));
        assert_eq!(uri_parts("[::1]"), parts("::1", None));
    }

    #[test]
    fn uri_parts_rejects_empty_host() {
        assert_eq!(uri_parts(""), None);
        assert_eq!(uri_parts("https://:8080"), None);
    }

    // -- looks_like_uuid() ---------------------------------------------------

    #[test]
    fn uuid_shape() {
        assert!(looks_like_uuid("c243cd7d-740a-4683-9cda-446f87fdf33c"));
        assert!(!looks_like_uuid("Servers"));
        assert!(!looks_like_uuid("c243cd7d-740a-4683-9cda-446f87fdf33"));
        assert!(!looks_like_uuid("c243cd7d-740a-4683-9cda-446f87fdf33g"));
    }

    // -- select_by_domain() --------------------------------------------------

    fn item(id: &str, uris: &[&str]) -> BwItem {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "login": { "uris": uris.iter().map(|u| serde_json::json!({ "uri": u })).collect::<Vec<_>>() },
        }))
        .expect("valid item")
    }

    fn ports_fixture() -> Vec<BwItem> {
        vec![
            item("a", &["https://box.example.com:8443"]),
            item("b", &["https://box.example.com:9443/path"]),
            item("c", &["https://other.example.com"]),
        ]
    }

    #[test]
    fn domain_with_port_selects_exact_port() {
        let items = ports_fixture();
        assert_eq!(
            select_by_domain(&items, "box.example.com:9443"),
            Selection::One(1)
        );
    }

    #[test]
    fn domain_with_unknown_port_matches_nothing() {
        let items = ports_fixture();
        assert_eq!(
            select_by_domain(&items, "box.example.com:1234"),
            Selection::NoMatch
        );
    }

    #[test]
    fn domain_without_port_is_ambiguous_across_ports() {
        let items = ports_fixture();
        assert_eq!(
            select_by_domain(&items, "box.example.com"),
            Selection::Ambiguous(vec![0, 1])
        );
    }

    #[test]
    fn domain_without_port_prefers_portless_uri() {
        let items = vec![
            item("a", &["https://box.example.com:8443"]),
            item("b", &["https://box.example.com"]),
        ];
        assert_eq!(
            select_by_domain(&items, "box.example.com"),
            Selection::One(1)
        );
    }

    #[test]
    fn domain_without_port_accepts_sole_port_match() {
        let items = vec![item("a", &["https://box.example.com:8443"])];
        assert_eq!(
            select_by_domain(&items, "box.example.com"),
            Selection::One(0)
        );
    }

    #[test]
    fn domain_matches_any_uri_of_an_item_case_insensitively() {
        let items = vec![item(
            "a",
            &["https://x.example.com", "https://Box.Example.com"],
        )];
        assert_eq!(
            select_by_domain(&items, "BOX.example.com"),
            Selection::One(0)
        );
    }

    #[test]
    fn domain_falls_back_to_sole_search_result() {
        // Found by name or username rather than URI.
        let items = vec![item("a", &[])];
        assert_eq!(
            select_by_domain(&items, "box.example.com"),
            Selection::One(0)
        );
    }

    #[test]
    fn domain_does_not_fall_back_with_several_search_results() {
        let items = vec![item("a", &[]), item("b", &[])];
        assert_eq!(
            select_by_domain(&items, "box.example.com"),
            Selection::NoMatch
        );
    }

    #[test]
    fn domain_with_port_does_not_fall_back_to_sole_search_result() {
        let items = vec![item("a", &["https://box.example.com:8443"])];
        assert_eq!(
            select_by_domain(&items, "box.example.com:9443"),
            Selection::NoMatch
        );
    }

    #[test]
    fn domain_does_not_match_a_longer_host() {
        let items = vec![
            item("a", &["https://notbox.example.com:8443"]),
            item("b", &[]),
        ];
        assert_eq!(
            select_by_domain(&items, "box.example.com:8443"),
            Selection::NoMatch
        );
    }

    // -- ResolvedScope::contains() -------------------------------------------

    fn scoped_item() -> BwItem {
        serde_json::from_value(serde_json::json!({
            "id": "a",
            "folderId": "f1",
            "collectionIds": ["c1", "c2"],
            "organizationId": "o1",
        }))
        .expect("valid item")
    }

    #[test]
    fn empty_scope_contains_everything() {
        assert!(ResolvedScope::default().contains(&scoped_item()));
    }

    #[test]
    fn scope_requires_every_restriction() {
        let item = scoped_item();
        let all = ResolvedScope {
            folder_id: Some("f1".into()),
            collection_id: Some("c2".into()),
            organization_id: Some("o1".into()),
        };
        assert!(all.contains(&item));
        assert!(
            !ResolvedScope {
                folder_id: Some("f2".into()),
                ..all.clone()
            }
            .contains(&item)
        );
        assert!(
            !ResolvedScope {
                collection_id: Some("c3".into()),
                ..all.clone()
            }
            .contains(&item)
        );
        assert!(
            !ResolvedScope {
                organization_id: Some("o2".into()),
                ..all
            }
            .contains(&item)
        );
    }

    #[test]
    fn folder_scope_excludes_item_without_folder() {
        let item: BwItem =
            serde_json::from_value(serde_json::json!({ "id": "a" })).expect("valid item");
        let scope = ResolvedScope {
            folder_id: Some("f1".into()),
            ..ResolvedScope::default()
        };
        assert!(!scope.contains(&item));
    }

    // -- BitwardenProvider construction & name() ----------------------------

    #[test]
    fn provider_name_is_bitwarden() {
        let p = BitwardenProvider::with_session(None);
        assert_eq!(p.name(), "Bitwarden");
    }

    #[test]
    fn provider_has_session_when_constructed_with_one() {
        let p = BitwardenProvider::with_session(Some(SecretString::from("key123".to_string())));
        assert!(p.session.is_some());
    }

    #[test]
    fn provider_has_no_session_when_constructed_without() {
        let p = BitwardenProvider::with_session(None);
        assert!(p.session.is_none());
    }
}
