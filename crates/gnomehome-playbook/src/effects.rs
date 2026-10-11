//! Everything the engine can change in the world, behind one trait.
//!
//! The engine decides; an [`Effects`] implementation acts. Tests use a fake that
//! records calls. [`RealEffects`] talks to Pi-hole's v6 API on loopback and runs the
//! Python `gnomehome` command for router actions, with a fixed argument list and no
//! shell, as the plan prescribes for Python-only capabilities.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// How the Python helper finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperOutcome {
    Done(String),
    /// The Python guard refused a protected target (exit code 3).
    Refused,
    Failed(String),
}

pub trait Effects {
    fn pihole_block(&mut self, domain: &str, comment: &str) -> Result<(), String>;
    fn pihole_unblock(&mut self, domain: &str) -> Result<(), String>;
    /// Runs `gnomehome <args>`. Arguments are passed as-is, never through a shell.
    fn helper(&mut self, args: &[String]) -> HelperOutcome;
}

/// A domain Pi-hole can block: lowercase letters, digits, dashes, and dots, with at
/// least two labels. Anything else (an address, spaces, slashes, wildcards) is refused.
pub fn valid_domain(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    domain.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

/// The Pi-hole v6 REST API, on this machine only.
pub struct PiholeClient {
    api: String,
    password: String,
    agent: ureq::Agent,
}

impl PiholeClient {
    /// `api` must be `http://` on loopback; the password comes from a file outside git.
    pub fn new(api: &str, password_file: &Path) -> Result<PiholeClient, String> {
        if !is_loopback_http(api) {
            return Err(format!("pihole_api {api:?} must be http:// on loopback"));
        }
        let password = std::fs::read_to_string(password_file)
            .map_err(|e| format!("can't read {}: {e}", password_file.display()))?
            .trim()
            .to_owned();
        if password.is_empty() {
            return Err(format!("{} is empty", password_file.display()));
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .http_status_as_error(false)
            .build()
            .into();
        Ok(PiholeClient {
            api: api.trim_end_matches('/').to_owned(),
            password,
            agent,
        })
    }

    /// Signs in, runs `f` with the session ID, and always signs out again.
    fn with_session<T>(&self, f: impl FnOnce(&str) -> Result<T, String>) -> Result<T, String> {
        let mut response = self
            .agent
            .post(&format!("{}/auth", self.api))
            .send_json(json!({ "password": self.password }))
            .map_err(|e| format!("Pi-hole sign-in failed: {e}"))?;
        if response.status() != 200 {
            return Err(format!(
                "Pi-hole sign-in refused (HTTP {})",
                response.status()
            ));
        }
        let body: Value = response
            .body_mut()
            .read_json()
            .map_err(|e| format!("Pi-hole sign-in: unexpected reply: {e}"))?;
        let sid = body["session"]["sid"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("Pi-hole sign-in: no session in the reply")?
            .to_owned();
        let result = f(&sid);
        let _ = self
            .agent
            .delete(&format!("{}/auth", self.api))
            .header("X-FTL-SID", &sid)
            .call();
        result
    }
}

impl PiholeClient {
    pub fn block(&self, domain: &str, comment: &str) -> Result<(), String> {
        if !valid_domain(domain) {
            return Err(format!("{domain:?} is not a domain Pi-hole can block"));
        }
        self.with_session(|sid| {
            let response = self
                .agent
                .post(&format!("{}/domains/deny/exact", self.api))
                .header("X-FTL-SID", sid)
                .send_json(json!({ "domain": domain, "comment": comment, "enabled": true }))
                .map_err(|e| format!("Pi-hole block failed: {e}"))?;
            match response.status().as_u16() {
                200 | 201 => Ok(()),
                code => Err(format!("Pi-hole refused the block (HTTP {code})")),
            }
        })
    }

    pub fn unblock(&self, domain: &str) -> Result<(), String> {
        if !valid_domain(domain) {
            return Err(format!("{domain:?} is not a domain Pi-hole can unblock"));
        }
        self.with_session(|sid| {
            let response = self
                .agent
                .delete(&format!("{}/domains/deny/exact/{domain}", self.api))
                .header("X-FTL-SID", sid)
                .call()
                .map_err(|e| format!("Pi-hole unblock failed: {e}"))?;
            match response.status().as_u16() {
                200 | 204 | 404 => Ok(()), // 404: already gone
                code => Err(format!("Pi-hole refused the unblock (HTTP {code})")),
            }
        })
    }
}

fn is_loopback_http(api: &str) -> bool {
    let Some(rest) = api.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.split_once(']'))
        .map_or_else(
            || host.rsplit_once(':').map_or(host, |(h, _)| h),
            |(h, _)| h,
        );
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// The real world: Pi-hole on loopback and the Python helper.
pub struct RealEffects {
    pub pihole: Option<PiholeClient>,
    pub cli: Option<PathBuf>,
    pub config_path: PathBuf,
    pub timeout: Duration,
}

impl Effects for RealEffects {
    fn pihole_block(&mut self, domain: &str, comment: &str) -> Result<(), String> {
        self.pihole
            .as_ref()
            .ok_or("Pi-hole isn't configured (pihole_password_file)")?
            .block(domain, comment)
    }

    fn pihole_unblock(&mut self, domain: &str) -> Result<(), String> {
        self.pihole
            .as_ref()
            .ok_or("Pi-hole isn't configured (pihole_password_file)")?
            .unblock(domain)
    }

    fn helper(&mut self, args: &[String]) -> HelperOutcome {
        let Some(cli) = &self.cli else {
            return HelperOutcome::Failed("gnomehome_cli isn't set in the config".into());
        };
        let mut command = Command::new(cli);
        command
            .arg("--config")
            .arg(&self.config_path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => return HelperOutcome::Failed(format!("can't run {}: {e}", cli.display())),
        };
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() > self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return HelperOutcome::Failed("the helper timed out".into());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return HelperOutcome::Failed(format!("waiting for the helper: {e}")),
            }
        }
        match child.wait_with_output() {
            Ok(out) if out.status.success() => {
                HelperOutcome::Done(String::from_utf8_lossy(&out.stdout).trim().to_owned())
            }
            Ok(out) if out.status.code() == Some(3) => HelperOutcome::Refused,
            Ok(out) => HelperOutcome::Failed(
                String::from_utf8_lossy(&out.stderr)
                    .trim()
                    .chars()
                    .take(300)
                    .collect(),
            ),
            Err(e) => HelperOutcome::Failed(format!("reading the helper's output: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn domains_are_validated() {
        for ok in ["malware-drop.test", "a.b.example", "x1.test"] {
            assert!(valid_domain(ok), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "192.0.2.10",
            "-x.test",
            "a..test",
            "UPPER.test",
            "x.test/path",
            "*.test",
            "a b.test",
        ] {
            assert!(!valid_domain(bad), "{bad}");
        }
    }

    #[test]
    fn only_loopback_http_is_accepted() {
        assert!(is_loopback_http("http://127.0.0.1/api"));
        assert!(is_loopback_http("http://127.0.0.1:8080/api"));
        assert!(is_loopback_http("http://[::1]:80/api"));
        assert!(!is_loopback_http("https://127.0.0.1/api"));
        assert!(!is_loopback_http("http://192.0.2.2/api"));
        assert!(!is_loopback_http("http://127.0.0.1.evil.test/api"));
    }

    /// A tiny fake Pi-hole: answers sign-in, block, unblock, and sign-out.
    fn fake_pihole() -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = format!("http://{}/api", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming().take(6) {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut length = 0;
                let mut sid = String::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header.trim().is_empty() {
                        break;
                    }
                    let lower = header.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                    if let Some(v) = lower.strip_prefix("x-ftl-sid:") {
                        sid = v.trim().to_owned();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let request = line
                    .split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ");
                log.lock().unwrap().push(format!(
                    "{request} sid={sid} {}",
                    String::from_utf8_lossy(&body)
                ));
                let (status, reply) = match request.as_str() {
                    "POST /api/auth" => ("200 OK", r#"{"session":{"valid":true,"sid":"s1"}}"#),
                    "POST /api/domains/deny/exact" => ("201 Created", "{}"),
                    _ => ("204 No Content", ""),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .unwrap();
            }
        });
        (api, seen)
    }

    #[test]
    fn pihole_block_signs_in_blocks_and_signs_out() {
        let (api, seen) = fake_pihole();
        let dir = tempfile::tempdir().unwrap();
        let password = dir.path().join("pw");
        std::fs::write(&password, "app-password\n").unwrap();
        let client = PiholeClient::new(&api, &password).unwrap();
        client
            .block("malware-drop.test", "GnomeHome run r1")
            .unwrap();
        client.unblock("malware-drop.test").unwrap();
        let log = seen.lock().unwrap().clone();
        assert!(log[0].starts_with("POST /api/auth") && log[0].contains("app-password"));
        assert!(log[1].starts_with("POST /api/domains/deny/exact sid=s1"));
        let body: Value = serde_json::from_str(
            log[1]
                .split_once(' ')
                .unwrap()
                .1
                .split_once("s1 ")
                .unwrap()
                .1,
        )
        .unwrap();
        assert_eq!(body["domain"], "malware-drop.test");
        assert_eq!(body["enabled"], true);
        assert!(log[2].starts_with("DELETE /api/auth sid=s1"));
        assert!(log[4].starts_with("DELETE /api/domains/deny/exact/malware-drop.test sid=s1"));
        assert!(client.block("192.0.2.10", "x").is_err()); // never reaches the network
    }

    #[test]
    fn a_non_loopback_api_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let password = dir.path().join("pw");
        std::fs::write(&password, "x").unwrap();
        assert!(PiholeClient::new("http://192.0.2.2/api", &password).is_err());
    }
}
