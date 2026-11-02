//! Ely.by accounts (https://ely.by), an authlib-injector / Yggdrasil-compatible service.
//!
//! An Ely.by account never replaces the Microsoft owner gate: Play still needs a Microsoft
//! account that owns Minecraft: Java Edition. When the gate passes and the player chose
//! Ely.by (`horizon-launcher account elyby use`), the game gets an Ely.by session instead of the
//! Microsoft one, to join servers that authenticate players through Ely.by.
//!
//! Tokens go to the same secret store as Microsoft ones, under `elyby:<uuid>`; accounts.json
//! keeps only the public name and UUID.

use super::SecretStore;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The Ely.by authentication server. `HORIZON_ELYBY_AUTH` overrides it (tests, mocks).
pub fn auth_server() -> String {
    std::env::var("HORIZON_ELYBY_AUTH")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://authserver.ely.by".to_owned())
}

/// The public half of an Ely.by account, kept in accounts.json.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ElyAccount {
    pub uuid: String,
    pub name: String,
    /// The game gets this account's session (instead of the Microsoft one) once the owner gate
    /// passed.
    #[serde(default)]
    pub play: bool,
}

/// The secret half, in the keychain.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ElySecrets {
    pub access_token: String,
    pub client_token: String,
}
impl std::fmt::Debug for ElySecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ElySecrets(<hidden>)")
    }
}

fn key(uuid: &str) -> String {
    format!("elyby:{uuid}")
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .build()
}

fn post(path: &str, body: Value) -> Result<Option<Value>, String> {
    let url = format!("{}{path}", auth_server());
    match agent()
        .post(&url)
        .set("Content-Type", "application/json; charset=utf-8")
        .send_string(&body.to_string())
    {
        Ok(r) => {
            let text = r.into_string().unwrap_or_default();
            Ok(serde_json::from_str(&text).ok())
        }
        Err(ureq::Error::Status(status, r)) => {
            let v: Value =
                serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null);
            let msg = v
                .get("errorMessage")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            if msg.contains("two factor") {
                return Err("Ely.by asks for your two-factor code: pass it with --totp.".into());
            }
            Err(format!("Ely.by refused ({status}): {msg}"))
        }
        Err(ureq::Error::Transport(_)) => Err("Ely.by can't be reached right now.".into()),
    }
}

fn random_token() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| e.to_string())?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Parse the `selectedProfile` and tokens of an authenticate/refresh answer.
pub fn parse_answer(v: &Value) -> Result<(ElyAccount, ElySecrets), String> {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str).map(str::to_owned);
    let access_token = s("/accessToken").ok_or("Ely.by sent no access token")?;
    let client_token = s("/clientToken").ok_or("Ely.by sent no client token")?;
    let uuid = s("/selectedProfile/id").ok_or("This Ely.by account has no profile")?;
    let name = s("/selectedProfile/name").ok_or("This Ely.by account has no profile")?;
    Ok((
        ElyAccount {
            uuid,
            name,
            play: false,
        },
        ElySecrets {
            access_token,
            client_token,
        },
    ))
}

/// Sign in with the Ely.by login (name or e-mail) and password; `totp` for two-factor accounts.
pub fn sign_in(
    store: &dyn SecretStore,
    login: &str,
    password: &str,
    totp: Option<&str>,
) -> Result<ElyAccount, String> {
    let password = match totp {
        Some(code) => format!("{password}:{code}"),
        None => password.to_owned(),
    };
    let answer = post(
        "/auth/authenticate",
        json!({
            "username": login,
            "password": password,
            "clientToken": random_token()?,
            "requestUser": true,
        }),
    )?
    .ok_or("Ely.by's answer is not valid JSON")?;
    let (account, secrets) = parse_answer(&answer)?;
    save(store, &account.uuid, &secrets)?;
    Ok(account)
}

fn save(store: &dyn SecretStore, uuid: &str, secrets: &ElySecrets) -> Result<(), String> {
    let text = serde_json::to_string(secrets).map_err(|e| e.to_string())?;
    store.set(&key(uuid), &text)
}

fn load(store: &dyn SecretStore, uuid: &str) -> Option<ElySecrets> {
    store
        .get(&key(uuid))
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// A valid access token for the game: validated, refreshed when Ely.by says it expired.
pub fn renew(store: &dyn SecretStore, account: &ElyAccount) -> Result<ElySecrets, String> {
    let secrets = load(store, &account.uuid)
        .ok_or_else(|| format!("{} is no longer signed in to Ely.by.", account.name))?;
    if post(
        "/auth/validate",
        json!({ "accessToken": secrets.access_token }),
    )
    .is_ok()
    {
        return Ok(secrets);
    }
    let answer = post(
        "/auth/refresh",
        json!({
            "accessToken": secrets.access_token,
            "clientToken": secrets.client_token,
            "requestUser": true,
        }),
    )
    .map_err(|e| format!("{e} Sign in to Ely.by again."))?
    .ok_or("Ely.by's answer is not valid JSON")?;
    let (_, renewed) = parse_answer(&answer)?;
    save(store, &account.uuid, &renewed)?;
    Ok(renewed)
}

/// Sign out: the token is invalidated (when Ely.by answers) and leaves the store.
pub fn sign_out(store: &dyn SecretStore, account: &ElyAccount) -> Result<(), String> {
    if let Some(s) = load(store, &account.uuid) {
        let _ = post(
            "/auth/invalidate",
            json!({ "accessToken": s.access_token, "clientToken": s.client_token }),
        );
    }
    store.delete(&key(&account.uuid))
}

/// The game's session file for an Ely.by account (`user_type: "elyby"`), private and read once,
/// like the Microsoft one.
pub fn write_session_file(
    dir: &Path,
    account: &ElyAccount,
    secrets: &ElySecrets,
) -> Result<PathBuf, String> {
    super::write_private_session(
        dir,
        &json!({
            "name": account.name,
            "uuid": account.uuid,
            "access_token": secrets.access_token,
            "user_type": "elyby",
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_parse() {
        let v = json!({
            "accessToken": "a", "clientToken": "c",
            "selectedProfile": {"id": "ffc8fdc95824509e8a57c99b940fb996", "name": "ErickSkrauch"}
        });
        let (acc, sec) = parse_answer(&v).unwrap();
        assert_eq!(acc.name, "ErickSkrauch");
        assert_eq!(sec.access_token, "a");
        assert!(parse_answer(&json!({"accessToken": "a"})).is_err());
        assert_eq!(format!("{sec:?}"), "ElySecrets(<hidden>)");
    }
}
