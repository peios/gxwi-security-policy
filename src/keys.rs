//! The code-signing keys: the public keys this kernel verifies signatures
//! with, as it lists them in `kacs/signing_keys`. They are compiled into
//! the kernel, so nothing here changes them; only a new kernel does.

use libgxwi::settings::{self, Glyph, Tile};
use libgxwi::escape;

/// Where the kernel lists its keys.
pub const LISTING: &str = "/sys/kernel/security/kacs/signing_keys";

/// One key, as the kernel lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey {
    /// SHA-256 of the raw public key, lowercase hex.
    pub sha256: String,
    pub pip_type: u32,
    pub pip_trust: u32,
}

/// Why the keys can't be shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unlisted {
    /// The kernel has no listing: one from before it had one.
    Absent,
    Denied,
    Other(String),
}

/// The keys in a listing. A line that isn't one is left out.
pub fn parse(text: &str) -> Vec<SigningKey> {
    text.lines()
        .filter_map(|line| {
            let (mut sha256, mut pip_type, mut pip_trust) = (None, None, None);
            for word in line.split_whitespace() {
                match word.split_once('=')? {
                    ("key_sha256", hex) if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                        sha256 = Some(hex.to_ascii_lowercase())
                    }
                    ("pip_type", n) => pip_type = n.parse().ok(),
                    ("pip_trust", n) => pip_trust = n.parse().ok(),
                    _ => {}
                }
            }
            Some(SigningKey { sha256: sha256?, pip_type: pip_type?, pip_trust: pip_trust? })
        })
        .collect()
}

/// The kernel's keys, read now.
pub fn read() -> Result<Vec<SigningKey>, Unlisted> {
    match std::fs::read_to_string(LISTING) {
        Ok(text) => Ok(parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Unlisted::Absent),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(Unlisted::Denied),
        Err(e) => Err(Unlisted::Other(e.to_string())),
    }
}

/// A PIP type in words.
fn kind(pip_type: u32) -> String {
    match pip_type {
        512 => "Protected".into(),
        1024 => "Isolated".into(),
        n => format!("Type {n}"),
    }
}

/// A PIP trust level in words.
fn trust(pip_trust: u32) -> String {
    match pip_trust {
        8192 => "Peios TCB".into(),
        4096 => "Peios".into(),
        2048 => "App".into(),
        1536 => "Antimalware".into(),
        1024 => "Authenticode".into(),
        n => format!("Trust {n}"),
    }
}

/// What a key is for, as its name.
fn name(key: &SigningKey) -> String {
    match (key.pip_type, key.pip_trust) {
        (512, 8192) => "Peios System Key".into(),
        (_, 4096) => "Peios Key".into(),
        (_, 2048) => "App Key".into(),
        _ => "Signing Key".into(),
    }
}

pub fn render(keys: &Result<Vec<SigningKey>, Unlisted>) -> String {
    let mut page = settings::head(
        Glyph::Key,
        Tile::Violet,
        "Code-Signing Keys",
        "The keys this machine trusts to sign the programs it protects most.",
    );
    let keys = match keys {
        Ok(keys) => keys,
        Err(unlisted) => {
            let (what, why) = match unlisted {
                Unlisted::Absent => ("This kernel doesn't list its keys", "A newer kernel shows them here."),
                Unlisted::Denied => ("You can't read the kernel's keys", "Reading them needs access to the kernel's security files."),
                Unlisted::Other(e) => ("The kernel's keys couldn't be read", e.as_str()),
            };
            page.push_str(&settings::group("", &settings::row(what, why, ""), ""));
            return page;
        }
    };
    let mut rows = String::new();
    for key in keys {
        let level = format!("Programs it signs run {}, {}", kind(key.pip_type), trust(key.pip_trust));
        rows.push_str(&settings::item(&settings::icon(Glyph::Key, Tile::Violet), &name(key), &[(&level, false)], ""));
        rows.push_str(&format!(
            r#"<div class="st-row fact long"><span class="label"><b>SHA-256 Fingerprint</b><code class="st-mono">{}</code></span><span class="control"><button type="button" class="st-button" fx-copy="text" fx-value-text="{}">Copy</button></span></div>"#,
            escape(&crate::words::colons(&key.sha256)),
            escape(&key.sha256)
        ));
    }
    if rows.is_empty() {
        rows = settings::row("No keys", "This kernel trusts no signature, so no program runs protected.", "");
    }
    page.push_str(&settings::group(
        "",
        &rows,
        &settings::note(
            "Only a program signed with one of these keys runs with process integrity protection. The keys are built into the kernel: nothing on a running machine adds or removes one.",
        ),
    ));
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_reads_as_its_keys() {
        let hex = "ab".repeat(32);
        let listing = format!("key_sha256={hex} pip_type=512 pip_trust=8192\nnonsense\nkey_sha256=zz pip_type=1 pip_trust=2\n");
        assert_eq!(parse(&listing), vec![SigningKey { sha256: hex, pip_type: 512, pip_trust: 8192 }]);
        assert!(parse("").is_empty());
    }

    #[test]
    fn the_system_key_is_named_for_what_it_is() {
        let key = SigningKey { sha256: String::new(), pip_type: 512, pip_trust: 8192 };
        assert_eq!(name(&key), "Peios System Key");
        assert_eq!(format!("{}, {}", kind(512), trust(8192)), "Protected, Peios TCB");
    }
}
