//! What the window says about certificates, in words: dates, purposes, how
//! soon one expires, and a name to suggest for one being added.

/// The purposes a certificate can be trusted for, as trustd names them and
/// as a person reads them, the one every addition has first.
pub const PURPOSES: [(&str, &str, &str); 4] = [
    ("ServerAuth", "Server Authentication", "p-server"),
    ("ClientAuth", "Client Authentication", "p-client"),
    ("CodeSigning", "Code Signing", "p-code"),
    ("EmailProtection", "Email Protection", "p-email"),
];

/// A purpose as a person reads it.
pub fn purpose(name: &str) -> String {
    PURPOSES
        .iter()
        .find(|(id, ..)| id.eq_ignore_ascii_case(name))
        .map(|(_, words, _)| words.to_string())
        .unwrap_or_else(|| name.to_string())
}

/// Purposes as a person reads them, together.
pub fn purposes(names: &[String]) -> String {
    if names.is_empty() {
        return purpose("ServerAuth");
    }
    names.iter().map(|name| purpose(name)).collect::<Vec<_>>().join(", ")
}

/// A day, as "18 Jan 2038".
pub fn date(seconds: i64) -> String {
    match jiff::Timestamp::from_second(seconds) {
        Ok(at) => at.strftime("%-d %b %Y").to_string(),
        Err(_) => "an unreadable date".into(),
    }
}

/// How near a certificate is to expiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    Fine,
    /// Within 90 days.
    Soon,
    Past,
}

pub fn expiry(not_after: i64, now: i64) -> Expiry {
    const SOON: i64 = 90 * 24 * 60 * 60;
    if not_after <= now {
        Expiry::Past
    } else if not_after - now <= SOON {
        Expiry::Soon
    } else {
        Expiry::Fine
    }
}

/// What to suggest calling a certificate being added: its name, lower case,
/// with anything but letters and digits made a single dash.
pub fn suggested_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let out: String = out.trim_end_matches('-').chars().take(48).collect();
    let out = out.trim_end_matches('-').to_string();
    if out.is_empty() { "added-ca".into() } else { out }
}

/// A fingerprint as other tools print it: upper case, a colon between bytes.
pub fn colons(fingerprint: &str) -> String {
    fingerprint
        .as_bytes()
        .chunks(2)
        .map(|pair| String::from_utf8_lossy(pair).to_uppercase())
        .collect::<Vec<_>>()
        .join(":")
}

/// "1 certificate", "2 certificates".
pub fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 { format!("1 {one}") } else { format!("{n} {many}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_suggested_name_is_a_usable_one() {
        assert_eq!(suggested_name("Example Corp Root CA"), "example-corp-root-ca");
        assert_eq!(suggested_name("  --DigiCert, Inc.  "), "digicert-inc");
        assert_eq!(suggested_name("!!!"), "added-ca");
        assert!(trust::usable_name(&suggested_name("a/b\\c")));
    }

    #[test]
    fn expiry_is_told_by_how_far_off_it_is() {
        assert_eq!(expiry(100, 200), Expiry::Past);
        assert_eq!(expiry(200 + 86_400, 200), Expiry::Soon);
        assert_eq!(expiry(200 + 100 * 86_400, 200), Expiry::Fine);
    }

    #[test]
    fn dates_and_fingerprints_read_as_people_expect() {
        assert_eq!(date(2_147_471_999), "18 Jan 2038");
        assert_eq!(colons("0a1b"), "0A:1B");
        assert_eq!(purposes(&[]), "Server Authentication");
        assert_eq!(purposes(&["ServerAuth".into(), "CodeSigning".into()]), "Server Authentication, Code Signing");
    }
}
