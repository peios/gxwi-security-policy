//! The settings page: whether trustd also writes the certificate files
//! under /etc/ssl, how it is faring, and who may change trust.

use libgxwi::settings::{self, Glyph, Kind, More, Tile, Tone};
use libtrust::Health;

use crate::policy::Asking;
use crate::store::Store;

/// Where a rendered file is, as programs see it: the registry-derived layer
/// of /etc appears at /etc.
fn as_seen(path: &str) -> String {
    match path.strip_prefix("/system/retc/") {
        Some(rest) => format!("/etc/{rest}"),
        None => path.to_string(),
    }
}

pub fn render(store: &Store, asking: Option<&Asking>) -> String {
    let mut page = settings::head(Glyph::Server, Tile::Slate, "Settings", "How trusted certificates reach programs, and who can change them.");

    // The trust service.
    let (state, about) = match &store.status {
        None => (settings::pill("Not Answering", Tone::Bad), "Programs keep trusting what they trusted before.".to_string()),
        Some(status) if status.health == Health::Degraded => (
            settings::pill("Needs Attention", Tone::Bad),
            status.message.clone().unwrap_or_else(|| "It couldn't bring the certificates up to date.".into()),
        ),
        Some(_) => (settings::pill("Up to Date", Tone::Good), "Keeps the trusted certificates current and tells programs when they change.".into()),
    };
    let reload = if store.may_reload && store.status.is_some() { settings::button("Reload", "reload", &[], Kind::Plain, true) } else { String::new() };
    page.push_str(&settings::group(
        "Trust Service",
        &settings::row("Status", &about, &format!("{state}{reload}")),
        "",
    ));

    // The files under /etc/ssl.
    if let Some(status) = &store.status {
        let mut rows = settings::row(
            "Certificate Files",
            "For programs that read trusted certificates from /etc/ssl rather than asking the trust service. Most programs do.",
            &settings::switch("compat", "Certificate Files", store.may_compat.is_ok()),
        );
        if asking == Some(&Asking::CompatOff) {
            rows.push_str(&settings::more(
                More::Asking,
                &format!(
                    "<p>Turn off certificate files? Programs that read /etc/ssl, which includes curl, Python and Go programs, will fail to check any secure connection. Turn them off only where every program asks the trust service.</p>{}",
                    settings::actions(&format!(
                        "{}{}",
                        settings::focused_button("Cancel", "cancel", Kind::Plain),
                        settings::button("Turn Off", "compat-off", &[], Kind::Danger, true)
                    ))
                ),
            ));
        }
        for path in &status.rendered {
            let label = if path.ends_with("ca-certificates.crt") { "Bundle" } else { "OpenSSL File" };
            rows.push_str(&settings::fact(label, &as_seen(path), true));
        }
        if status.compat_mode != 0 {
            rows.push_str(&settings::fact("OpenSSL Directory", "/etc/ssl/certs", true));
        }
        let foot = match &store.may_compat {
            Ok(()) => settings::hint("The files are written by the trust service and rewritten on every change. Editing one changes nothing."),
            Err(why) => settings::locked(why),
        };
        page.push_str(&settings::group("Linux Compatibility", &rows, &foot));
    }

    // Who may change it.
    let rows = format!(
        "{}{}",
        settings::row(
            "Changing Trust",
            "Who can add, remove and distrust certificates, and turn certificate files on and off.",
            &settings::button("Permissions…", "perm-trust", &[], Kind::Plain, true)
        ),
        settings::row(
            "Trust Service",
            "Who can ask the trust service to reload.",
            &settings::button("Permissions…", "perm-service", &[], Kind::Plain, true)
        ),
    );
    page.push_str(&settings::group("Permissions", &rows, ""));
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_files_are_named_where_programs_find_them() {
        assert_eq!(as_seen("/system/retc/ssl/cert.pem"), "/etc/ssl/cert.pem");
        assert_eq!(as_seen("/elsewhere"), "/elsewhere");
    }
}
