//! The certificates pages: every certificate in force, one of them, one
//! being added, and those distrusted.

use libgxwi::settings::{self, Glyph, Kind, More, Tile, Tone, Width};
use libgxwi::{Fields, escape};
use libtrust::{Health, Source};

use crate::policy::{Asking, Candidate};
use crate::store::{Cert, Store};
use crate::words::{self, Expiry};

/// A small icon for a certificate in a list: green for one Peios ships,
/// blue for one this machine added.
fn badge(source: Source) -> String {
    settings::icon(Glyph::Certificate, if source == Source::Added { Tile::Blue } else { Tile::Green })
}

/// How near it is to expiring, where that is worth saying.
fn expiry_pill(not_after: i64, now: i64) -> String {
    match words::expiry(not_after, now) {
        Expiry::Fine => String::new(),
        Expiry::Soon => settings::pill("Expires Soon", Tone::Warn),
        Expiry::Past => settings::pill("Expired", Tone::Bad),
    }
}

fn row(cert: &Cert, now: i64) -> String {
    let added = cert.root.name.as_ref().map(|name| format!("Added as {name}"));
    let line = added.as_deref().or(cert.organisation()).unwrap_or("");
    let lines: Vec<(&str, bool)> = if line.is_empty() { Vec::new() } else { vec![(line, false)] };
    let pill = expiry_pill(cert.root.not_after, now);
    let aside = if pill.is_empty() {
        // The year is enough to tell one from another; the day is inside.
        let year = words::date(cert.root.not_after).rsplit(' ').next().unwrap_or_default().to_string();
        format!(r#"<span class="until">Expires {}</span>"#, escape(&year))
    } else {
        pill
    };
    settings::link(&badge(cert.root.source), cert.name(), &lines, &aside, "open", &[("cert", &cert.root.fingerprint)])
}

/// How many are trusted, large, and the store's health, before the list.
fn hero(store: &Store, roots: &[Cert]) -> String {
    let added = roots.iter().filter(|c| c.root.source == Source::Added).count();
    let shipped = roots.len() - added;
    let under = match added {
        0 => "certificate authorities trusted, all shipped with Peios".to_string(),
        n => format!("certificate authorities trusted: {shipped} shipped with Peios, {n} added on this machine"),
    };
    let degraded = store.status.as_ref().filter(|s| s.health == Health::Degraded);
    let right = match degraded {
        Some(_) => {
            let again = if store.may_reload { settings::button("Try Again", "reload", &[], Kind::Plain, true) } else { String::new() };
            format!("{}{again}", settings::pill("Needs Attention", Tone::Bad))
        }
        None => settings::pill("Up to Date", Tone::Good),
    };
    let mut out = settings::hero(&settings::big(&roots.len().to_string(), &under), &right);
    if let Some(status) = degraded {
        let why = status.message.as_deref().unwrap_or("the reason wasn't given");
        out.push_str(&settings::caution(&format!(
            "The trust service couldn't bring the certificates up to date: {why}. Programs keep trusting what they trusted before."
        )));
    }
    if let Some(status) = &store.status
        && status.skipped > 0
    {
        out.push_str(&settings::caution(&format!(
            "{} couldn't be used. The trust service's log says why.",
            words::count(status.skipped as usize, "added or distrusted entry", "added or distrusted entries")
        )));
    }
    out
}

/// Every certificate in force, narrowed to what the search finds.
pub fn list(store: &Store, fields: &Fields, now: i64, choosing: bool) -> String {
    let mut page = settings::head(
        Glyph::Certificate,
        Tile::Green,
        "Trusted Certificates",
        "The authorities this machine accepts when a program checks a secure connection.",
    );
    if store.may.is_err() {
        page.push_str(&settings::banner(store.may.as_ref().err().map(String::as_str).unwrap_or_default()));
    }
    let roots = match &store.roots {
        Ok(roots) => roots,
        Err(why) => {
            page.push_str(&settings::group(
                "",
                &settings::row("The trust service isn't answering", why, ""),
                &settings::note("Programs keep trusting what they trusted before. This page fills in when it's back."),
            ));
            return page;
        }
    };
    page.push_str(&hero(store, roots));
    let add = if store.may.is_ok() { settings::button("Add Certificate…", "choose-file", &[], Kind::Primary, !choosing) } else { String::new() };
    page.push_str(&settings::search("search", "Search certificates", "Search by name, organisation or fingerprint", &add));

    let words = fields.get("search").trim().to_lowercase();
    let found: Vec<&Cert> = roots.iter().filter(|c| words.is_empty() || c.matches(&words)).collect();
    if found.is_empty() {
        page.push_str(&settings::group("", &settings::row(&format!("No certificates match “{}”", fields.get("search").trim()), "", ""), ""));
        return page;
    }
    let added: String = found.iter().filter(|c| c.root.source == Source::Added).map(|c| row(c, now)).collect();
    let shipped: String = found.iter().filter(|c| c.root.source == Source::Shipped).map(|c| row(c, now)).collect();
    if !added.is_empty() {
        page.push_str(&settings::group("Added on This Machine", &added, ""));
    }
    if !shipped.is_empty() {
        page.push_str(&settings::group("Shipped with Peios", &shipped, ""));
    }
    page
}

/// A fact too long to sit beside its name, a fingerprint or a serial: its
/// name with the value under it, and a button to copy it when `copy` is
/// what to copy.
fn long(label: &str, shown: &str, copy: Option<&str>) -> String {
    let button = match copy {
        Some(text) => format!(r#"<button type="button" class="st-button" fx-copy="text" fx-value-text="{}">Copy</button>"#, escape(text)),
        None => String::new(),
    };
    format!(
        r#"<div class="st-row fact long"><span class="label"><b>{}</b><code class="st-mono">{}</code></span><span class="control">{button}</span></div>"#,
        escape(label),
        escape(shown)
    )
}

/// Who issued it, in words: a root certificate issues itself.
fn issuer(details: &trust::Details) -> String {
    if details.issuer == details.subject { "Itself (a root certificate)".to_string() } else { details.issuer.clone() }
}

/// What a certificate says about itself beyond its name, which is shown
/// above it.
fn facts(details: &trust::Details, fingerprint: &str) -> String {
    let mut rows = String::new();
    if let Some(unit) = &details.unit {
        rows.push_str(&settings::fact("Unit", unit, false));
    }
    if let Some(country) = &details.country {
        rows.push_str(&settings::fact("Country", country, false));
    }
    rows.push_str(&settings::fact("Issued By", &issuer(details), false));
    rows.push_str(&settings::fact("Valid From", &words::date(details.not_before), false));
    rows.push_str(&settings::fact("Expires", &words::date(details.not_after), false));
    rows.push_str(&settings::fact("Public Key", &details.key, false));
    rows.push_str(&long("Serial Number", &details.serial, None));
    rows.push_str(&long("SHA-256 Fingerprint", &words::colons(fingerprint), Some(fingerprint)));
    settings::group("Certificate", &rows, "")
}

/// One certificate in force: what it is, why it is trusted, and what may be
/// done with it.
pub fn detail(cert: &Cert, store: &Store, asking: Option<&Asking>, now: i64, choosing: bool) -> String {
    let mut page = settings::back("Trusted Certificates", "back");
    let fingerprint = cert.root.fingerprint.as_str();
    let tile = if cert.root.source == Source::Added { Tile::Blue } else { Tile::Green };
    let about = cert.organisation().map(str::to_string).unwrap_or_else(|| cert.details.subject.clone());
    let state = match words::expiry(cert.root.not_after, now) {
        Expiry::Past => settings::pill("Expired", Tone::Bad),
        Expiry::Soon => settings::pill("Expires Soon", Tone::Warn),
        Expiry::Fine => settings::pill("Trusted", Tone::Good),
    };
    page.push_str(&settings::hero(&settings::hero_title(Glyph::Certificate, tile, cert.name(), &about), &state));
    if store.may.is_err() {
        page.push_str(&settings::banner(store.may.as_ref().err().map(String::as_str).unwrap_or_default()));
    }
    page.push_str(&facts(&cert.details, fingerprint));

    let source = match &cert.root.name {
        Some(name) => format!("Added on this machine as {name}"),
        None => "Shipped with Peios".to_string(),
    };
    let trust_rows = format!(
        "{}{}",
        settings::fact("Source", &source, false),
        settings::fact("Trusted For", &words::purposes(&cert.root.purposes), false)
    );
    page.push_str(&settings::group("Trust", &trust_rows, ""));

    let may = store.may.is_ok();
    let values = [("cert", fingerprint)];
    let mut rows = settings::row(
        "Export",
        "Save it as a PEM file, to use elsewhere.",
        &settings::button("Export…", "export", &values, Kind::Plain, !choosing),
    );
    if may {
        let asked = |what: &Asking| asking == Some(what);
        rows.push_str(&settings::row(
            "Distrust",
            "Stop trusting it. Programs refuse certificates it issued.",
            &settings::button("Distrust…", "ask-distrust", &values, Kind::Danger, !asked(&Asking::Distrust(fingerprint.into()))),
        ));
        if asked(&Asking::Distrust(fingerprint.into())) {
            rows.push_str(&settings::more(
                More::Asking,
                &format!(
                    r#"<p>Stop trusting {}? Every program on this machine refuses certificates it issued within a few seconds. You can trust it again under Distrusted.</p><div class="fields"><label>Reason<input class="st-input wide" name="reason" placeholder="Optional: why, for whoever reads it later" autocomplete="off"></label></div>{}"#,
                    escape(cert.name()),
                    settings::actions(&format!(
                        "{}{}",
                        settings::focused_button("Cancel", "cancel", Kind::Plain),
                        settings::button("Distrust", "distrust", &values, Kind::Danger, true)
                    ))
                ),
            ));
        }
        if cert.root.source == Source::Added {
            rows.push_str(&settings::row(
                "Remove",
                "Take back adding it. It's no longer trusted.",
                &settings::button("Remove…", "ask-remove", &values, Kind::Danger, !asked(&Asking::Remove(fingerprint.into()))),
            ));
            if asked(&Asking::Remove(fingerprint.into())) {
                rows.push_str(&settings::more(
                    More::Asking,
                    &format!(
                        "<p>Remove {}? Programs on this machine stop trusting it within a few seconds. Adding it again needs the file.</p>{}",
                        escape(cert.name()),
                        settings::actions(&format!(
                            "{}{}",
                            settings::focused_button("Cancel", "cancel", Kind::Plain),
                            settings::button("Remove", "remove", &values, Kind::Danger, true)
                        ))
                    ),
                ));
            }
        }
    }
    page.push_str(&settings::group("", &rows, ""));
    page
}

/// A certificate read from a file, before it is added: what it is, and the
/// form to add it, or why it can't be.
pub fn adding(candidate: &Candidate, store: &Store, now: i64, choosing: bool) -> String {
    let mut page = settings::back("Trusted Certificates", "cancel-add");
    page.push_str(&settings::head(
        Glyph::Certificate,
        Tile::Blue,
        "Add Certificate",
        "Trust a certificate authority Peios doesn't ship, such as your organisation's own.",
    ));
    let details = &candidate.details;
    let state = if candidate.problem.is_some() {
        settings::pill("Can't Be Added", Tone::Bad)
    } else if words::expiry(details.not_after, now) == Expiry::Soon {
        settings::pill("Expires Soon", Tone::Warn)
    } else {
        settings::pill("Ready to Add", Tone::Good)
    };
    if let Some(problem) = &candidate.problem {
        page.push_str(&settings::caution(problem));
    }
    // What it is, briefly: enough to recognise it before trusting it.
    let from = format!("From {}", candidate.file);
    let mut lines: Vec<(&str, bool)> = Vec::new();
    if let Some(organisation) = details.organisation.as_deref().filter(|o| *o != details.name()) {
        lines.push((organisation, false));
    }
    lines.push((&from, false));
    let mut rows = settings::item(&settings::icon(Glyph::Certificate, Tile::Blue), details.name(), &lines, &state);
    rows.push_str(&settings::fact("Issued By", &issuer(details), false));
    rows.push_str(&settings::fact("Expires", &words::date(details.not_after), false));
    rows.push_str(&settings::fact("Public Key", &details.key, false));
    rows.push_str(&long("SHA-256 Fingerprint", &words::colons(&candidate.fingerprint), Some(&candidate.fingerprint)));
    page.push_str(&settings::group("Certificate", &rows, ""));

    if candidate.problem.is_some() {
        page.push_str(&settings::actions(&format!(
            "{}{}",
            settings::button("Cancel", "cancel-add", &[], Kind::Plain, true),
            settings::button("Choose Another File…", "choose-file", &[], Kind::Primary, !choosing)
        )));
        return page;
    }
    if let Err(why) = &store.may {
        page.push_str(&settings::banner(why));
        return page;
    }
    let mut rows = settings::row(
        "Name",
        "What it's called on this machine. Letters, digits and dashes read best.",
        &settings::text("add-name", "Name", "text", Width::Normal, true, r#"autocomplete="off" spellcheck="false""#),
    );
    for (_, label, field) in words::PURPOSES {
        rows.push_str(&settings::row(label, "", &settings::switch(field, label, true)));
    }
    let form = format!(
        r#"<form fx-submit="add">{}{}</form>"#,
        settings::group(
            "Add As",
            &rows,
            &settings::hint("This version of Peios uses certificates for Server Authentication. The other purposes are kept for when it uses them.")
        ),
        settings::actions(&format!(
            "{}{}",
            settings::button("Cancel", "cancel-add", &[], Kind::Plain, true),
            settings::submit("Add Certificate", Kind::Primary, true)
        ))
    );
    page.push_str(&form);
    page
}

/// What this machine refuses, and the form to refuse one it doesn't have.
pub fn distrusted(store: &Store, asking: Option<&Asking>) -> String {
    let mut page = settings::head(
        Glyph::Blocked,
        Tile::Red,
        "Distrusted Certificates",
        "Certificates this machine refuses, wherever they come from.",
    );
    let may = store.may.is_ok();
    if let Err(why) = &store.may {
        page.push_str(&settings::banner(why));
    }
    let list = match &store.distrusted {
        Ok(list) => list,
        Err(why) => {
            page.push_str(&settings::group("", &settings::row("What's distrusted can't be read", why, ""), ""));
            return page;
        }
    };
    let mut rows = String::new();
    for refused in list {
        let values = [("cert", refused.fingerprint.as_str())];
        let reason = if refused.reason.is_empty() { "No reason given".to_string() } else { refused.reason.clone() };
        let name = refused.known.as_ref().map(|d| d.name().to_string()).unwrap_or_else(|| "Certificate Not on This Machine".to_string());
        let asked = asking == Some(&Asking::Restore(refused.fingerprint.clone()));
        let control = if may { settings::button("Trust Again…", "ask-restore", &values, Kind::Plain, !asked) } else { String::new() };
        rows.push_str(&settings::item(
            &settings::icon(Glyph::Blocked, Tile::Red),
            &name,
            &[(&reason, false), (&words::colons(&refused.fingerprint), true)],
            &control,
        ));
        if asked {
            rows.push_str(&settings::more(
                More::Asking,
                &format!(
                    "<p>Trust {} again? Programs on this machine accept certificates it issued within a few seconds{}.</p>{}",
                    escape(&name),
                    if refused.known.is_none() { ", if it ever arrives" } else { "" },
                    settings::actions(&format!(
                        "{}{}",
                        settings::focused_button("Cancel", "cancel", Kind::Plain),
                        settings::button("Trust Again", "restore", &values, Kind::Primary, true)
                    ))
                ),
            ));
        }
    }
    if rows.is_empty() {
        rows = settings::row("Nothing is distrusted", "Every certificate under Trusted is accepted.", "");
    }
    page.push_str(&settings::group("", &rows, ""));

    if may {
        let open = asking == Some(&Asking::ByFingerprint);
        let mut more = settings::row(
            "Distrust by Fingerprint",
            "For a certificate this machine doesn't have. It's refused if it ever arrives.",
            &settings::button("Distrust by Fingerprint…", "ask-by-fingerprint", &[], Kind::Plain, !open),
        );
        if open {
            more.push_str(&settings::more(
                More::Form,
                &format!(
                    r#"<form fx-submit="distrust-by-fingerprint"><div class="fields fingerprint"><label>SHA-256 Fingerprint<input class="st-input wide mono" name="by-fp" placeholder="64 hex digits, colons or not" autocomplete="off" spellcheck="false"></label><label>Reason<input class="st-input wide" name="by-reason" placeholder="Optional" autocomplete="off"></label></div>{}</form>"#,
                    settings::actions(&format!(
                        "{}{}",
                        settings::button("Cancel", "cancel", &[], Kind::Plain, true),
                        settings::submit("Distrust", Kind::Danger, true)
                    ))
                ),
            ));
        }
        page.push_str(&settings::group("Distrust Another", &more, ""));
    }
    page
}
