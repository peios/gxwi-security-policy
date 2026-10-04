//! The window: what this machine trusts, in sections down the side, the one
//! chosen beside them.
//!
//! Everything is read as the person and changed as the person: what they
//! may change is asked of the system (`trust::may_change` and friends), and
//! what they may not is shown as it is, with the reason said once. Anything
//! that widens or narrows what every program on the machine accepts asks
//! first, under its row, with the safe answer the keyboard's.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use gxwi_file_dialog::{Filter, Mode, Request as Choose};
use libgxwi::settings::{self, Glyph, Nav, Section, Tile};
use libgxwi::{Facts, Fields, Live, Surface, Value};
use trust::{Details, cert};

use crate::store::{self, Known, LOOK_ONLY, Store};
use crate::{certificates, keys, options, permissions, words};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Trusted,
    Distrusted,
    Settings,
    Keys,
}

impl View {
    const ALL: [(View, &'static str); 4] =
        [(View::Trusted, "trusted"), (View::Distrusted, "distrusted"), (View::Settings, "settings"), (View::Keys, "keys")];

    fn by(name: &str) -> Option<View> {
        View::ALL.iter().find(|(_, by)| *by == name).map(|(view, _)| *view)
    }

    fn id(self) -> &'static str {
        View::ALL.iter().find(|(view, _)| *view == self).map(|(_, by)| *by).unwrap_or("trusted")
    }
}

/// What the trusted section shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    List,
    /// One certificate, by fingerprint.
    Certificate(String),
    /// A certificate chosen to be added.
    Adding(Box<Candidate>),
}

/// A certificate read from a file, to be added, and why it can't be if it
/// can't.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub file: String,
    pub der: Vec<u8>,
    pub fingerprint: String,
    pub details: Details,
    pub problem: Option<String>,
}

/// A question open under a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asking {
    Distrust(String),
    Remove(String),
    Restore(String),
    /// The form to distrust a certificate the machine doesn't have.
    ByFingerprint,
    CompatOff,
}

pub struct Policy {
    pub window: Weak<Surface<Policy>>,
    known: Arc<Known>,
    view: View,
    page: Page,
    store: Store,
    asking: Option<Asking>,
    /// A file dialog is open, for adding or for exporting.
    choosing: bool,
    /// Permissions editors open, by which.
    editing: Vec<&'static str>,
    /// What came of the last change: what was done, or why it wasn't.
    said: Option<Result<String, String>>,
}

impl Policy {
    pub fn new(known: Arc<Known>) -> Policy {
        Policy {
            window: Weak::new(),
            store: store::read_all(&known),
            known,
            view: View::Trusted,
            page: Page::List,
            asking: None,
            choosing: false,
            editing: Vec::new(),
            said: None,
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Puts what is set in every field that shows a setting.
    pub fn fill(&self, fields: &mut Fields) {
        let on = self.store.status.as_ref().is_none_or(|s| s.compat_mode != 0);
        fields.set("compat", if on { "on" } else { "" });
    }

    /// What was read again. A page about a certificate that has gone goes
    /// back to the list.
    pub fn heard(&mut self, read: Store, fields: &mut Fields) {
        self.store = read;
        if self.asking != Some(Asking::CompatOff) {
            self.fill(fields);
        }
        if let Page::Certificate(fingerprint) = &self.page
            && self.store.certificate(fingerprint).is_none()
            && self.store.roots.is_ok()
        {
            self.page = Page::List;
            self.asking = None;
        }
        if let Page::Adding(candidate) = &self.page {
            let problem = problem(&self.store, &candidate.der, &candidate.fingerprint);
            if let Page::Adding(candidate) = &mut self.page {
                candidate.problem = problem;
            }
        }
    }

    /// Reads everything again after a change, giving trustd a moment to
    /// act on it.
    fn changed(&mut self, fields: &mut Fields) {
        std::thread::sleep(std::time::Duration::from_millis(400));
        let read = store::read_all(&self.known);
        self.heard(read, fields);
    }

    fn nav(&self) -> Vec<Nav> {
        let section = |view: View, title, now: String, glyph, tile| Nav::Section(Section { id: view.id(), title, now, glyph, tile });
        let trusted = match (&self.store.roots, &self.store.status) {
            (Err(_), _) => "Unavailable".to_string(),
            (_, Some(status)) if status.health == libtrust::Health::Degraded => "Needs attention".to_string(),
            (Ok(roots), _) => format!("{} trusted", roots.len()),
        };
        let distrusted = match &self.store.distrusted {
            Ok(list) if list.is_empty() => "None".to_string(),
            Ok(list) => words::count(list.len(), "certificate", "certificates"),
            Err(_) => "Unavailable".to_string(),
        };
        let files = match &self.store.status {
            Some(status) if status.compat_mode == 0 => "Certificate files off",
            Some(_) => "Certificate files on",
            None => "",
        };
        let keys = match &self.store.keys {
            Ok(keys) => words::count(keys.len(), "key", "keys"),
            Err(_) => "Not listed".to_string(),
        };
        vec![
            Nav::Heading("Certificates"),
            section(View::Trusted, "Trusted", trusted, Glyph::Certificate, Tile::Green),
            section(View::Distrusted, "Distrusted", distrusted, Glyph::Blocked, Tile::Red),
            section(View::Settings, "Settings", files.to_string(), Glyph::Server, Tile::Slate),
            Nav::Heading("Code Signing"),
            section(View::Keys, "Signing Keys", keys, Glyph::Key, Tile::Violet),
        ]
    }

    /// Opens the file dialog for a certificate to add.
    fn choose_file(&mut self) {
        if self.choosing {
            return;
        }
        let request = Choose {
            mode: Mode::Open,
            title: "Add a certificate".into(),
            purpose: Some("A certificate authority for this machine to trust, as a PEM or DER file.".into()),
            folder: None,
            name: None,
            filters: vec![Filter {
                name: "Certificates".into(),
                extensions: ["pem", "crt", "cer", "der"].iter().map(|e| e.to_string()).collect(),
            }],
        };
        let window = self.window.clone();
        let opened = gxwi_file_dialog::choose(&request, move |file| {
            let Some(window) = window.upgrade() else { return };
            window.update(|policy, fields| {
                policy.choosing = false;
                if let Some(file) = file {
                    policy.read_candidate(&file, fields);
                }
            });
        });
        match opened {
            Ok(()) => self.choosing = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.said = Some(Err("The file dialog isn't installed.".into())),
            Err(e) => self.said = Some(Err(format!("The file dialog couldn't be opened: {e}."))),
        }
    }

    /// Reads the certificate in `file` and shows it, to be added.
    fn read_candidate(&mut self, file: &Path, fields: &mut Fields) {
        let shown = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| file.display().to_string());
        let bytes = match std::fs::read(file) {
            Ok(bytes) => bytes,
            Err(e) => return self.said = Some(Err(format!("{shown} couldn't be read: {e}."))),
        };
        let der = match trust::certificate(&bytes, &shown) {
            Ok(der) => der,
            Err(_) => return self.said = Some(Err(format!("{shown} holds more than one certificate. Add them one at a time."))),
        };
        let Ok(details) = cert::describe(&der) else {
            return self.said = Some(Err(format!("{shown} isn't a certificate.")));
        };
        let fingerprint = cert::fingerprint(&der);
        let problem = problem(&self.store, &der, &fingerprint);
        fields.set("add-name", &words::suggested_name(details.name()));
        for (purpose, _, field) in words::PURPOSES {
            fields.set(field, if purpose == "ServerAuth" { "on" } else { "" });
        }
        self.page = Page::Adding(Box::new(Candidate { file: shown, der, fingerprint, details, problem }));
        self.said = None;
    }

    /// Adds the certificate being looked at, as the form says.
    fn add(&mut self, fields: &mut Fields) -> Result<String, String> {
        let Page::Adding(candidate) = &self.page else { return Err("There's no certificate to add.".into()) };
        if let Some(problem) = &candidate.problem {
            return Err(problem.clone());
        }
        let name = fields.get("add-name").trim().to_string();
        if !trust::usable_name(&name) {
            return Err("Give it a name, without slashes.".into());
        }
        if self.store.added_names().iter().any(|n| n.eq_ignore_ascii_case(&name)) {
            return Err(format!("A certificate is already added as {name}."));
        }
        let purposes: Vec<String> =
            words::PURPOSES.iter().filter(|(_, _, field)| fields.get(field) == "on").map(|(id, ..)| id.to_string()).collect();
        if purposes.is_empty() {
            return Err("Choose at least one purpose.".into());
        }
        // ServerAuth alone is what an addition has unless told otherwise,
        // so it is written as nothing, as `trust add` writes it.
        let written: &[String] = if purposes == ["ServerAuth"] { &[] } else { &purposes };
        let called = candidate.details.name().to_string();
        trust::add(&name, &candidate.der, written).map_err(said_error)?;
        fields.set("add-name", "");
        self.page = Page::List;
        Ok(format!("{called} added. Programs trust it within a few seconds."))
    }

    /// Opens the file dialog for where to export a certificate.
    fn export(&mut self, fingerprint: &str) {
        if self.choosing {
            return;
        }
        let Some(cert) = self.store.certificate(fingerprint) else { return };
        let (der, called) = (cert.root.der.clone(), cert.name().to_string());
        let request = Choose {
            mode: Mode::Save,
            title: "Export a certificate".into(),
            purpose: Some(format!("{called} is saved as a PEM file.")),
            folder: None,
            name: Some(format!("{}.pem", words::suggested_name(&called))),
            filters: vec![Filter { name: "PEM certificates".into(), extensions: vec!["pem".into()] }],
        };
        let window = self.window.clone();
        let opened = gxwi_file_dialog::choose(&request, move |file: Option<PathBuf>| {
            let Some(window) = window.upgrade() else { return };
            window.update(|policy, _| {
                policy.choosing = false;
                let Some(file) = file else { return };
                policy.said = Some(match std::fs::write(&file, cert::to_pem(&der)) {
                    Ok(()) => Ok(format!("{called} exported to {}.", file.display())),
                    Err(e) => Err(format!("{called} couldn't be exported: {e}.")),
                });
            });
        });
        match opened {
            Ok(()) => self.choosing = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.said = Some(Err("The file dialog isn't installed.".into())),
            Err(e) => self.said = Some(Err(format!("The file dialog couldn't be opened: {e}."))),
        }
    }

    fn distrust(&mut self, fingerprint: &str, fields: &mut Fields) -> Result<String, String> {
        let called = self.store.certificate(fingerprint).map(|c| c.name().to_string());
        let reason = fields.get("reason").trim().to_string();
        trust::distrust(fingerprint, &reason).map_err(said_error)?;
        fields.set("reason", "");
        self.page = Page::List;
        Ok(match called {
            Some(name) => format!("{name} distrusted. Programs refuse it within a few seconds."),
            None => "Certificate distrusted.".into(),
        })
    }

    fn distrust_by_fingerprint(&mut self, fields: &mut Fields) -> Result<String, String> {
        let typed = fields.get("by-fp").trim().to_string();
        if typed.is_empty() {
            return Err("Enter the certificate's SHA-256 fingerprint.".into());
        }
        let roots: Vec<libtrust::Root> =
            self.store.roots.as_ref().map(|roots| roots.iter().map(|c| c.root.clone()).collect()).unwrap_or_default();
        let fingerprint = trust::fingerprint_in(&typed, &roots).map_err(|e| match e {
            trust::Error::NotFound(_) => "No trusted certificate starts with that. Give the whole fingerprint for one this machine doesn't have.".to_string(),
            other => capitalised(&other.to_string()),
        })?;
        if self.store.refused(&fingerprint).is_some() {
            return Err("That certificate is distrusted already.".into());
        }
        let called = self.store.certificate(&fingerprint).map(|c| c.name().to_string());
        let reason = fields.get("by-reason").trim().to_string();
        trust::distrust(&fingerprint, &reason).map_err(said_error)?;
        fields.set("by-fp", "");
        fields.set("by-reason", "");
        Ok(match called {
            Some(name) => format!("{name} distrusted. Programs refuse it within a few seconds."),
            None => "Distrusted. It's refused if it ever arrives.".into(),
        })
    }

    fn remove(&mut self, fingerprint: &str) -> Result<String, String> {
        let Some(cert) = self.store.certificate(fingerprint) else { return Err("That certificate has gone.".into()) };
        let Some(name) = cert.root.name.clone() else { return Err("Only an added certificate can be removed.".into()) };
        let called = cert.name().to_string();
        trust::remove(&name).map_err(said_error)?;
        self.page = Page::List;
        Ok(format!("{called} removed. Programs stop trusting it within a few seconds."))
    }

    fn restore(&mut self, fingerprint: &str) -> Result<String, String> {
        let called = self.store.refused(fingerprint).and_then(|r| r.known.as_ref()).map(|d| d.name().to_string());
        trust::restore(fingerprint).map_err(said_error)?;
        Ok(match called {
            Some(name) => format!("{name} trusted again."),
            None => "Distrust removed.".into(),
        })
    }

    fn reload(&mut self) -> Result<String, String> {
        trust::reload().map_err(|e| capitalised(&e.to_string()))?;
        Ok("The trust service composed the store again.".into())
    }

    fn compat(&mut self, on: bool) -> Result<String, String> {
        trust::set_compat(u32::from(on)).map_err(said_error)?;
        Ok(if on { "Certificate files turned on.".into() } else { "Certificate files turned off.".into() })
    }

    /// Opens the permissions editor on `which`: the trust key, or trustd's
    /// control object.
    fn permissions(&mut self, which: &'static str) {
        if self.editing.contains(&which) {
            self.said = Some(Ok("Those permissions are open already.".into()));
            return;
        }
        let opened = match which {
            "trust" => permissions::trust_key(),
            _ => permissions::service(self.store.may_compat.is_ok()),
        };
        let (request, mut apply) = match opened {
            Ok(opened) => opened,
            Err(why) => return self.said = Some(Err(format!("The permissions couldn't be opened: {why}."))),
        };
        let looking = self.window.clone();
        let applied = move |sd: &[u8], parts: &[gxwi_sd_editor::Part]| {
            apply(sd, parts)?;
            if let Some(window) = looking.upgrade() {
                window.update(|policy, fields| {
                    let read = store::read(&policy.known, Some(&policy.store));
                    policy.heard(read, fields);
                });
            }
            Ok(())
        };
        let window = self.window.clone();
        let done = move || {
            if let Some(window) = window.upgrade() {
                window.update(|policy, _| policy.editing.retain(|w| *w != which));
            }
        };
        self.said = None;
        match gxwi_sd_editor::edit(&request, applied, done) {
            Ok(()) => self.editing.push(which),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.said = Some(Err("The permissions editor isn't installed.".into())),
            Err(e) => self.said = Some(Err(format!("The permissions editor couldn't be started: {e}."))),
        }
    }
}

/// Why `der` can't be added, if it can't: it is in force already, or
/// distrusted, or not a CA, or expired.
fn problem(store: &Store, der: &[u8], fingerprint: &str) -> Option<String> {
    if let Some(cert) = store.certificate(fingerprint) {
        return Some(match &cert.root.name {
            Some(name) => format!("This certificate is already trusted: it was added as {name}."),
            None => "This certificate is already trusted: it ships with Peios.".into(),
        });
    }
    if store.refused(fingerprint).is_some() {
        return Some("This certificate is distrusted. Restore it under Distrusted to trust it again.".into());
    }
    match trust::vet(der) {
        Ok(_) => None,
        Err(cert::Error::NotACa) => Some("This isn't a certificate authority's certificate, so it can't vouch for others.".into()),
        Err(cert::Error::Expired) => {
            let expired = cert::describe(der).map(|d| words::date(d.not_after)).unwrap_or_default();
            Some(format!("This certificate expired on {expired}."))
        }
        Err(_) => Some("This certificate can't be read in full, so it can't be trusted.".into()),
    }
}

/// A refusal in the window's words.
fn said_error(error: trust::Error) -> String {
    match error {
        trust::Error::Denied(_) => LOOK_ONLY.replace("You can look, but you", "You"),
        other => capitalised(&other.to_string()),
    }
}

/// `text` as a sentence: a capital first letter and a full stop.
fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    let Some(first) = chars.next() else { return String::new() };
    let mut out: String = first.to_uppercase().chain(chars).collect();
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

impl Live for Policy {
    fn render(&self, facts: &Facts) -> String {
        let fields = facts.fields;
        let now = jiff::Timestamp::now().as_second();
        let page = match self.view {
            View::Trusted => match &self.page {
                Page::List => certificates::list(&self.store, fields, now, self.choosing),
                Page::Certificate(fingerprint) => match self.store.certificate(fingerprint) {
                    Some(cert) => certificates::detail(cert, &self.store, self.asking.as_ref(), now, self.choosing),
                    None => certificates::list(&self.store, fields, now, self.choosing),
                },
                Page::Adding(candidate) => certificates::adding(candidate, &self.store, now, self.choosing),
            },
            View::Distrusted => certificates::distrusted(&self.store, self.asking.as_ref()),
            View::Settings => options::render(&self.store, self.asking.as_ref()),
            View::Keys => keys::render(&self.store.keys),
        };
        settings::window(&self.nav(), self.view.id(), &page, &settings::status(self.said.as_ref(), ""))
    }

    fn input(&mut self, name: &str, fields: &mut Fields) {
        if name != "compat" {
            return;
        }
        if fields.get("compat") == "on" {
            self.asking = None;
            let done = self.compat(true);
            if done.is_ok() {
                self.changed(fields);
            } else {
                self.fill(fields);
            }
            self.said = Some(done);
        } else {
            // Turning them off breaks most programs' TLS: asked first, and
            // shown on until the answer is yes.
            fields.set("compat", "on");
            self.asking = Some(Asking::CompatOff);
            self.said = None;
        }
    }

    fn event(&mut self, name: &str, value: &Value, fields: &mut Fields) {
        let cert = || value.get("cert").and_then(Value::as_str).unwrap_or_default().to_string();
        let done = match name {
            "section" => {
                if let Some(view) = value.get("section").and_then(Value::as_str).and_then(View::by) {
                    self.view = view;
                    self.page = Page::List;
                    self.asking = None;
                    self.said = None;
                }
                return;
            }
            "open" => {
                self.page = Page::Certificate(cert());
                self.asking = None;
                self.said = None;
                return;
            }
            "back" | "cancel-add" => {
                self.page = Page::List;
                self.asking = None;
                return;
            }
            "choose-file" => return self.choose_file(),
            "export" => return self.export(&cert()),
            "ask-distrust" => return self.asking = Some(Asking::Distrust(cert())),
            "ask-remove" => return self.asking = Some(Asking::Remove(cert())),
            "ask-restore" => return self.asking = Some(Asking::Restore(cert())),
            "ask-by-fingerprint" => return self.asking = Some(Asking::ByFingerprint),
            "cancel" => {
                self.asking = None;
                for field in ["reason", "by-fp", "by-reason"] {
                    fields.set(field, "");
                }
                return;
            }
            "perm-trust" => return self.permissions("trust"),
            "perm-service" => return self.permissions("service"),
            "add" => self.add(fields),
            "distrust" => self.distrust(&cert(), fields),
            "distrust-by-fingerprint" => self.distrust_by_fingerprint(fields),
            "remove" => self.remove(&cert()),
            "restore" => self.restore(&cert()),
            "reload" => self.reload(),
            "compat-off" => self.compat(false),
            _ => return,
        };
        if done.is_ok() {
            self.asking = None;
            self.changed(fields);
        }
        self.said = Some(done);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_section_names_a_view() {
        for (view, by) in View::ALL {
            assert_eq!(View::by(by), Some(view));
            assert_eq!(view.id(), by);
        }
        assert_eq!(View::by("Nonsense"), None);
    }

    #[test]
    fn a_refusal_reads_as_a_sentence() {
        assert_eq!(capitalised("no addition named x"), "No addition named x.");
        assert_eq!(said_error(trust::Error::Denied("k".into())), "You can't change what this machine trusts: as shipped, only Administrators can.");
    }
}
