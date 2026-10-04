//! Security Policy: what this machine trusts. Its certificates section is
//! the trust store — the certificate authorities every program accepts,
//! what this machine has added to them and what it refuses — as far as the
//! person looking may see and change it.
//!
//! It asks trustd, the only one that knows the set in force, over its own
//! socket, and changes the registry keys trustd reads through the `trust`
//! library, with no more authority than the person has: the same steps the
//! `trust` command takes.

use std::sync::Arc;

use libgxwi::App;

mod certificates;
mod keys;
mod options;
mod permissions;
mod policy;
mod store;
mod words;

use policy::Policy;
use store::Known;

// What this program looks like, to whatever lists it. The icon itself is
// `gxwi-security-policy.svg` at the repo root, installed as the base theme's.
libgxwi::icon!(b"dev.peios.gxwi-security-policy");

fn main() {
    if std::env::args().nth(1).is_some() {
        eprintln!("gxwi-security-policy: usage: gxwi-security-policy (given {:?})", std::env::args().skip(1).collect::<Vec<_>>());
        std::process::exit(64);
    }
    let mut app = match App::connect() {
        Ok(app) => app,
        Err(e) => {
            eprintln!("gxwi-security-policy: no desktop to open on: {e}");
            std::process::exit(1);
        }
    };
    libgxwi::settings::stylesheet(&mut app);
    app.stylesheet("/gxwi-security-policy.css", include_str!("gxwi-security-policy.css"));
    let known = Arc::new(Known::read());
    let window = app.live("Security Policy", Policy::new(known.clone()));
    let aside = Arc::downgrade(&window);
    window.update(|policy, fields| {
        policy.window = aside.clone();
        policy.fill(fields);
    });
    std::thread::spawn(move || store::follow(aside, known));
    if let Err(e) = app.run() {
        eprintln!("gxwi-security-policy: {e}");
        std::process::exit(1);
    }
}
