//! Who may change what this machine trusts, and who may control trustd, for
//! gxwi-sd-editor to show and change.
//!
//! The first is the descriptor of `Machine\System\Trust`, the key whose
//! subkeys hold every addition and distrust; the registry checks it, and
//! it is opened as any key's is. The second is `ControlSecurity`, a
//! descriptor kept in a value of that key for trustd to check its own
//! requests against: absent, trustd uses its compiled default, which is
//! where the editor starts.

use gxwi_sd_editor::registry::{self as key_permissions, Apply};
use gxwi_sd_editor::{Can, Children, Generic, Object, Part, Request, Right, splice};
use libtrust::{CONTROL_SECURITY_VALUE, TRUST_ALL_ACCESS, TRUST_CONTROL, TRUST_KEY, TRUST_QUERY};
use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};
use peios::security::AccessMask;

/// The trust key's own descriptor.
pub fn trust_key() -> Result<(Request, Apply), String> {
    let (mut request, apply) = key_permissions::key(TRUST_KEY, "Trust", "You can't change who may change what this machine trusts.")?;
    request.object.kind = format!("What this machine trusts, kept in {TRUST_KEY}");
    Ok((request, apply))
}

/// The descriptor trustd checks its requests against, as it is now.
fn control_security() -> Result<Vec<u8>, String> {
    let key = Key::open(None, TRUST_KEY, KeyAccess::QUERY_VALUE, OpenFlags::empty()).map_err(|e| format!("it couldn't be read ({e})"))?;
    match key.query_value(CONTROL_SECURITY_VALUE.as_bytes(), None) {
        Ok(value) => Ok(value.data),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(libtrust::default_control_security().as_bytes().to_vec()),
        Err(e) => Err(format!("it couldn't be read ({e})")),
    }
}

/// trustd's control object's descriptor. `may` is whether the person may
/// change the trust key's values, which is what changing it takes.
pub fn service(may: bool) -> Result<(Request, Apply), String> {
    let rc = AccessMask::READ_CONTROL.bits();
    let general = |name: &str, mask: u32| Right { name: name.into(), mask, general: true };
    let special = |name: &str, mask: u32| Right { name: name.into(), mask, general: false };
    let request = Request {
        object: Object { name: "Trust Service".into(), kind: "The trust service, trustd".into(), container: false, children: Children::All },
        sd: control_security()?,
        rights: vec![
            general("Full control", TRUST_ALL_ACCESS),
            general("List certificates", TRUST_QUERY | rc),
            general("Reload", TRUST_CONTROL),
            special("Read permissions", rc),
            special("Change permissions", AccessMask::WRITE_DAC.bits()),
            special("Take ownership", AccessMask::WRITE_OWNER.bits()),
        ],
        generic: Generic { read: TRUST_QUERY | rc, write: TRUST_CONTROL | rc, execute: TRUST_QUERY, all: TRUST_ALL_ACCESS },
        can: Can { dacl: may, owner: may, audit: false, why: (!may).then(|| "You can't change who may control the trust service.".to_string()) },
    };
    let apply = move |sd: &[u8], parts: &[Part]| {
        // What it is now, with what the person changed put in: the rest is
        // not the editor's to write back.
        let now = control_security()?;
        let value = splice(&now, sd, parts)?;
        let key = Key::open(None, TRUST_KEY, KeyAccess::SET_VALUE, OpenFlags::empty()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied { "you are not allowed to".to_string() } else { e.to_string() }
        })?;
        key.set_value(CONTROL_SECURITY_VALUE.as_bytes(), ValueType::BINARY, &value).call().map_err(|e| e.to_string())
    };
    Ok((request, Box::new(apply)))
}
