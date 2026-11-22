//! Linux lock signals, best effort. Listens on D-Bus for
//!  - logind `Lock` on this session (system bus; `loginctl lock-session`, most lockers),
//!  - logind `PrepareForSleep(true)` (suspend / hibernate),
//!  - `ActiveChanged(true)` of the GNOME / freedesktop screensaver (session bus).
//!
//! Each listener runs on its own thread; if D-Bus or a service is missing the
//! thread ends quietly and the idle timer in the UI remains the fallback.
//! This file depends on zbus only, so it can be type-checked on its own.

use std::sync::Arc;
use zbus::blocking::{Connection, MessageIterator};
use zbus::MatchRule;

pub type Notify = Arc<dyn Fn() + Send + Sync + 'static>;

pub fn start(on_lock: Notify) {
    {
        let n = on_lock.clone();
        std::thread::spawn(move || {
            let _ = logind(&n);
        });
    }
    {
        let n = on_lock.clone();
        std::thread::spawn(move || {
            let _ = screensaver(&n, "org.gnome.ScreenSaver", "/org/gnome/ScreenSaver");
        });
    }
    std::thread::spawn(move || {
        let _ = screensaver(&on_lock, "org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver");
    });
}

fn rule(sender: Option<&str>, iface: &str, member: &str, path: Option<&str>) -> zbus::Result<MatchRule<'static>> {
    let mut b = MatchRule::builder().msg_type(zbus::message::Type::Signal);
    if let Some(s) = sender {
        b = b.sender(s.to_owned())?;
    }
    b = b.interface(iface.to_owned())?.member(member.to_owned())?;
    if let Some(p) = path {
        b = b.path(p.to_owned())?;
    }
    Ok(b.build())
}

fn logind(notify: &Notify) -> zbus::Result<()> {
    let conn = Connection::system()?;
    // One iterator per rule: `Lock` is sent on the session object, `PrepareForSleep` on the manager.
    let lock_rule = rule(Some("org.freedesktop.login1"), "org.freedesktop.login1.Session", "Lock", None)?;
    let sleep_rule = rule(Some("org.freedesktop.login1"), "org.freedesktop.login1.Manager", "PrepareForSleep", None)?;
    let sleep_conn = conn.clone();
    let n2 = notify.clone();
    std::thread::spawn(move || {
        let Ok(it) = MessageIterator::for_match_rule(sleep_rule, &sleep_conn, None) else { return };
        for msg in it.flatten() {
            if matches!(msg.body().deserialize::<bool>(), Ok(true)) {
                n2();
            }
        }
    });
    // `Lock` is addressed to every session; only react to ours when we can tell, else to any.
    let mine = my_session_path(&conn);
    for msg in MessageIterator::for_match_rule(lock_rule, &conn, None)?.flatten() {
        let from = msg.header().path().map(|p| p.to_string());
        if mine.is_none() || from == mine {
            notify();
        }
    }
    Ok(())
}

fn my_session_path(conn: &Connection) -> Option<String> {
    let id = std::env::var("XDG_SESSION_ID").ok().filter(|s| !s.is_empty())?;
    let reply =
        conn.call_method(Some("org.freedesktop.login1"), "/org/freedesktop/login1", Some("org.freedesktop.login1.Manager"), "GetSession", &(id,)).ok()?;
    reply.body().deserialize::<zbus::zvariant::OwnedObjectPath>().ok().map(|p| p.to_string())
}

fn screensaver(notify: &Notify, iface: &str, path: &str) -> zbus::Result<()> {
    let conn = Connection::session()?;
    let r = rule(None, iface, "ActiveChanged", Some(path))?;
    for msg in MessageIterator::for_match_rule(r, &conn, None)?.flatten() {
        if matches!(msg.body().deserialize::<bool>(), Ok(true)) {
            notify();
        }
    }
    Ok(())
}
