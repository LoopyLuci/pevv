//! Designated USB device as a presence LOCK, never as a key.
//!
//! A mouse or a keyboard holds no secret: its vendor id, product id and serial are readable by
//! any program and a USB microcontroller can claim the same ones. So this is only a trigger:
//! the vault locks when the designated device disappears, and (optionally) the app refuses to
//! start an unlock while it is absent. That refusal is a soft gate, not protection against anyone
//! who can copy the identifiers; the master password / passkey / key file remain the only way in.
//! The designation lives in the app's local settings file, not in the vault.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UsbDevice {
    /// `usb:<vid>:<pid>:<serial or port path>`. Without a serial it is tied to the port.
    pub id: String,
    pub vid: String,
    pub pid: String,
    pub name: String,
    pub serial: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Designation {
    pub id: String,
    pub name: String,
    /// Refuse to start an unlock while the device is absent (a soft gate).
    #[serde(default)]
    pub require_to_unlock: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(default)]
    pub presence: Option<Designation>,
}

/// Local, plain-text app settings (`settings.json` in the app data folder).
pub struct SettingsStore {
    path: PathBuf,
}

impl SettingsStore {
    pub fn new(dir: &Path) -> Self {
        Self { path: dir.join("settings.json") }
    }

    pub fn load(&self) -> Settings {
        std::fs::read_to_string(&self.path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, s: &Settings) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }
}

/// Windows instance id `USB\VID_046D&PID_C52B\5&2A1B&0&3` -> (vid, pid, tail).
/// Interface entries of a composite device (`...&MI_01`) and root hubs return `None`.
pub fn parse_instance_id(id: &str) -> Option<(String, String, String)> {
    let mut parts = id.split('\\');
    if !parts.next()?.eq_ignore_ascii_case("USB") {
        return None;
    }
    let hw = parts.next()?.to_ascii_uppercase();
    let tail = parts.next()?.to_string();
    if hw.contains("&MI_") {
        return None;
    }
    let vid = hw.strip_prefix("VID_")?.get(..4)?.to_ascii_lowercase();
    let pid = hw.split("&PID_").nth(1)?.get(..4)?.to_ascii_lowercase();
    Some((vid, pid, tail))
}

pub fn device_id(vid: &str, pid: &str, serial_or_port: &str) -> String {
    format!("usb:{vid}:{pid}:{serial_or_port}")
}

#[cfg(windows)]
pub fn list_devices() -> Result<Vec<UsbDevice>, String> {
    use windows::core::w;
    use windows::Win32::Devices::DeviceAndDriverInstallation::*;

    let mut out = Vec::new();
    // SAFETY: SetupAPI enumeration with local buffers; the device set is destroyed before returning.
    unsafe {
        let set = SetupDiGetClassDevsW(None, w!("USB"), None, DIGCF_PRESENT | DIGCF_ALLCLASSES).map_err(|e| e.to_string())?;
        let mut idx = 0u32;
        loop {
            let mut data = SP_DEVINFO_DATA { cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32, ..Default::default() };
            if SetupDiEnumDeviceInfo(set, idx, &mut data).is_err() {
                break;
            }
            idx += 1;
            let mut buf = [0u16; 512];
            if SetupDiGetDeviceInstanceIdW(set, &data, Some(&mut buf), None).is_err() {
                continue;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let inst = String::from_utf16_lossy(&buf[..end]);
            let Some((vid, pid, tail)) = parse_instance_id(&inst) else { continue };
            let mut name_buf = [0u8; 512];
            let mut name = String::new();
            if SetupDiGetDeviceRegistryPropertyW(set, &data, SPDRP_DEVICEDESC, None, Some(&mut name_buf), None).is_ok() {
                let wide: Vec<u16> = name_buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
                name = String::from_utf16_lossy(&wide);
            }
            // A serial number is a tail without '&'; "5&2a1b&0&3" is a port-derived id.
            let serial = (!tail.contains('&')).then(|| tail.clone());
            out.push(UsbDevice { id: device_id(&vid, &pid, &tail.to_ascii_lowercase()), vid, pid, name, serial });
        }
        let _ = SetupDiDestroyDeviceInfoList(set);
    }
    Ok(out)
}

/// Read a sysfs `/sys/bus/usb/devices`-style tree. `root` is a parameter so tests can fake one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn list_sysfs(root: &Path) -> Result<Vec<UsbDevice>, String> {
    let rd = std::fs::read_dir(root).map_err(|e| e.to_string())?;
    let read = |p: &Path, f: &str| std::fs::read_to_string(p.join(f)).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if name.contains(':') || name.starts_with("usb") {
            continue; // an interface, or a root hub
        }
        let p = ent.path();
        let (Some(vid), Some(pid)) = (read(&p, "idVendor"), read(&p, "idProduct")) else { continue };
        if read(&p, "bDeviceClass").as_deref() == Some("09") {
            continue; // a hub
        }
        let serial = read(&p, "serial");
        let product = read(&p, "product").unwrap_or_default();
        let maker = read(&p, "manufacturer").unwrap_or_default();
        let label = format!("{maker} {product}").trim().to_string();
        let tail = serial.clone().unwrap_or_else(|| name.clone());
        out.push(UsbDevice {
            id: device_id(&vid.to_ascii_lowercase(), &pid.to_ascii_lowercase(), &tail.to_ascii_lowercase()),
            vid: vid.to_ascii_lowercase(),
            pid: pid.to_ascii_lowercase(),
            name: label,
            serial,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

#[cfg(target_os = "linux")]
pub fn list_devices() -> Result<Vec<UsbDevice>, String> {
    list_sysfs(Path::new("/sys/bus/usb/devices"))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn list_devices() -> Result<Vec<UsbDevice>, String> {
    Ok(Vec::new())
}

/// What one poll of the designated device means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Nothing,
    /// It was there and now is not: lock.
    Lost,
}

/// `seen` is the last known state; `now` is `None` when the enumeration itself failed
/// (then nothing changes: a failed read must not lock the vault).
pub fn step(seen: &mut bool, now: Option<bool>) -> Step {
    let Some(now) = now else { return Step::Nothing };
    let was = std::mem::replace(seen, now);
    if was && !now {
        Step::Lost
    } else {
        Step::Nothing
    }
}

pub fn is_present(devices: &[UsbDevice], id: &str) -> bool {
    devices.iter().any(|d| d.id == id)
}

/// Shared by the poller thread and the commands.
pub struct Presence {
    pub settings: SettingsStore,
    pub current: Mutex<Option<Designation>>,
}

impl Presence {
    pub fn new(dir: &Path) -> Arc<Self> {
        let settings = SettingsStore::new(dir);
        let current = Mutex::new(settings.load().presence);
        Arc::new(Self { settings, current })
    }

    pub fn designation(&self) -> Option<Designation> {
        self.current.lock().ok().and_then(|g| g.clone())
    }

    pub fn set(&self, d: Option<Designation>) -> Result<(), String> {
        let mut s = self.settings.load();
        s.presence = d.clone();
        self.settings.save(&s)?;
        if let Ok(mut g) = self.current.lock() {
            *g = d;
        }
        Ok(())
    }
}

/// The poller's state between polls.
#[derive(Default)]
pub struct PollState {
    seen: bool,
    last_id: String,
}

/// One poll: look at the designated device through `list` and call `on_lost` if it went away.
/// `list` is the test seam (the real one is `list_devices`).
pub fn poll_once(p: &Presence, st: &mut PollState, list: &dyn Fn() -> Result<Vec<UsbDevice>, String>, on_lost: &dyn Fn()) {
    let Some(d) = p.designation() else {
        st.seen = false;
        st.last_id.clear();
        return;
    };
    if d.id != st.last_id {
        st.last_id = d.id.clone();
        st.seen = false;
    }
    let now = list().ok().map(|l| is_present(&l, &d.id));
    if step(&mut st.seen, now) == Step::Lost {
        on_lost();
    }
}

/// Poll every 2 s; call `on_lost` when the designated device goes away.
pub fn spawn_poller(p: Arc<Presence>, on_lost: Arc<dyn Fn() + Send + Sync>) {
    std::thread::spawn(move || {
        let mut st = PollState::default();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            poll_once(&p, &mut st, &list_devices, &*on_lost);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_ids_parse() {
        assert_eq!(parse_instance_id(r"USB\VID_046D&PID_C52B\5&2A1B&0&3"), Some(("046d".into(), "c52b".into(), "5&2A1B&0&3".into())));
        assert_eq!(parse_instance_id(r"USB\VID_1050&PID_0407\0012345678"), Some(("1050".into(), "0407".into(), "0012345678".into())));
        assert_eq!(parse_instance_id(r"USB\VID_046D&PID_C52B&MI_01\6&1&0&1"), None);
        assert_eq!(parse_instance_id(r"USB\ROOT_HUB30\4&1&0"), None);
        assert_eq!(parse_instance_id(r"HID\VID_046D&PID_C52B\x"), None);
    }

    #[test]
    fn step_locks_only_on_a_real_disappearance() {
        let mut seen = false;
        assert_eq!(step(&mut seen, Some(false)), Step::Nothing); // never seen: nothing to lose
        assert_eq!(step(&mut seen, Some(true)), Step::Nothing);
        assert_eq!(step(&mut seen, None), Step::Nothing); // a failed read is not an unplug
        assert!(seen);
        assert_eq!(step(&mut seen, Some(true)), Step::Nothing);
        assert_eq!(step(&mut seen, Some(false)), Step::Lost);
        assert_eq!(step(&mut seen, Some(false)), Step::Nothing); // lock once
        assert_eq!(step(&mut seen, Some(true)), Step::Nothing);
        assert_eq!(step(&mut seen, Some(false)), Step::Lost);
    }

    fn fake_device(root: &Path, name: &str, files: &[(&str, &str)]) {
        let d = root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        for (f, c) in files {
            std::fs::write(d.join(f), format!("{c}\n")).unwrap();
        }
    }

    #[test]
    fn sysfs_listing_skips_hubs_and_interfaces() {
        let t = tempfile::tempdir().unwrap();
        fake_device(
            t.path(),
            "1-2",
            &[("idVendor", "046D"), ("idProduct", "C52B"), ("product", "USB Receiver"), ("manufacturer", "Logitech"), ("bDeviceClass", "00")],
        );
        fake_device(t.path(), "1-3", &[("idVendor", "1050"), ("idProduct", "0407"), ("serial", "ABC123"), ("bDeviceClass", "00")]);
        #[cfg(unix)] // ':' is not a legal file name character on Windows
        fake_device(t.path(), "1-2:1.0", &[("idVendor", "046d"), ("idProduct", "c52b")]);
        fake_device(t.path(), "usb1", &[("idVendor", "1d6b"), ("idProduct", "0002")]);
        fake_device(t.path(), "1-1", &[("idVendor", "05e3"), ("idProduct", "0610"), ("bDeviceClass", "09")]);
        let l = list_sysfs(t.path()).unwrap();
        let ids: Vec<_> = l.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, vec!["usb:046d:c52b:1-2", "usb:1050:0407:abc123"]);
        assert_eq!(l[0].name, "Logitech USB Receiver");
        assert_eq!(l[1].serial.as_deref(), Some("ABC123"));
        assert!(is_present(&l, "usb:1050:0407:abc123"));
        assert!(!is_present(&l, "usb:1050:0407:other"));
    }

    #[test]
    fn settings_round_trip_and_survive_garbage() {
        let t = tempfile::tempdir().unwrap();
        let p = Presence::new(t.path());
        assert_eq!(p.designation(), None);
        let d = Designation { id: "usb:046d:c52b:1-2".into(), name: "Mouse".into(), require_to_unlock: true };
        p.set(Some(d.clone())).unwrap();
        assert_eq!(Presence::new(t.path()).designation(), Some(d));
        p.set(None).unwrap();
        assert_eq!(Presence::new(t.path()).designation(), None);
        std::fs::write(t.path().join("settings.json"), "not json").unwrap();
        assert_eq!(Presence::new(t.path()).designation(), None);
    }

    #[test]
    fn listing_real_devices_does_not_panic() {
        let _ = list_devices();
    }

    #[test]
    fn poller_locks_when_the_designated_device_disappears() {
        use std::cell::{Cell, RefCell};
        let t = tempfile::tempdir().unwrap();
        let p = Presence::new(t.path());
        p.set(Some(Designation { id: "usb:0001:0002:S".into(), name: "mouse".into(), ..Default::default() })).unwrap();
        let dev = |id: &str| UsbDevice { id: id.into(), vid: "0001".into(), pid: "0002".into(), name: "x".into(), serial: None };
        let plugged = RefCell::new(Ok(vec![dev("usb:0001:0002:S")]));
        let locks = Cell::new(0);
        let mut st = PollState::default();
        let list = || plugged.borrow().clone();
        poll_once(&p, &mut st, &list, &|| locks.set(locks.get() + 1));
        assert_eq!(locks.get(), 0, "present: no lock");
        *plugged.borrow_mut() = Err("enumeration failed".to_string());
        poll_once(&p, &mut st, &list, &|| locks.set(locks.get() + 1));
        assert_eq!(locks.get(), 0, "a failed read never locks");
        *plugged.borrow_mut() = Ok(vec![]);
        poll_once(&p, &mut st, &list, &|| locks.set(locks.get() + 1));
        assert_eq!(locks.get(), 1, "unplugged: lock");
        poll_once(&p, &mut st, &list, &|| locks.set(locks.get() + 1));
        assert_eq!(locks.get(), 1, "only once");
    }
}
