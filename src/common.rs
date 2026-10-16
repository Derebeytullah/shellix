use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Uygulama durum dosyalarının (profiles.json, shellix.salt, shellix.pin,
/// known_hosts.json) tutulduğu dizin.
/// Linux: ~/.config/shellix, macOS: ~/Library/Application Support/shellix,
/// Windows: %APPDATA%\shellix
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("shellix")
}

pub fn config_file(name: &str) -> PathBuf {
    config_dir().join(name)
}

/// Eski sürümler durum dosyalarını çalışma dizininde tutuyordu; bulunanları
/// config dizinine taşır. main başlarken bir kez çağrılır (PIN kontrolünden
/// önce olmalı, çünkü shellix.pin ve shellix.salt da taşınıyor).
pub fn migrate_legacy_files() {
    let _ = fs::create_dir_all(config_dir());

    for name in ["profiles.json", "shellix.salt", "shellix.pin", "known_hosts.json"] {
        let old = Path::new(name);
        let new = config_file(name);
        if old.is_file() && !new.exists() {
            // rename farklı dosya sistemleri arasında çalışmaz: kopyala + sil
            if fs::rename(old, &new).is_err() && fs::copy(old, &new).is_ok() {
                let _ = fs::remove_file(old);
            }
        }
    }
}

pub fn read_json(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut content = String::new();

    file.read_to_string(&mut content)?;

    Ok(content)
}
