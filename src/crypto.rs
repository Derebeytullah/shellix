use std::fs;
use std::sync::RwLock;

use crate::common;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Digest, Sha256};

// Şifrelenmiş değerleri düz metinden ayırmak için başlarına bu etiket eklenir.
const ENC_PREFIX: &str = "enc:";
const SALT_FILE: &str = "shellix.salt";
const PIN_FILE: &str = "shellix.pin";
const DEFAULT_PIN: &str = "1234";
const PBKDF2_ITERATIONS: u32 = 100_000;

// PIN değiştirilebildiği için OnceLock değil RwLock kullanılıyor.
static KEY: RwLock<Option<[u8; 32]>> = RwLock::new(None);

fn derive_key(pin: &str) -> [u8; 32] {
    let salt = load_or_create_salt();
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pin.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Anahtarın diske yazılan doğrulayıcısı: SHA256(etiket + anahtar).
/// Anahtarın kendisini açığa çıkarmadan PIN kontrolüne yarar.
fn key_verifier(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"shellix-pin-verifier");
    hasher.update(key);
    BASE64.encode(hasher.finalize())
}

/// PIN doğru mu? shellix.pin henüz yoksa varsayılan PIN (1234) kabul edilir.
pub fn check_pin(pin: &str) -> bool {
    match fs::read_to_string(common::config_file(PIN_FILE)) {
        Ok(stored) => key_verifier(&derive_key(pin)) == stored.trim(),
        Err(_) => pin == DEFAULT_PIN,
    }
}

/// Girişte kullanılır: PIN'i doğrular, doğruysa anahtarı belleğe alır.
/// PBKDF2 pahalı olduğu için türetme bir kez yapılır (check_pin + ayrı init yok).
/// İlk çalıştırmada (shellix.pin yoksa) varsayılan PIN kabul edilir ve dosya oluşturulur.
pub fn login(pin: &str) -> bool {
    let key = derive_key(pin);
    let pin_path = common::config_file(PIN_FILE);
    match fs::read_to_string(&pin_path) {
        Ok(stored) => {
            if key_verifier(&key) != stored.trim() {
                return false;
            }
        }
        Err(_) => {
            if pin != DEFAULT_PIN {
                return false;
            }
            let _ = fs::write(&pin_path, key_verifier(&key));
        }
    }
    *KEY.write().unwrap() = Some(key);
    true
}

/// PIN'i değiştirir: yeni doğrulayıcıyı yazar ve aktif anahtarı günceller.
/// DİKKAT: Çağırmadan önce kayıtlı şifreler ESKİ anahtarla çözülmüş olmalı,
/// sonrasında yeni anahtarla yeniden şifrelenmeli (bkz. menu::change_pin).
pub fn set_pin(new_pin: &str) -> Result<(), String> {
    let key = derive_key(new_pin);
    fs::write(common::config_file(PIN_FILE), key_verifier(&key))
        .map_err(|e| format!("{} yazılamadı: {}", PIN_FILE, e))?;
    *KEY.write().unwrap() = Some(key);
    Ok(())
}

fn load_or_create_salt() -> [u8; 16] {
    let salt_path = common::config_file(SALT_FILE);
    if let Ok(bytes) = fs::read(&salt_path) {
        if bytes.len() == 16 {
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&bytes);
            return salt;
        }
    }

    // İlk çalıştırma: rastgele salt üret ve dosyaya kaydet.
    // Bu dosya silinirse mevcut şifreli veriler bir daha çözülemez.
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let _ = fs::create_dir_all(common::config_dir());
    fs::write(salt_path, salt).expect("shellix.salt dosyası yazılamadı");
    salt
}

pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENC_PREFIX)
}

/// Düz metni şifreler. Çıktı formatı: "enc:" + base64(nonce + ciphertext)
pub fn encrypt(plain: &str) -> String {
    let key = KEY
        .read()
        .unwrap()
        .expect("init_key çağrılmadan encrypt kullanılamaz");
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plain.as_bytes())
        .expect("şifreleme başarısız");

    let mut payload = nonce_bytes.to_vec();
    payload.extend_from_slice(&ciphertext);
    format!("{}{}", ENC_PREFIX, BASE64.encode(payload))
}

/// Şifreli değeri çözer. Yanlış anahtar veya bozuk veri için None döner.
pub fn decrypt(value: &str) -> Option<String> {
    let encoded = value.strip_prefix(ENC_PREFIX)?;
    let payload = BASE64.decode(encoded).ok()?;
    if payload.len() < 12 {
        return None;
    }
    let (nonce_bytes, ciphertext) = payload.split_at(12);

    let key = (*KEY.read().unwrap())?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .ok()?;
    String::from_utf8(plain).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Testler kullanıcının gerçek config dizinine dokunmasın diye
    // anahtar diskten türetilmeden doğrudan atanır.
    fn set_test_key() {
        *KEY.write().unwrap() = Some([7u8; 32]);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        set_test_key();
        let secret = "süper-gizli-şifre!42";
        let encrypted = encrypt(secret);

        assert!(is_encrypted(&encrypted));
        assert!(!encrypted.contains(secret));
        assert_eq!(decrypt(&encrypted).as_deref(), Some(secret));
    }

    #[test]
    fn decrypt_rejects_garbage() {
        set_test_key();
        assert_eq!(decrypt("enc:AAAA"), None);
        assert_eq!(decrypt("düz metin"), None);
    }
}
