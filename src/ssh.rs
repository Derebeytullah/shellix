use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use russh::client;
use russh::{ChannelMsg, Disconnect};
use russh_keys::key;

use crate::model::ServerProfile;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const KNOWN_HOSTS_FILE: &str = "known_hosts.json";

/// run_session'ın hata türü: host key reddi, kullanıcı onayı gerektirdiği için
/// diğer hatalardan ayrı ele alınır.
enum SessionError {
    /// Sunucu anahtarı beklenen parmak iziyle eşleşmedi (veya hiç kayıt yoktu).
    HostKeyRejected,
    Other(String),
}

struct Client {
    /// known_hosts'ta kayıtlı parmak izi (yoksa None -> bağlantı reddedilir, TOFU akışı başlar)
    expected_fingerprint: Option<String>,
    /// Sunucunun sunduğu gerçek parmak izi buraya yazılır (onay ekranında gösterilir)
    seen_fingerprint: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    // TOFU: handshake sırasında kullanıcıya soru soramayız (runtime bloklanır),
    // bu yüzden bilinmeyen/uyuşmayan anahtar burada sadece reddedilir;
    // onay connect_blocking içinde, runtime dışında alınır.
    async fn check_server_key(
        self,
        server_public_key: &key::PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        let fingerprint = server_public_key.fingerprint();
        *self.seen_fingerprint.lock().unwrap() = Some(fingerprint.clone());

        let trusted = match &self.expected_fingerprint {
            Some(expected) => *expected == fingerprint,
            None => false,
        };
        Ok((self, trusted))
    }
}

/// Profil bilgileriyle interaktif bir SSH oturumu açar ve oturum bitene kadar bloklar.
/// Host key TOFU akışı: ilk bağlantıda parmak izi kullanıcı onayıyla known_hosts.json'a
/// kaydedilir, sonraki bağlantılarda otomatik doğrulanır, değişmişse uyarı verilir.
pub fn connect_blocking(profile: &ServerProfile, password: &str) -> Result<(), String> {
    let host_id = format!("{}:{}", profile.hostname, profile.port);
    let mut trusted_fingerprint = load_known_hosts().get(&host_id).cloned();

    // En fazla iki deneme: reddedilen anahtar onaylanırsa bir kez yeniden bağlanılır
    for _ in 0..2 {
        let seen_fingerprint = Arc::new(Mutex::new(None));

        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Tokio runtime başlatılamadı: {}", e))?;
        let result = runtime.block_on(run_session(
            profile,
            password,
            trusted_fingerprint.clone(),
            seen_fingerprint.clone(),
        ));
        // Normal drop, bekleyen bloklayıcı işlerin bitmesini bekleyip takılabilir
        runtime.shutdown_background();

        match result {
            Err(SessionError::HostKeyRejected) => {
                let seen = seen_fingerprint
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or_else(|| "Server did not present a host key".to_string())?;

                let accepted = match &trusted_fingerprint {
                    None => prompt_trust_new_host(&host_id, &seen),
                    Some(old) => prompt_host_key_changed(&host_id, old, &seen),
                };

                if !accepted {
                    return Err("Host key not trusted, connection aborted".to_string());
                }
                save_known_host(&host_id, &seen)?;
                trusted_fingerprint = Some(seen);
                // döngü başa döner ve artık güvenilen anahtarla yeniden bağlanır
            }
            Err(SessionError::Other(e)) => return Err(e),
            Ok(()) => return Ok(()),
        }
    }

    Err("Host key was rejected again after being trusted".to_string())
}

async fn run_session(
    profile: &ServerProfile,
    password: &str,
    expected_fingerprint: Option<String>,
    seen_fingerprint: Arc<Mutex<Option<String>>>,
) -> Result<(), SessionError> {
    let config = Arc::new(client::Config::default());
    let handler = Client {
        expected_fingerprint,
        seen_fingerprint,
    };

    let connect_result = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect(
            config,
            (profile.hostname.as_str(), profile.port),
            handler,
        ),
    )
    .await
    .map_err(|_| {
        SessionError::Other(format!("Connection timed out ({}s)", CONNECT_TIMEOUT.as_secs()))
    })?;

    let mut session = match connect_result {
        Ok(session) => session,
        // check_server_key false döndüğünde russh bu hatayı üretir -> TOFU akışı
        Err(russh::Error::UnknownKey) => return Err(SessionError::HostKeyRejected),
        Err(e) => return Err(SessionError::Other(format!("Connection failed: {}", e))),
    };

    let authenticated = session
        .authenticate_password(&profile.username, password)
        .await
        .map_err(|e| SessionError::Other(format!("Authentication error: {}", e)))?;

    if !authenticated {
        return Err(SessionError::Other(
            "Authentication failed (wrong username or password?)".to_string(),
        ));
    }

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| SessionError::Other(format!("Could not open channel: {}", e)))?;

    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    channel
        .request_pty(false, "xterm-256color", cols as u32, rows as u32, 0, 0, &[])
        .await
        .map_err(|e| SessionError::Other(format!("PTY request failed: {}", e)))?;
    channel
        .request_shell(false)
        .await
        .map_err(|e| SessionError::Other(format!("Shell request failed: {}", e)))?;

    // Tuş olayları -> SSH kanalı, SSH kanalı -> yerel stdout köprüsü.
    // Menüyle aynı crossterm olay kaynağı kullanıldığı için oturum bitince
    // bekleyen tuşlar kaybolmaz.
    let mut events = EventStream::new();
    let mut stdout = std::io::stdout();
    // Uzak uygulamanın açıp kapattığı terminal modları (ok tuşu kodlaması bunlara bağlı)
    let mut modes = TermModes::default();

    loop {
        tokio::select! {
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if key.kind != KeyEventKind::Release => {
                        let bytes = key_event_to_bytes(&key, modes.app_cursor_keys);
                        if !bytes.is_empty() && channel.data(&bytes[..]).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Event::Paste(text))) => {
                        let bytes = paste_to_bytes(&text);
                        if channel.data(&bytes[..]).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Event::Resize(new_cols, new_rows))) => {
                        let _ = channel
                            .window_change(new_cols as u32, new_rows as u32, 0, 0)
                            .await;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        modes.feed(&data);
                        stdout.write_all(&data).map_err(|e| SessionError::Other(e.to_string()))?;
                        stdout.flush().map_err(|e| SessionError::Other(e.to_string()))?;
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        stdout.write_all(&data).map_err(|e| SessionError::Other(e.to_string()))?;
                        stdout.flush().map_err(|e| SessionError::Other(e.to_string()))?;
                    }
                    Some(ChannelMsg::ExitStatus { .. }) => {}
                    Some(ChannelMsg::Close) | Some(ChannelMsg::Eof) | None => break,
                    _ => {}
                }
            }
        }
    }

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "en")
        .await;

    Ok(())
}

// ---------- known_hosts (TOFU) ----------

fn load_known_hosts() -> HashMap<String, String> {
    fs::read_to_string(crate::common::config_file(KNOWN_HOSTS_FILE))
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_default()
}

fn save_known_host(host_id: &str, fingerprint: &str) -> Result<(), String> {
    let mut hosts = load_known_hosts();
    hosts.insert(host_id.to_string(), fingerprint.to_string());
    let json = serde_json::to_string_pretty(&hosts)
        .map_err(|e| format!("known_hosts serileştirilemedi: {}", e))?;
    fs::write(crate::common::config_file(KNOWN_HOSTS_FILE), json)
        .map_err(|e| format!("{} yazılamadı: {}", KNOWN_HOSTS_FILE, e))
}

/// İlk bağlantı: parmak izini gösterip güvenilsin mi diye sorar.
fn prompt_trust_new_host(host_id: &str, fingerprint: &str) -> bool {
    crate::menu::clear_screen();
    println!("======================================================\r");
    println!(" The authenticity of host '{}' can't be established.\r", host_id);
    println!("======================================================\r");
    println!("Server key fingerprint:\r");
    println!("  SHA256:{}\r", fingerprint);
    println!("\nTrust this host and save its fingerprint? \r");
    println!("[Press 'Y' to trust | 'N' or 'Esc' to abort]\r");
    let _ = std::io::stdout().flush();
    prompt_yes_no()
}

/// Kayıtlı anahtar değişmiş: olası MITM uyarısı gösterir.
fn prompt_host_key_changed(host_id: &str, old: &str, new: &str) -> bool {
    crate::menu::clear_screen();
    println!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r");
    println!("@  WARNING: REMOTE HOST KEY HAS CHANGED for '{}'!\r", host_id);
    println!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r");
    println!("Someone could be eavesdropping on you (man-in-the-middle attack),\r");
    println!("or the server's host key may have been legitimately regenerated.\r");
    println!("\nStored fingerprint : SHA256:{}\r", old);
    println!("Current fingerprint: SHA256:{}\r", new);
    println!("\nOnly continue if you are SURE the key change is expected.\r");
    println!("[Press 'Y' to replace & connect | 'N' or 'Esc' to abort]\r");
    let _ = std::io::stdout().flush();
    prompt_yes_no()
}

fn prompt_yes_no() -> bool {
    loop {
        if let Ok(Event::Key(key)) = crossterm::event::read() {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => return true,
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => return false,
                _ => {}
            }
        }
    }
}

/// Yapıştırılan metni uzak PTY'ye iletilecek byte dizisine çevirir.
///
/// Paste olayı ancak yerel terminal bracketed-paste modundayken üretilir; o moda da
/// uzaktaki uygulama (bash/readline, vim...) `ESC[?2004h` gönderdiği için girilmiştir.
/// Dolayısıyla metni yeniden parantezleyip göndermek gerçek ssh davranışıyla birebir aynı:
/// uzak taraf yapıştırmayı tek blok olarak alır, satırları tek tek çalıştırmaz.
fn paste_to_bytes(text: &str) -> Vec<u8> {
    // İçeride kapanış işareti varsa erken sonlanmayı engellemek için ayıklanır
    let text = text.replace("\x1b[201~", "");
    // Terminal satır sonlarını PTY'nin beklediği CR'ye çevirir
    let text = text.replace("\r\n", "\r").replace('\n', "\r");

    let mut bytes = Vec::with_capacity(text.len() + 12);
    bytes.extend_from_slice(b"\x1b[200~");
    bytes.extend_from_slice(text.as_bytes());
    bytes.extend_from_slice(b"\x1b[201~");
    bytes
}

/// Uzak taraftan gelen çıktıyı izleyerek tuş kodlamasını etkileyen terminal modlarını takip eder.
///
/// vim, less, htop, readline gibi programlar `ESC[?1h` (DECCKM) ile "application cursor keys"
/// moduna geçer ve ok tuşlarını `ESC[A` yerine `ESC O A` olarak bekler. Crossterm iki biçimi de
/// aynı `KeyCode::Up`'a çevirdiği için bu bilgi kaybolur; modu burada kendimiz izliyoruz.
/// Ayrıştırıcı durum makinesi olduğundan, paketler arasında bölünen diziler de doğru yakalanır.
#[derive(Default)]
struct TermModes {
    app_cursor_keys: bool,
    state: ParseState,
    params: Vec<u8>,
}

#[derive(Default, PartialEq)]
enum ParseState {
    #[default]
    Ground,
    Esc,
    /// CSI içindeyiz; `private` = `ESC[?` ile başladı
    Csi { private: bool },
}

impl TermModes {
    fn feed(&mut self, data: &[u8]) {
        for &b in data {
            self.state = match std::mem::take(&mut self.state) {
                ParseState::Ground => {
                    if b == 0x1b { ParseState::Esc } else { ParseState::Ground }
                }
                ParseState::Esc => match b {
                    b'[' => {
                        self.params.clear();
                        ParseState::Csi { private: false }
                    }
                    // RIS (tam terminal sıfırlama)
                    b'c' => {
                        self.app_cursor_keys = false;
                        ParseState::Ground
                    }
                    0x1b => ParseState::Esc,
                    _ => ParseState::Ground,
                },
                ParseState::Csi { private } => match b {
                    b'?' if self.params.is_empty() && !private => ParseState::Csi { private: true },
                    b'0'..=b'9' | b';' => {
                        // Bozuk/çok uzun dizilerde belleği sınırlı tut
                        if self.params.len() < 64 {
                            self.params.push(b);
                        }
                        ParseState::Csi { private }
                    }
                    // Final byte: dizi bitti
                    0x40..=0x7e => {
                        if private && (b == b'h' || b == b'l') {
                            self.apply_private_mode(b == b'h');
                        }
                        ParseState::Ground
                    }
                    0x1b => ParseState::Esc,
                    // Ara byte'lar (0x20..0x2f) vb. yok sayılır
                    _ => ParseState::Csi { private },
                },
            };
        }
    }

    fn apply_private_mode(&mut self, enable: bool) {
        // Tek dizide birden çok mod olabilir: ESC[?1;1049h
        for param in self.params.split(|&c| c == b';') {
            if param == b"1" {
                self.app_cursor_keys = enable;
            }
        }
    }
}

/// xterm modifier parametresi: 1 + Shift(1) + Alt(2) + Ctrl(4). Modifier yoksa None.
fn xterm_modifier_param(modifiers: KeyModifiers) -> Option<u8> {
    let mut m = 0;
    if modifiers.contains(KeyModifiers::SHIFT) {
        m |= 1;
    }
    if modifiers.contains(KeyModifiers::ALT) {
        m |= 2;
    }
    if modifiers.contains(KeyModifiers::CONTROL) {
        m |= 4;
    }
    if m == 0 { None } else { Some(m + 1) }
}

/// Crossterm tuş olayını, uzak PTY'nin beklediği terminal byte dizisine çevirir.
/// `app_cursor_keys`: uzak uygulama DECCKM'i açtıysa ok/Home/End `ESC O x` olarak gönderilir.
fn key_event_to_bytes(key: &KeyEvent, app_cursor_keys: bool) -> Vec<u8> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    // Ok, Home, End: modifier varsa xterm biçimi ESC[1;<m>X (örn. Ctrl+Left -> ESC[1;5D),
    // yoksa moda göre ESC[X (normal) veya ESC O X (application).
    let cursor_final = match key.code {
        KeyCode::Up => Some(b'A'),
        KeyCode::Down => Some(b'B'),
        KeyCode::Right => Some(b'C'),
        KeyCode::Left => Some(b'D'),
        KeyCode::Home => Some(b'H'),
        KeyCode::End => Some(b'F'),
        _ => None,
    };
    if let Some(final_byte) = cursor_final {
        return match xterm_modifier_param(key.modifiers) {
            Some(m) => format!("\x1b[1;{}{}", m, final_byte as char).into_bytes(),
            None if app_cursor_keys => vec![0x1b, b'O', final_byte],
            None => vec![0x1b, b'[', final_byte],
        };
    }

    let mut bytes: Vec<u8> = match key.code {
        KeyCode::Char(c) => {
            if ctrl {
                // Ctrl+A..Z -> 0x01..0x1A (örn. Ctrl+C = 0x03)
                match c.to_ascii_uppercase() {
                    ch @ 'A'..='Z' => vec![(ch as u8) & 0x1f],
                    ' ' => vec![0x00],
                    _ => c.to_string().into_bytes(),
                }
            } else {
                c.to_string().into_bytes()
            }
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Esc => vec![0x1b],
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        KeyCode::Insert => b"\x1b[2~".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::F(n) => match n {
            1 => b"\x1bOP".to_vec(),
            2 => b"\x1bOQ".to_vec(),
            3 => b"\x1bOR".to_vec(),
            4 => b"\x1bOS".to_vec(),
            5 => b"\x1b[15~".to_vec(),
            6 => b"\x1b[17~".to_vec(),
            7 => b"\x1b[18~".to_vec(),
            8 => b"\x1b[19~".to_vec(),
            9 => b"\x1b[20~".to_vec(),
            10 => b"\x1b[21~".to_vec(),
            11 => b"\x1b[23~".to_vec(),
            12 => b"\x1b[24~".to_vec(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };

    // Alt (Meta) tuşu: başa ESC eklenir (örn. Alt+B -> ESC b)
    if alt && !bytes.is_empty() {
        bytes.insert(0, 0x1b);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn arrows_follow_cursor_key_mode() {
        let up = key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(key_event_to_bytes(&up, false), b"\x1b[A");
        assert_eq!(key_event_to_bytes(&up, true), b"\x1bOA");
    }

    #[test]
    fn modified_arrows_use_xterm_encoding() {
        let ctrl_left = key(KeyCode::Left, KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&ctrl_left, true), b"\x1b[1;5D");
        let alt_up = key(KeyCode::Up, KeyModifiers::ALT);
        assert_eq!(key_event_to_bytes(&alt_up, false), b"\x1b[1;3A");
        let shift_end = key(KeyCode::End, KeyModifiers::SHIFT);
        assert_eq!(key_event_to_bytes(&shift_end, false), b"\x1b[1;2F");
    }

    #[test]
    fn tracks_decckm_including_split_and_combined_sequences() {
        let mut modes = TermModes::default();
        modes.feed(b"hello\x1b[?1h");
        assert!(modes.app_cursor_keys);
        modes.feed(b"\x1b[?1l");
        assert!(!modes.app_cursor_keys);

        // Paketler arasında bölünmüş dizi
        modes.feed(b"abc\x1b[");
        modes.feed(b"?1");
        assert!(!modes.app_cursor_keys);
        modes.feed(b"h");
        assert!(modes.app_cursor_keys);

        // Birleşik parametreler ve ilgisiz modlar
        modes.feed(b"\x1b[?1049;1l");
        assert!(!modes.app_cursor_keys);
        modes.feed(b"\x1b[?12h\x1b[?2004h\x1b[1h");
        assert!(!modes.app_cursor_keys);

        // RIS sıfırlar
        modes.feed(b"\x1b[?1h\x1bc");
        assert!(!modes.app_cursor_keys);
    }
}
