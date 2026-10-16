use std::io::{self, Write};
use std::sync::Mutex;
use std::fs;
use crossterm::cursor::MoveTo;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{Clear, ClearType};
use lazy_static::lazy_static;
use crate::common::{self, read_json};
use crate::crypto;
use crate::model::ServerProfile;
use crate::ssh;

lazy_static! {
    // Shared profile storage. Initially an empty Vector (Vec).
    pub static ref PROFILES_CACHE: Mutex<Vec<ServerProfile>> = Mutex::new(Vec::new());
}

// Define menu options globally as a constant
const MENU_ITEMS: [&str; 7] = [
    "1. Show Profiles",
    "2. Edit Profiles",
    "3. Delete Profiles",
    "4. Connect Profiles",
    "5. Create Profile",
    "6. Change PIN",
    "7. Exit Shellix"
];

pub fn load_profiles_to_cache() {
    match read_json(&common::config_file("profiles.json")){
        Ok(content) => {
            match serde_json::from_str::<Vec<ServerProfile>>(&content) {
                Ok(mut profiles) => {
                    // Migrasyon: eski düz metin şifreleri şifrele ve dosyayı güncelle
                    let mut migrated = false;
                    for profile in profiles.iter_mut() {
                        if !crypto::is_encrypted(&profile.password) {
                            profile.password = crypto::encrypt(&profile.password);
                            migrated = true;
                        }
                    }

                    {
                        let mut cache = PROFILES_CACHE.lock().unwrap();
                        *cache = profiles;
                    }

                    if migrated {
                        save_profiles_to_json();
                    }
                }Err(e) => {
                    println!("{}",e);
                }
            }
        }Err(e) => {
            println!("{}",e);
        }
    }
}

pub fn clear_screen() {
    // Harici komut (cls/clear) yerine crossterm: platform bağımsız ve süreç başlatmaz
    let _ = execute!(
        io::stdout(),
        Clear(ClearType::All),
        Clear(ClearType::Purge),
        MoveTo(0, 0)
    );
}

fn handle_menu(title: &str, items: &[String]) -> Option<usize>{
    let mut selected_index = 0;

    loop {
        clear_screen();
        println!("======================================================\r");
        println!("                    {}\r", title);
        println!("       (Use Arrow Keys to navigate, Enter to select)  \r");
        println!("======================================================\r");

        for (i, item) in items.iter().enumerate(){
            if i == selected_index {
                println!("> [X] {} \r", item);
            } else {
                println!("> [ ] {} \r", item);
            }
        }

        println!("===============================================\r");
        println!("\n[Press 'Backspace' to return to main menu]\r");
        io::stdout().flush().unwrap();

        if let Ok(Event::Key(key_event)) = event::read() {
            match key_event.code {
                KeyCode::Up => {
                    if selected_index > 0 { selected_index -= 1; }
                    else { selected_index = items.len() - 1; }
                }
                KeyCode::Down => {
                    if selected_index < items.len() - 1 { selected_index += 1; }
                    else { selected_index = 0; }
                }
                KeyCode::Enter => {
                    return Some(selected_index);
                }
                KeyCode::Backspace => {
                    return None;
                } 
                _=> {} 
            }
        }
    }
}

fn read_input(prompt: &str, initial_value: &str) -> Option<String> {
    let mut input = initial_value.to_string();
    
    loop {
        clear_screen();
        println!("=======================================\r");
        println!("{}\r", prompt);
        println!("=======================================\r");
        println!("> {}\r", input); 
        println!("\n[Enter: Save | Esc: Cancel]\r");
        io::stdout().flush().unwrap();

        if let Ok(Event::Key(key_event)) = event::read() {
            match key_event.code {
                KeyCode::Char(c) => input.push(c),
                KeyCode::Backspace => { input.pop(); },
                KeyCode::Enter => return Some(input),
                KeyCode::Esc => return None,
                _ => {}
            }
        }
    }
}

/// read_input ile aynı, ama yazılanları ekranda '*' olarak gösterir (şifre girişi için)
fn read_password_input(prompt: &str) -> Option<String> {
    let mut input = String::new();

    loop {
        clear_screen();
        println!("=======================================\r");
        println!("{}\r", prompt);
        println!("=======================================\r");
        println!("> {}\r", "*".repeat(input.len()));
        println!("\n[Enter: Save | Esc: Cancel]\r");
        io::stdout().flush().unwrap();

        if let Ok(Event::Key(key_event)) = event::read() {
            match key_event.code {
                KeyCode::Char(c) => input.push(c),
                KeyCode::Backspace => { input.pop(); },
                KeyCode::Enter => return Some(input),
                KeyCode::Esc => return None,
                _ => {}
            }
        }
    }
}

fn show_profiles() {
    clear_screen();
    
    let profiles = PROFILES_CACHE.lock().unwrap();

    if profiles.is_empty(){
        println!("No profiles found in memory.\r");
    } else {
        for profil in profiles.iter() {
            println!("Profile Name : {}\r", profil.profile_name);
            println!("Connection   : {}@{}\r", profil.username, profil.hostname);
            println!("Password     : ********\r"); // Güvenlik için maskelendi
            println!("Port         : {}\r", profil.port);
            println!("------------------------------------------------------\r");
        }   
    }

    println!("\n[Press 'Backspace' to return to main menu]\r");
    io::stdout().flush().unwrap();

    loop {
        if let Ok(Event::Key(key_event)) = event::read() {
            if key_event.code == KeyCode::Backspace {
                break;
            }
        }
    }
}

fn create_profile() {
    // Adım 1: Profil Adı
    let profile_name = match read_input("[WIZARD 1/5] Enter Profile Name:", "") {
        Some(val) if !val.trim().is_empty() => val,
        _ => { return; }
    };

    // Adım 2: Kullanıcı Adı
    let username = match read_input("[WIZARD 2/5] Enter Username:", "") {
        Some(val) => val,
        None => { return; }
    };

    // Adım 3: Şifre (maskeli girilir, şifrelenerek saklanır)
    let password = match read_password_input("[WIZARD 3/5] Enter Password:") {
        Some(val) => crypto::encrypt(&val),
        None => { return; }
    };

    // Adım 4: Hostname / IP
    let hostname = match read_input("[WIZARD 4/5] Enter Hostname or IP:", "") {
        Some(val) => val,
        None => { return; }
    };

    // Adım 5: Port
    let mut port = 22;
    loop {
        if let Some(new_val) = read_input("[WIZARD 5/5] Enter Port:", &port.to_string()) {
            if let Ok(parsed_port) = new_val.parse() {
                port = parsed_port;
                break;
            } else {
                clear_screen();
                println!("Invalid port number! Please enter a valid number.\r");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        } else {
            return;
        }
    }

    // Yeni struct nesnesini güncel model yapısına göre oluşturuyoruz
    let new_profile = ServerProfile {
        profile_name,
        username,
        password, // Şifrelenmiş halde
        hostname,
        port,
    };

    {
        let mut profiles = PROFILES_CACHE.lock().unwrap();
        profiles.push(new_profile);
    }

    save_profiles_to_json();

    clear_screen();
    println!("=======================================\r");
    println!("   Profile Created Successfully! 🎉    \r");
    println!("=======================================\r");
    std::thread::sleep(std::time::Duration::from_secs(1));
}

fn edit_profiles() {
    let mut selected_profile_index: usize = 0;
    
    loop {
        clear_screen();
        println!("==============================\r");
        println!("Please Select Profile To Edit \r");
        println!("==============================\r");

        let profiles_len = {
            let profiles = PROFILES_CACHE.lock().unwrap();
            if profiles.is_empty() {
                println!("No profiles found.\r");
            } else {
                for (i, profile) in profiles.iter().enumerate() {
                    if i == selected_profile_index {
                        println!(" > [X] {}\r", profile.profile_name);
                    } else {
                        println!(" > [ ] {}\r", profile.profile_name);   
                    }
                }
            }
            profiles.len()
        };

        println!("\n[Press 'Backspace' to return to main menu]\r");
        io::stdout().flush().unwrap();

        if let Ok(Event::Key(key_event)) = event::read() {
            match key_event.code {
                KeyCode::Up => {
                    if selected_profile_index > 0 { selected_profile_index -= 1; } 
                    else if profiles_len > 0 { selected_profile_index = profiles_len - 1; }
                }
                KeyCode::Down => {
                    if selected_profile_index < profiles_len.saturating_sub(1) { selected_profile_index += 1; } 
                    else { selected_profile_index = 0; }
                }
                KeyCode::Backspace => { break; }
                KeyCode::Enter => {
                    if profiles_len == 0 { continue; }

                    let mut profile_to_edit = {
                        let profiles = PROFILES_CACHE.lock().unwrap();
                        profiles[selected_profile_index].clone()
                    };

                    loop {
                        let menu_title = format!("EDITING: {}", profile_to_edit.profile_name);
                        
                        // Şifre artık şifreli saklandığı için ekranda sabit maske gösteriyoruz
                        let masked_password = "********".to_string();

                        let field_items = vec![
                            format!("1. Profile Name : {}", profile_to_edit.profile_name),
                            format!("2. Username     : {}", profile_to_edit.username),
                            format!("3. Password     : {}", masked_password), // Maskeli gösterim
                            format!("4. Hostname     : {}", profile_to_edit.hostname),
                            format!("5. Port         : {}", profile_to_edit.port),
                            "6. Save & Return".to_string(),
                        ];

                        if let Some(field_index) = handle_menu(&menu_title, &field_items) {
                            match field_index {
                                0 => {
                                    if let Some(new_val) = read_input("New Profile Name:", &profile_to_edit.profile_name) {
                                        profile_to_edit.profile_name = new_val;
                                    }
                                }
                                1 => {
                                    if let Some(new_val) = read_input("New Username:", &profile_to_edit.username) {
                                        profile_to_edit.username = new_val;
                                    }
                                }
                                2 => {
                                    // Mevcut şifre asla düz metin gösterilmez; boş bırakılırsa eskisi korunur
                                    if let Some(new_val) = read_password_input("New Password (leave empty to keep current):") {
                                        if !new_val.is_empty() {
                                            profile_to_edit.password = crypto::encrypt(&new_val);
                                        }
                                    }
                                }
                                3 => {
                                    if let Some(new_val) = read_input("New Hostname:", &profile_to_edit.hostname) {
                                        profile_to_edit.hostname = new_val;
                                    }
                                }
                                4 => {
                                    if let Some(new_val) = read_input("New Port:", &profile_to_edit.port.to_string()) {
                                        if let Ok(parsed_port) = new_val.parse() {
                                            profile_to_edit.port = parsed_port;
                                        }
                                    }
                                }
                                5 => {
                                    {
                                        let mut profiles = PROFILES_CACHE.lock().unwrap();
                                        profiles[selected_profile_index] = profile_to_edit.clone();
                                    }
                                    save_profiles_to_json();
                                    break;
                                }
                                _ => {}
                            }
                        } else {
                            break; 
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

pub fn save_profiles_to_json() {
    // 1. Get the current state of profiles from the cache
    let profiles = PROFILES_CACHE.lock().unwrap();

    // 2. Serialize the vector to a nicely formatted JSON string
    match serde_json::to_string_pretty(&*profiles) {
        Ok(json_content) => {
            // 3. Write the JSON string to the file
            if let Err(e) = fs::write(common::config_file("profiles.json"), json_content) {
                // If writing fails, clear screen and show error briefly
                clear_screen();
                println!("Error writing to profiles.json: {}\r", e);
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
        Err(e) => {
            // If serialization fails
            clear_screen();
            println!("Error serializing profiles: {}\r", e);
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
}

fn delete_profiles() {
    let mut selected_profile_index: usize = 0;
    
    loop {
        clear_screen();

        println!("================================\r");
        println!(" Please Select Profile To Delete \r");
        println!("================================\r");

        // 1. Profilleri listeleme ve sayısını alma
        let profiles_len = {
            let profiles = PROFILES_CACHE.lock().unwrap();
            
            if profiles.is_empty() {
                println!("No profiles found.\r");
            } else {
                for (i, profile) in profiles.iter().enumerate() {
                    if i == selected_profile_index {
                        println!(" > [X] {}\r", profile.profile_name);
                    } else {
                        println!(" > [ ] {}\r", profile.profile_name);   
                    }
                }
            }
            profiles.len()
        };

        println!("\n[Press 'Enter' to delete | 'Backspace' to return main menu]\r");
        io::stdout().flush().unwrap();

        if let Ok(Event::Key(key_event)) = event::read() {
            match key_event.code {
                KeyCode::Up => {
                    if selected_profile_index > 0 { selected_profile_index -= 1; } 
                    else if profiles_len > 0 { selected_profile_index = profiles_len - 1; }
                }
                KeyCode::Down => {
                    if selected_profile_index < profiles_len.saturating_sub(1) { selected_profile_index += 1; } 
                    else { selected_profile_index = 0; }
                }
                KeyCode::Backspace => {
                    break; // Ana menüye dön
                }
                KeyCode::Enter => {
                    if profiles_len == 0 { continue; }

                    // Silinecek profilin adını alalım (onay mesajında göstermek için)
                    let profile_name = {
                        let profiles = PROFILES_CACHE.lock().unwrap();
                        profiles[selected_profile_index].profile_name.clone()
                    };

                    // 2. Onay (Confirmation) ekranı
                    clear_screen();
                    println!("=======================================\r");
                    println!(" Are you sure you want to delete '{}'? \r", profile_name);
                    println!("=======================================\r");
                    println!("\n[Press 'Y' to confirm | 'N' or 'Esc' to cancel]\r");
                    io::stdout().flush().unwrap();

                    let mut confirmed = false;
                    loop {
                        if let Ok(Event::Key(confirm_event)) = event::read() {
                            match confirm_event.code {
                                KeyCode::Char('y') | KeyCode::Char('Y') => {
                                    confirmed = true;
                                    break;
                                }
                                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Backspace => {
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }

                    // 3. Eğer onaylandıysa sil ve kaydet
                    if confirmed {
                        {
                            let mut profiles = PROFILES_CACHE.lock().unwrap();
                            profiles.remove(selected_profile_index); // Vektörden çıkar
                        }
                        
                        save_profiles_to_json(); // Değişikliği dosyaya yaz

                        // Eğer listenin en sonundaki elemanı sildiysek, imleci bir yukarı kaydır ki out-of-bounds olmasın
                        if selected_profile_index >= profiles_len - 1 && selected_profile_index > 0 {
                            selected_profile_index -= 1;
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn connect_profiles() {
    let mut selected_profile_index: usize = 0;
    
    loop {
        clear_screen();
        println!("=================================\r");
        println!(" Please Select Profile To Connect \r");
        println!("=================================\r");

        let profiles_len = {
            let profiles = PROFILES_CACHE.lock().unwrap();
            if profiles.is_empty() {
                println!("No profiles found.\r");
            } else {
                for (i, profile) in profiles.iter().enumerate() {
                    if i == selected_profile_index {
                        println!(" > [X] {}\r", profile.profile_name);
                    } else {
                        println!(" > [ ] {}\r", profile.profile_name);   
                    }
                }
            }
            profiles.len()
        };

        println!("\n[Press 'Enter' to connect | 'Backspace' to return]\r");
        io::stdout().flush().unwrap();

        if let Ok(Event::Key(key_event)) = event::read() {
            match key_event.code {
                KeyCode::Up => {
                    if selected_profile_index > 0 { selected_profile_index -= 1; } 
                    else if profiles_len > 0 { selected_profile_index = profiles_len - 1; }
                }
                KeyCode::Down => {
                    if selected_profile_index < profiles_len.saturating_sub(1) { selected_profile_index += 1; } 
                    else { selected_profile_index = 0; }
                }
                KeyCode::Backspace => { break; }
                KeyCode::Enter => {
                    if profiles_len == 0 { continue; }

                    // Profili al
                    let profile = {
                        let profiles = PROFILES_CACHE.lock().unwrap();
                        profiles[selected_profile_index].clone()
                    };

                    clear_screen();
                    establish_connection(&profile);
                    
                    println!("\n[Press any key to return to menu]\r");
                    io::stdout().flush().unwrap();
                    loop {
                        if let Ok(Event::Key(_)) = event::read() { break; }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Profile bağlanır, oturum bitene kadar bloklar ve sonucu ekrana yazar.
/// Hem menüden hem de `shellix <profil>` doğrudan bağlantısından kullanılır.
fn establish_connection(profile: &ServerProfile) {
    println!("Connecting to {} ({}@{}:{})...\r", profile.profile_name, profile.username, profile.hostname, profile.port);
    io::stdout().flush().unwrap();

    // Kayıtlı şifreyi sadece bellek içinde çöz ve russh ile bağlan.
    // Terminal zaten raw mode'da olduğu için tuşlar doğrudan sunucuya akar.
    let result = match crypto::decrypt(&profile.password) {
        Some(plain_password) => ssh::connect_blocking(profile, &plain_password),
        None => Err("Stored password could not be decrypted (corrupted data or wrong PIN)".to_string()),
    };

    match result {
        Ok(()) => {
            println!("\r\nDisconnected from {}.\r", profile.profile_name);
        }
        Err(e) => {
            println!("\r\nSSH error: {}\r", e);
        }
    }
}

/// `shellix <profil_adı>` için: menüyü hiç açmadan adı verilen profile bağlanır.
pub fn connect_direct(profile_name: &str) {
    let profile = {
        let profiles = PROFILES_CACHE.lock().unwrap();
        profiles
            .iter()
            .find(|p| p.profile_name.eq_ignore_ascii_case(profile_name))
            .cloned()
    };

    match profile {
        Some(profile) => establish_connection(&profile),
        None => {
            println!("Profile '{}' not found.\r", profile_name);
            let profiles = PROFILES_CACHE.lock().unwrap();
            if profiles.is_empty() {
                println!("No profiles saved yet. Run 'shellix' and use 'Create Profile'.\r");
            } else {
                println!("Available profiles:\r");
                for p in profiles.iter() {
                    println!("  - {}\r", p.profile_name);
                }
            }
        }
    }
}

/// PIN değiştirme: doğrulama sonrası tüm kayıtlı şifreler eski anahtarla
/// çözülüp yeni PIN'den türetilen anahtarla yeniden şifrelenir.
fn change_pin() {
    let current = match read_password_input("Enter CURRENT PIN:") {
        Some(val) => val,
        None => return,
    };
    if !crypto::check_pin(current.trim()) {
        clear_screen();
        println!("Wrong PIN!\r");
        std::thread::sleep(std::time::Duration::from_secs(1));
        return;
    }

    let new_pin = match read_password_input("Enter NEW PIN:") {
        Some(val) if !val.trim().is_empty() => val.trim().to_string(),
        Some(_) => {
            clear_screen();
            println!("PIN cannot be empty!\r");
            std::thread::sleep(std::time::Duration::from_secs(1));
            return;
        }
        None => return,
    };
    let confirm = match read_password_input("Confirm NEW PIN:") {
        Some(val) => val.trim().to_string(),
        None => return,
    };
    if new_pin != confirm {
        clear_screen();
        println!("PINs do not match!\r");
        std::thread::sleep(std::time::Duration::from_secs(1));
        return;
    }

    // 1. Tüm şifreleri ESKİ anahtar hâlâ aktifken çöz
    let decrypted: Vec<Option<String>> = {
        let profiles = PROFILES_CACHE.lock().unwrap();
        profiles.iter().map(|p| crypto::decrypt(&p.password)).collect()
    };

    // 2. Yeni anahtarı devreye al (shellix.pin doğrulayıcısı da güncellenir)
    if let Err(e) = crypto::set_pin(&new_pin) {
        clear_screen();
        println!("Error: {}\r", e);
        std::thread::sleep(std::time::Duration::from_secs(2));
        return;
    }

    // 3. Şifreleri yeni anahtarla yeniden şifrele
    {
        let mut profiles = PROFILES_CACHE.lock().unwrap();
        for (profile, plain) in profiles.iter_mut().zip(decrypted.iter()) {
            if let Some(plain) = plain {
                profile.password = crypto::encrypt(plain);
            }
            // Çözülemeyen kayıt olduğu gibi bırakılır (eski PIN'le de çözülemiyordu)
        }
    }
    save_profiles_to_json();

    clear_screen();
    println!("=======================================\r");
    println!("     PIN Changed Successfully! 🎉      \r");
    println!("=======================================\r");
    std::thread::sleep(std::time::Duration::from_secs(1));
}

/// Main entry point for the menu lifecycle loop
pub fn run_menu() {
    let main_menu_items : Vec<String> = MENU_ITEMS.iter().map(|s| s.to_string()).collect();

    loop {
        if let Some(selected_index) = handle_menu("SHELLIX MAIN MENU", &main_menu_items) {
            match selected_index {
                0 => show_profiles(),
                1 => edit_profiles(),
                2 => delete_profiles(),
                3 => connect_profiles(),
                4 => create_profile(),
                5 => change_pin(),
                6 => { println!("Exiting...\r"); break; },
                _ => {}
            }
        } else {
            break;
        }
    }
}