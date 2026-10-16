mod menu;
mod common;
mod model;
mod crypto;
mod ssh;
use std::io::{self, Write}; // Girdi/Çıktı kütüphanesini çağırdık
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

fn main() {
    // "shellix" -> menü, "shellix <profil_adı>" -> doğrudan bağlantı
    let profile_arg: Option<String> = std::env::args().nth(1);

    // Eski sürümlerin çalışma dizininde bıraktığı durum dosyalarını config
    // dizinine taşı (PIN kontrolünden önce olmalı: shellix.pin/salt da taşınıyor)
    common::migrate_legacy_files();

    println!("======================================================");
    println!(" WELCOME TO THE SHELLIX CLI");
    println!("======================================================");
    println!("PLS ENTER YOUR PIN NUMBER :");

    // Terminalin hemen yazıyı basması için buffer'ı temizliyoruz
    io::stdout().flush().unwrap();
    let mut input = String::new(); // Gelen yazıyı kaydedeceğimiz boş bir değişken

    // Terminalden satırı oku ve 'input' değişkeninin içine yaz
    io::stdin().read_line(&mut input).expect("Okunamadı moruq");

    // PIN, shellix.pin'deki doğrulayıcıyla kontrol edilir (dosya yoksa varsayılan: 1234).
    // login aynı zamanda şifreleme anahtarını belleğe alır.
    if !crypto::login(input.trim()) {
        println!("Invalid PIN number");
        return;
    }
    println!("LOGIN SUCCESSFULL");

    enable_raw_mode().unwrap();

    menu::load_profiles_to_cache();

    match profile_arg {
        Some(profile_name) => menu::connect_direct(&profile_name),
        None => menu::run_menu(),
    }

    disable_raw_mode().unwrap();
    println!("Shellix closed successfully. See you space cowboy!");
}

