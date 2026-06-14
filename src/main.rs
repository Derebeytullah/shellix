mod menu;
use std::io::{self, Write}; // Girdi/Çıktı kütüphanesini çağırdık
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

fn main() {
    println!("======================================================");
    println!(" WELCOME TO THE SHELLIX CLI");
    println!("======================================================");
    println!("PLS ENTER YOUR PIN NUMBER :");
    
    // Terminalin hemen yazıyı basması için buffer'ı temizliyoruz
    io::stdout().flush().unwrap();
    let mut input = String::new(); // Gelen yazıyı kaydedeceğimiz boş bir değişken
    
    // Terminalden satırı oku ve 'input' değişkeninin içine yaz
    io::stdin().read_line(&mut input).expect("Okunamadı moruq");

    if input.trim() != "1234"{
        println!("Invalid PIN number");
        return;
    }
    println!("LOGIN SUCCESSFULL");
    
    enable_raw_mode().unwrap();

    menu::run_menu();
    
    disable_raw_mode().unwrap();
    println!("Shellix closed successfully. See you space cowboy!");
}

