use std::process::Command;
use crossterm::event::{self, Event, KeyCode};
use std::io::{self, Write};
use std::fs::File;
use std::io::Write;

// Define menu options globally as a constant
const MENU_ITEMS: [&str; 5] = [
    "1. Show Profiles",
    "2. Edit Profiles",
    "3. Delete Profiles",
    "4. Connect Profiles",
    "5. Exit Shellix"
];

pub fn clear_screen() {
    // --- TERMİNALİ TEMİZLEME KODU ---
    if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "cls"]).status().unwrap();
    } else {
        Command::new("clear").status().unwrap();
    }
}

/// Renders the menu interface based on the currently selected index
fn render_menu(selected_index: usize) {
    clear_screen();
    
    println!("======================================================\r");
    println!("                    SHELLIX MAIN MENU                 \r");
    println!("       (Use Arrow Keys to navigate, Enter to select)  \r");
    println!("======================================================\r");

    // Loop through items and highlight the selected one
    for (i, item) in MENU_ITEMS.iter().enumerate() {
        if i == selected_index {
            // Highlighted row
            println!(" > [X] {} \r", item);
        } else {
            // Normal row
            println!("   [ ] {} \r", item);
        }
    }
    println!("======================================================\r");
    io::stdout().flush().unwrap();
}

/// Main entry point for the menu lifecycle loop
pub fn run_menu() {
    let mut selected_index = 0;

    // Initial render of the menu
    render_menu(selected_index);

    loop {
        // Read input events from the terminal
        if let Ok(Event::Key(key_event)) = event::read() {
            match key_event.code {
                KeyCode::Up => {
                    if selected_index > 0 {
                        selected_index -= 1;
                    } else {
                        selected_index = MENU_ITEMS.len() - 1; // Wrap around to bottom
                    }
                    render_menu(selected_index);
                }
                KeyCode::Down => {
                    if selected_index < MENU_ITEMS.len() - 1 {
                        selected_index += 1;
                    } else {
                        selected_index = 0; // Wrap around to top
                    }
                    render_menu(selected_index);
                }
                KeyCode::Enter => {
                    print!("\r\nExecuting selected action... \r\n");
                    
                    match selected_index {
                        0 => println!(">> Profile: Beyto (Administrator)\r"),
                        1 => println!(">> System Status: All systems operational.\r"),
                        2 => println!(">> Delete Profiles\r"),
                        3 => println!(">> Connect Profiles\r"),
                        4 => {
                            println!("Exiting application...\r");
                            break; // Break the loop to exit the function
                        }
                        _ => {}
                    }
                    io::stdout().flush().unwrap();
                }
                KeyCode::Esc => {
                    break; // Exit menu with Escape key
                }
                _ => {} // Ignore other keystrokes
            }
        }
    }
}
/* 
fn show_profiles(){
    
}*/