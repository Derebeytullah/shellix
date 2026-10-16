# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Shellix is a terminal-based SSH connection manager written in Rust (edition 2024). It presents an arrow-key-driven menu (crossterm raw mode) for creating, editing, deleting, and connecting to SSH server profiles stored in `profiles.json`.

## Commands

- `cargo build` — build
- `cargo run` — run the app (interactive TUI menu; default PIN is `1234` until changed in-app)
- `cargo run -- <profile_name>` — skip the menu and connect directly to that profile (case-insensitive match)
- `cargo check` — fast type-check
- `cargo test` — run unit tests (currently only in `src/crypto.rs`)

All state files (`profiles.json`, `shellix.salt`, `shellix.pin`, `known_hosts.json`) live in the user config dir — `~/.config/shellix` on Linux (`dirs::config_dir()` + `/shellix`) — so the app runs from any directory. `common::migrate_legacy_files` moves files left in the CWD by old versions on startup. A tracked `profiles.example.json` documents the profile format; the real `profiles.json` is gitignored.

## Architecture

- `src/main.rs` — entry point: PIN gate, enables/disables crossterm raw mode around the menu lifecycle.
- `src/menu.rs` — nearly all logic lives here: the global profile store (`PROFILES_CACHE`, a `lazy_static` `Mutex<Vec<ServerProfile>>`), the reusable menu/input widgets (`handle_menu`, `read_input`), each menu screen (show/edit/delete/connect/create), and JSON persistence (`save_profiles_to_json`).
- `src/model.rs` — `ServerProfile` struct (serde Serialize/Deserialize).
- `src/common.rs` — config-dir path helpers (`config_dir`, `config_file`, `migrate_legacy_files`) and the `read_json` file-reading helper.
- `src/crypto.rs` — password encryption: AES-256-GCM with a key derived (PBKDF2-HMAC-SHA256) from the login PIN + a random per-install salt in `shellix.salt` (gitignored). Stored values look like `enc:<base64(nonce+ciphertext)>`; `load_profiles_to_cache` transparently migrates any plaintext passwords it finds and rewrites the file. `crypto::login` (called once in main) verifies the PIN and loads the key in a single derivation — the key must be loaded before any encrypt/decrypt.
- **PIN storage**: the PIN itself is never stored — `shellix.pin` (gitignored) holds a verifier, SHA-256 of the derived key. Missing file ⇒ default PIN `1234` is accepted and the file is created on first login. "Change PIN" (`menu::change_pin`) must decrypt all passwords with the old key *before* calling `crypto::set_pin`, then re-encrypt and save — keep that ordering, the active key changes in between.
- `src/ssh.rs` — built-in SSH client (russh, no system `ssh` dependency). `connect_blocking` spins up a tokio runtime, authenticates with the decrypted password, opens a PTY+shell, and bridges crossterm key events → channel bytes and channel data → stdout. Key events are translated to terminal escape sequences in `key_event_to_bytes`; using the crossterm `EventStream` (not raw stdin) is deliberate — it shares the menu's event source so no keystrokes are lost when a session ends. The runtime is shut down with `shutdown_background()`, a normal drop would block.
- **Host key TOFU**: fingerprints are stored per `host:port` in `known_hosts.json` (gitignored). The interactive accept/warn prompts cannot run inside `check_server_key` (it executes during the handshake inside the runtime — blocking there would stall the session I/O), so an unknown/mismatched key rejects the connection (`SessionError::HostKeyRejected`), the prompt runs outside the runtime, and on approval the fingerprint is saved and the connection retried. Keep this two-phase structure when touching host key logic.

Key patterns to preserve:

- **Raw mode is on for the whole session**, so every `println!` ends with `\r` to reset the cursor column. Keep this in any new output.
- **Mutex discipline**: screens lock `PROFILES_CACHE` in a tight scope (clone what's needed, drop the guard) before blocking on `event::read()` or calling `save_profiles_to_json()`, which takes the lock itself — holding the guard across those calls will deadlock or block.
- Comments are partly in Turkish; that's the author's style, not an error.

## Caveats

- Passwords in `profiles.json` are encrypted at rest, but the file is git-tracked and old plaintext credentials remain in git history. Never display or log decrypted passwords; password input uses `read_password_input` (masked with `*`).
- Losing `shellix.salt` (or changing the PIN) makes existing encrypted passwords undecryptable — there is no re-key flow yet.
- Host keys are verified TOFU-style against `known_hosts.json`; deleting that file re-triggers first-use prompts for all hosts.
- PBKDF2 (100k iterations) takes seconds in **debug** builds, so there is a noticeable pause between entering the PIN and the menu appearing; release builds are instant. Automated/pty tests must wait for the menu marker instead of using fixed sleeps.
- The codebase is fully cross-platform (pure-Rust dependency tree, no OpenSSL); `cargo check --target x86_64-pc-windows-msvc` is a cheap portability check.
