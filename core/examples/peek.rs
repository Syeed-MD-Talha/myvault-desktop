//! Diagnostic helper: read a container header without knowing the password.
//!
//! ```text
//! cargo run -p myvault-core --example peek -- path\to\vault.vault
//! ```

fn main() {
    let path = match std::env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("usage: peek <vault-file>");
            std::process::exit(2);
        }
    };

    match myvault_core::services::vault::peek(&path) {
        Ok((name, version)) => println!("name={name} format_version={version}"),
        Err(e) => {
            println!("peek failed: {e} ({})", e.code());
            std::process::exit(1);
        }
    }

    match myvault_core::OpenedVault::open(&path) {
        Ok(opened) => {
            let id: String = opened
                .vault_id()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            println!(
                "header ok: vault_id={id} format_version={}",
                opened.format_version()
            );
        }
        Err(e) => {
            println!("open failed: {e} ({})", e.code());
            std::process::exit(1);
        }
    }
}
