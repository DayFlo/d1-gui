use tauri::command;

#[command]
fn greet(name: &str) -> String {
    format!("Hello, {}! Welcome to Tauri with Svelte!", name)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
