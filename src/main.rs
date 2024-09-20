use eframe::{egui, App};
use tokio::runtime::Runtime;

mod authentication;

fn main() -> Result<(), eframe::Error> {
    // Initialize the Tokio runtime
    let rt = Runtime::new().unwrap();
    let _guard = rt.enter(); // Enter the runtime context

    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Cloudflare D1 GUI",
        native_options,
        Box::new(|_cc| Ok(Box::new(authentication::D1Gui::default()))),
    )
}
