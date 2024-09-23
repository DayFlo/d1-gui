use eframe;
use std::sync::{Arc, Mutex};

mod authentication;

fn main() -> Result<(), eframe::Error> {

    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Cloudflare D1 GUI",
        native_options,
        Box::new(|_cc| {
            Ok(Box::new(authentication::D1Gui::default()))
        }),
    );
    Ok(())
}
