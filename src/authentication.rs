use eframe::egui::{self, TextEdit};
use egui_file::FileDialog;
use serde_json::Value;
use std::cell::RefCell;
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;

#[derive(Clone, PartialEq)]
pub enum AuthenticationMode {
    Credentials,
    Wrangler,
}

pub struct D1Gui {
    query: String,
    results: String,
    history: Vec<String>,
    database_uuid: String,
    database_name: String,
    database_context: String,
    account_id: String,
    api_token: String,
    is_authenticated: bool,
    status_message: String,
    is_executing: bool,
    authentication_mode: AuthenticationMode,
    wrangler_file: Option<PathBuf>,
    file_dialog: Option<FileDialog>,
}

impl Default for D1Gui {
    fn default() -> Self {
        Self {
            query: String::new(),
            results: String::new(),
            history: Vec::new(),
            database_uuid: String::new(),
            database_name: String::new(),
            database_context: String::new(),
            account_id: String::new(),
            api_token: String::new(),
            is_authenticated: false,
            status_message: String::new(),
            is_executing: false,
            authentication_mode: AuthenticationMode::Credentials,
            wrangler_file: None,
            file_dialog: None,
        }
    }
}

impl eframe::App for D1Gui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.update_ui(ctx);
    }
}

impl D1Gui {
    pub fn update_ui(&mut self, ctx: &egui::Context) {
        let this = Arc::new(Mutex::new(self.clone())); // Wrap self in Arc<Mutex>

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Cloudflare D1 GUI");

            if !self.is_authenticated {
                ui.label("Please select your authentication method.");

                ui.horizontal(|ui| {
                    ui.label("Authentication Mode:");
                    ui.radio_value(
                        &mut self.authentication_mode,
                        AuthenticationMode::Credentials,
                        "Use Credentials",
                    );
                    ui.radio_value(
                        &mut self.authentication_mode,
                        AuthenticationMode::Wrangler,
                        "Use Wrangler.toml",
                    );
                });

                match self.authentication_mode {
                    AuthenticationMode::Credentials => {
                        ui.horizontal(|ui| {
                            ui.label("Account ID:");
                            ui.text_edit_singleline(&mut self.account_id);
                        });

                        ui.horizontal(|ui| {
                            ui.label("Database UUID:");
                            ui.text_edit_singleline(&mut self.database_uuid);
                        });

                        ui.horizontal(|ui| {
                            ui.label("Database Name:");
                            ui.text_edit_singleline(&mut self.database_name);
                        });

                        ui.horizontal(|ui| {
                            ui.label("Bearer Auth:");
                            ui.add(TextEdit::singleline(&mut self.api_token).password(true));
                        });
                    }
                    AuthenticationMode::Wrangler => {
                        ui.label("Wrangler mode will use the configuration from wrangler.toml.");
                        ui.horizontal(|ui| {
                            ui.label("Database UUID:");
                            ui.text_edit_singleline(&mut self.database_uuid);
                        });

                        ui.horizontal(|ui| {
                            ui.label("Database Name:");
                            ui.text_edit_singleline(&mut self.database_name);
                        });

                        // Wrangler.toml file selection
                        ui.horizontal(|ui| {
                            if let Some(file) = &self.wrangler_file {
                                ui.label(format!("Selected file: {:?}", file.display()));
                            } else {
                                ui.label("No file selected.");
                            }

                            if ui.button("Pick Wrangler.toml").clicked() {
                                let mut dialog = FileDialog::open_file(None)
                                    .resizable(false)
                                    .title("Select wrangler.toml");
                                dialog.open();
                                self.file_dialog = Some(dialog);
                            }
                        });

                        // Show file picker if the dialog is set
                        if let Some(dialog) = &mut self.file_dialog {
                            dialog.show(ctx);

                            if dialog.selected() {
                                if let Some(file) = dialog.path() {
                                    self.wrangler_file = Some(file.to_path_buf().clone());
                                }
                                self.file_dialog = None; // Close the dialog after selection
                            }
                        }
                    }
                }

                if ui.button("Authenticate").clicked() {
                    let ctx = ctx.clone();
                    let this = Arc::clone(&this);

                    Handle::current().spawn(async move {
                        let (mut status_message, mut is_authenticated, mut cloned_this); // Declare cloned_this as mutable

                        // Acquire the lock, clone/copy necessary values, and drop the lock
                        {
                            let this = this.lock().unwrap(); // Lock the mutex

                            // Clone/copy the values you need
                            cloned_this = this.clone(); // Clone the `D1Gui` instance
                            status_message = this.status_message.clone();
                            is_authenticated = this.is_authenticated;
                        } // Lock is dropped here

                        // Now perform the async operation without holding the lock
                        if let Err(err) = cloned_this.authenticate().await {
                            status_message = format!("Authentication failed: {}", err);
                        } else {
                            is_authenticated = true;
                            status_message = "Authentication successful.".to_string();
                        }

                        // Re-acquire the lock to update the shared state
                        let mut this = this.lock().unwrap();
                        this.status_message = status_message;
                        this.is_authenticated = is_authenticated;

                        ctx.request_repaint();
                    });
                }

                if !self.status_message.is_empty() {
                    ui.label(&self.status_message);
                }

                return;
            }

            // Authenticated UI
            ui.horizontal(|ui| {
                if ui.button("Change Connection").clicked() {
                    self.is_authenticated = false;
                    self.account_id.clear();
                    self.api_token.clear();
                    self.database_uuid.clear();
                    self.database_name.clear();
                    self.database_context.clear();
                    self.status_message.clear();
                    self.query.clear();
                    self.results.clear();
                    self.history.clear();
                    self.wrangler_file = None;
                }
            });

            // Display status messages
            if !self.status_message.is_empty() {
                ui.label(&self.status_message);
                self.status_message.clear();
            }

            ui.separator();

            ui.label("Enter your SQL query:");
            ui.add(TextEdit::multiline(&mut self.query).desired_rows(5));

            if !self.is_executing && ui.button("Execute Query").clicked() {
                self.is_executing = true; // Prevent multiple queries
                let ctx = ctx.clone();

                // Clone only the cloneable parts of `self`
                let mut this = D1Gui {
                    query: self.query.clone(),
                    results: self.results.clone(),
                    history: self.history.clone(),
                    database_uuid: self.database_uuid.clone(),
                    database_name: self.database_name.clone(),
                    database_context: self.database_context.clone(),
                    account_id: self.account_id.clone(),
                    api_token: self.api_token.clone(),
                    is_authenticated: self.is_authenticated,
                    status_message: self.status_message.clone(),
                    is_executing: self.is_executing,
                    authentication_mode: self.authentication_mode.clone(),
                    wrangler_file: self.wrangler_file.clone(),
                    file_dialog: None, // Set this to None or handle it differently
                };

                Handle::current().spawn(async move {
                    if let Err(err) = this.authenticate().await {
                        this.status_message = format!("Authentication failed: {}", err);
                    } else {
                        this.is_authenticated = true;
                        this.status_message = "Authentication successful.".to_string();
                    }
                    match this.execute_query().await {
                        Ok(_) => {
                            this.status_message = "Query executed successfully.".to_string();
                            this.results = this.results.trim().to_string();
                        }
                        Err(err) => {
                            this.results = format!("Error: {}", err);
                        }
                    }

                    this.reset_after_query();
                    ctx.request_repaint();
                });
            }

            ui.separator();

            println!("Results: {}", self.results);
            ui.label("Results:");
            ui.add(
                TextEdit::multiline(&mut self.results)
                    .desired_rows(10)
                    .font(egui::TextStyle::Monospace),
            );

            ui.separator();

            ui.label("Query History:");
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Collect history to avoid mutable and immutable borrow conflicts
                let query_history = self.history.clone();

                for past_query in query_history {
                    if ui.button(&past_query).clicked() {
                        self.query = past_query;
                    }
                }
            });
        });
    }

    pub async fn authenticate(&mut self) -> Result<(), String> {
        match self.authentication_mode {
            AuthenticationMode::Credentials => {
                let client = reqwest::Client::new();

                let url = format!(
                    "https://api.cloudflare.com/client/v4/accounts/{}/d1/database/{}",
                    self.account_id.trim(),
                    self.database_uuid.trim()
                );

                let response = client
                    .get(&url)
                    .bearer_auth(self.api_token.trim())
                    .send()
                    .await
                    .map_err(|e| format!("Request failed: {}", e))?;

                let status = response.status();
                let text = response.text().await.map_err(|e| e.to_string())?;

                if !status.is_success() {
                    return Err(format!("Error: HTTP {}: {}", status, text));
                }

                let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;

                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if !success {
                        return Err(
                            "Authentication failed: API response indicated failure.".to_string()
                        );
                    }
                } else {
                    return Err("Malformed API response: missing 'success' field.".to_string());
                }

                Ok(())
            }
            AuthenticationMode::Wrangler => {
                let mut args = vec!["whoami"];

                if let Some(ref wrangler_file) = self.wrangler_file {
                    if let Some(wrangler_path) = wrangler_file.to_str() {
                        args.push("-c");
                        args.push(wrangler_path);
                    } else {
                        return Err("Invalid wrangler.toml file path.".to_string());
                    }
                }

                let output = Command::new("wrangler").args(&args).output();

                match output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);

                        let combined_output = format!("{}\n{}", stdout, stderr);

                        if combined_output.contains("You are not authenticated") {
                            Err(
                                "Wrangler is not authenticated. Please run 'wrangler login'."
                                    .to_string(),
                            )
                        } else if combined_output.contains("You are logged in") {
                            Ok(())
                        } else {
                            Err("Unable to determine Wrangler authentication status.".to_string())
                        }
                    }
                    Err(err) => Err(format!("Failed to execute 'wrangler whoami': {}", err)),
                }
            }
        }
    }

    pub async fn execute_query(&mut self) -> Result<(), String> {
        if !self.is_authenticated {
            self.status_message =
                "Not authenticated. Please provide your API credentials.".to_string();
            return Err(self.status_message.clone());
        }

        if self.query.trim().is_empty() {
            return Err("SQL query is required.".to_string());
        }

        match self.authentication_mode {
            AuthenticationMode::Credentials => {
                let client = reqwest::Client::new();

                // Create the Cloudflare D1 API URL
                let url = format!(
                    "https://api.cloudflare.com/client/v4/accounts/{}/d1/database/{}",
                    self.account_id.trim(),
                    self.database_uuid.trim()
                );

                let response = client
                    .get(&url)
                    .bearer_auth(self.api_token.trim())
                    .send()
                    .await
                    .map_err(|e| format!("Request failed: {}", e))?;

                let status = response.status();
                let text = response.text().await.map_err(|e| e.to_string())?;

                if !status.is_success() {
                    return Err(format!("Error: HTTP {}: {}", status, text));
                }

                // Parse the JSON response
                let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;

                // Check if the "success" field is true
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if !success {
                        return Err(
                            "Authentication failed: API response indicated failure.".to_string()
                        );
                    }
                } else {
                    return Err("Malformed API response: missing 'success' field.".to_string());
                }
                Ok(())
            }
            AuthenticationMode::Wrangler => {
                if self.database_name.trim().is_empty() {
                    return Err("Database name is required.".to_string());
                }

                if self.database_uuid.trim().is_empty() {
                    return Err("Database UUID is required.".to_string());
                }

                let mut args = vec![
                    "d1",
                    "execute",
                    self.database_name.trim(),
                    "--database",
                    self.database_uuid.trim(),
                    "--command",
                    self.query.trim(),
                    "--json",
                ];

                if let Some(ref wrangler_file) = self.wrangler_file {
                    if let Some(wrangler_path) = wrangler_file.to_str() {
                        args.push("-c");
                        args.push(wrangler_path);
                    } else {
                        return Err("Invalid wrangler.toml file path.".to_string());
                    }
                }

                let output = Command::new("wrangler")
                    .args(&args)
                    .output()
                    .map_err(|e| e.to_string())?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(stderr.to_string());
                }

                let stdout = String::from_utf8_lossy(&output.stdout).to_string();

                // Parse the JSON output
                let value: Value = serde_json::from_str(&stdout).map_err(|e| e.to_string())?;

                // Extract the results
                if let Some(result) = value.get("result") {
                    self.results =
                        serde_json::to_string_pretty(result).map_err(|e| e.to_string())?;
                } else {
                    self.results =
                        serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
                }

                // Save the query to history
                let trimmed_query = self.query.trim().to_string();
                if !trimmed_query.is_empty() {
                    if self.history.first() != Some(&trimmed_query) {
                        self.history.insert(0, trimmed_query);
                    }
                }

                Ok(())
            }
        }
    }

    pub fn reset_after_query(&mut self) {
        self.is_executing = false;
        self.status_message.clear();
    }
}

impl Clone for D1Gui {
    fn clone(&self) -> Self {
        Self {
            query: self.query.clone(),
            results: self.results.clone(),
            history: self.history.clone(),
            database_uuid: self.database_uuid.clone(),
            database_name: self.database_name.clone(),
            database_context: self.database_context.clone(),
            account_id: self.account_id.clone(),
            api_token: self.api_token.clone(),
            is_authenticated: self.is_authenticated,
            status_message: self.status_message.clone(),
            is_executing: self.is_executing,
            authentication_mode: self.authentication_mode.clone(),
            wrangler_file: self.wrangler_file.clone(),
            file_dialog: None,
        }
    }
}
