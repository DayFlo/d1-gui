extern crate eframe;
extern crate serde_json;
extern crate directories;
extern crate strip_ansi;
extern crate serde;
extern crate tokio;

use eframe::{ egui, App };
use serde_json::Value;
use tokio::runtime::Runtime;
use std::process::Command;
use std::sync::{ mpsc::{ channel, Receiver, Sender } };
use std::sync::mpsc;
use std::thread;

#[derive(Clone, PartialEq)]
enum AuthenticationMode {
    Credentials,
    Wrangler,
}

#[derive(Clone, PartialEq)]
enum DatabaseContext {
    Local,
    Remote,
    Preview,
}

pub struct D1Gui {
    query: String,
    results: String,
    history: Vec<String>,
    database_uuid: String,
    database_name: String,
    database_context: DatabaseContext,
    account_id: String,
    api_token: String,
    is_authenticated: bool,
    status_message: String,
    is_executing: bool,
    authentication_mode: AuthenticationMode,
    wrangler_toml_path: String,
    file_picker_sender: mpsc::Sender<String>,
    file_picker_receiver: mpsc::Receiver<String>,
}

impl Default for D1Gui {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();

        Self {
            query: String::new(),
            results: String::new(),
            history: Vec::new(),
            database_uuid: String::new(),
            database_name: String::new(),
            database_context: DatabaseContext::Remote,
            account_id: String::new(),
            api_token: String::new(),
            is_authenticated: false,
            status_message: String::new(),
            is_executing: false,
            authentication_mode: AuthenticationMode::Credentials,
            wrangler_toml_path: String::new(),
            file_picker_sender: sender,
            file_picker_receiver: receiver,
        }
    }
}

impl App for D1Gui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let rt = Runtime::new().unwrap();

        if let Ok(new_path) = self.file_picker_receiver.try_recv() {
            self.wrangler_toml_path = new_path;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Cloudflare D1 GUI");

            if !self.is_authenticated {
                self.show_authentication_ui(ui, &rt);
            } else {
                self.show_main_ui(ui, &rt);
            }
        });
    }
}

impl D1Gui {
    fn show_authentication_ui(&mut self, ui: &mut egui::Ui, rt: &Runtime) {
        ui.label("Please select your authentication method.");

        ui.horizontal(|ui| {
            ui.label("Authentication Mode:");
            ui.radio_value(&mut self.authentication_mode, AuthenticationMode::Credentials, "Use Credentials");
            ui.radio_value(&mut self.authentication_mode, AuthenticationMode::Wrangler, "Use Wrangler.toml");
        });

        match self.authentication_mode {
            AuthenticationMode::Credentials => self.show_credentials_ui(ui),
            AuthenticationMode::Wrangler => self.show_wrangler_ui(ui),
        }

        if ui.button("Authenticate").clicked() {
            self.handle_authentication(ui, rt);
        }

        if !self.status_message.is_empty() {
            ui.label(&self.status_message);
        }
    }

    fn show_credentials_ui(&mut self, ui: &mut egui::Ui) {
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
            ui.add(egui::TextEdit::singleline(&mut self.api_token).password(true));
        });
    }

    fn show_wrangler_ui(&mut self, ui: &mut egui::Ui) {
        ui.label("Wrangler mode will use the configuration from wrangler.toml.");
        ui.horizontal(|ui| {
            ui.label("Database UUID:");
            ui.text_edit_singleline(&mut self.database_uuid);
        });

        ui.horizontal(|ui| {
            ui.label("Database Name:");
            ui.text_edit_singleline(&mut self.database_name);
        });

        ui.horizontal(|ui| {
            ui.label("Wrangler .toml path:");
            if self.wrangler_toml_path.is_empty() {
                ui.label("No file selected");
            } else {
                ui.label(&self.wrangler_toml_path);
            }
        });

        if ui.button("📂 Open wrangler toml file").clicked() {
            let sender = self.file_picker_sender.clone();
            
            thread::spawn(move || {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    if let Some(path_str) = path.to_str() {
                        let _ = sender.send(path_str.to_string());
                    }
                }
            });
        }
    }

    fn handle_authentication(&mut self, ui: &mut egui::Ui, rt: &Runtime) {
        let ctx = ui.ctx().clone();

        rt.block_on(async move {
            match self.authenticate().await {
                Ok(_) => {
                    self.is_authenticated = true;
                    self.status_message = "Authentication successful.".to_string();
                }
                Err(err) => {
                    self.status_message = format!("Authentication failed: {}", err);

                    // Attempt to login
                    let _ = Command::new("wrangler").args(&[
                        "login",
                    ]).output();
                }
            }
            ctx.request_repaint();
        });
    }

    fn show_main_ui(&mut self, ui: &mut egui::Ui, rt: &Runtime) {
        if ui.button("Change Connection").clicked() {
            self.reset_connection();
        }

        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Database Context:");
            ui.radio_value(&mut self.database_context, DatabaseContext::Local, "Use Local");
            ui.radio_value(&mut self.database_context, DatabaseContext::Remote, "Use Remote");
            ui.radio_value(&mut self.database_context, DatabaseContext::Preview, "Use Preview");
        });

        ui.separator();

        ui.label("Enter your SQL query:");
        ui.text_edit_multiline(&mut self.query);

        if !self.is_executing && ui.button("Execute Query").clicked() {
            self.execute_query(ui, rt);
        }

        ui.separator();

        ui.label("Results:");
        ui.add(egui::TextEdit::multiline(&mut self.results)
            .desired_rows(10)
            .font(egui::TextStyle::Monospace));

        ui.separator();

        ui.label("Query History:");
        egui::ScrollArea::vertical().show(ui, |ui| {
            for past_query in &self.history {
                if ui.button(past_query).clicked() {
                    self.query = past_query.clone();
                }
            }
        });
    }

    fn reset_connection(&mut self) {
        self.is_authenticated = false;
        self.account_id.clear();
        self.api_token.clear();
        self.database_uuid.clear();
        self.database_name.clear();
        self.status_message.clear();
        self.query.clear();
        self.results.clear();
        self.history.clear();
    }

    fn execute_query(&mut self, ui: &mut egui::Ui, rt: &Runtime) {
        self.is_executing = true;
        let ctx = ui.ctx().clone();

        rt.block_on(async move {
            match self.execute_query_internal().await {
                Ok(_) => {
                    self.status_message = "Query executed successfully.".to_string();
                }
                Err(err) => {
                    self.results = format!("Error: {}", err);
                }
            }
            self.is_executing = false;
            ctx.request_repaint();
        });
    }

    async fn authenticate(&self) -> Result<(), String> {
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
            },
            AuthenticationMode::Wrangler => {
                let mut args = vec!["whoami"];

                let output = Command::new("wrangler").args(&args).output();
                if !self.wrangler_toml_path.is_empty() {
                    let config_args = vec![
                        "d1",
                        "--config",

                    ];
                    let _ = Command::new("wrangler")
                        .arg("d1")
                        .arg("--config")
                        .arg(format!("{}", &self.wrangler_toml_path.trim()))
                        .output();
                } else {
                    return Err(format!("No configuration wrangler .toml file selected"))
                }

                match output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);

                        let combined_output = format!("{}\n{}", stdout, stderr);

                        if combined_output.contains("You are not authenticated") {
                            Err(
                                "Wrangler is not authenticated. Attempting to login via 'wrangler login'. Please authenticate after completing oAuth flow"
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
            },
        }
    }

    async fn execute_query_internal(&mut self) -> Result<(), String> {
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
            "--json",
        ];


        let output = Command::new("wrangler")
            .args(&args)
            .arg("--command")
            .arg(format!("{}", &self.query.trim()))
            .output()
            .map_err(|e| e.to_string())?;


        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            if !stderr.is_empty() {
                return Err(stderr.to_string());
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);

                // Try to parse the stdout as JSON and extract the error message
                match serde_json::from_str::<Value>(&stdout) {
                    Ok(json) => {
                        if let Some(error_text) = json.get("error").and_then(|err| err.get("text")) {
                            return Err(error_text.as_str().unwrap_or("Unknown error").to_string());
                        } else {
                            return Err("Unknown error format in stdout".to_string());
                        }
                    }
                    Err(_) => {
                        return Err(format!("Failed to parse stdout as JSON: {}", stdout));
                    }
                }
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        // Parse the JSON output
        let value: Value = serde_json::from_str(&stdout).map_err(|e| e.to_string())?;

        // Extract the results
        if let Some(result) = value.get("result") {
            println!("Query result: {}", result);
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
