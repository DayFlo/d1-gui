extern crate eframe;
extern crate serde_json;
extern crate directories;
extern crate strip_ansi;
extern crate serde;
extern crate tokio;

use eframe::{egui, NativeOptions, App, Error, Frame};
use std::process::Command;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Write, Read};
use std::fs::OpenOptions;
use directories::BaseDirs;
use strip_ansi::strip_ansi;
use tokio::runtime::Runtime;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, PartialEq)]
enum AuthenticationMode {
    Credentials,
    Wrangler,
}

fn main() -> Result<(), eframe::Error> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Cloudflare D1 GUI",
        native_options,
        Box::new(|_cc| {
            let app = Arc::new(Mutex::new(D1Gui::default()));
            Ok(Box::new(D1GuiWrapper { app }))
        }),
    );
    Ok(())
}

#[derive(Clone)]
struct D1Gui {
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
        }
    }
}

struct D1GuiWrapper {
    app: Arc<Mutex<D1Gui>>,
}

impl App for D1GuiWrapper {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut app = self.app.lock().unwrap();
        use egui::TextEdit;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Cloudflare D1 GUI");

            if !app.is_authenticated {
                ui.label("Please select your authentication method.");

                ui.horizontal(|ui| {
                    ui.label("Authentication Mode:");
                    ui.radio_value(&mut app.authentication_mode, AuthenticationMode::Credentials, "Use Credentials");
                    ui.radio_value(&mut app.authentication_mode, AuthenticationMode::Wrangler, "Use Wrangler.toml");
                });

                match app.authentication_mode {
                    AuthenticationMode::Credentials => {
                        ui.horizontal(|ui| {
                            ui.label("Account ID:");
                            ui.text_edit_singleline(&mut app.account_id);
                        });

                        ui.horizontal(|ui| {
                            ui.label("Database UUID:");
                            ui.text_edit_singleline(&mut app.database_uuid);
                        });

                        ui.horizontal(|ui| {
                          ui.label("Database Name:");
                          ui.text_edit_singleline(&mut app.database_name);
                      });

                        ui.horizontal(|ui| {
                            ui.label("Bearer Auth:");
                            ui.add(TextEdit::singleline(&mut app.api_token).password(true));
                        });
                    },
                    AuthenticationMode::Wrangler => {
                        ui.label("Wrangler mode will use the configuration from wrangler.toml.");
                        ui.horizontal(|ui| {
                            ui.label("Database UUID:");
                            ui.text_edit_singleline(&mut app.database_uuid);
                        });

                        ui.horizontal(|ui| {
                          ui.label("Database Name:");
                          ui.text_edit_singleline(&mut app.database_name);
                      });
                    },
                }

                if ui.button("Authenticate").clicked() {
                    match app.authentication_mode {
                        AuthenticationMode::Credentials => {
                            if app.account_id.is_empty()
                                || app.api_token.is_empty()
                                || app.database_uuid.is_empty()
                            {
                                app.status_message =
                                    "Account ID, Database UUID, and API Token are required.".to_string();
                            } else {
                                let app_clone = Arc::clone(&self.app);
                                let ctx_clone = ctx.clone();

                                std::thread::spawn(move || {
                                    let rt = Runtime::new().expect("Failed to create Tokio runtime");

                                    rt.block_on(async move {
                                        let mut app = app_clone.lock().unwrap();

                                        match app.authenticate().await {
                                            Ok(_) => {
                                                app.is_authenticated = true;
                                                app.status_message = "Authentication successful.".to_string();
                                            }
                                            Err(err) => {
                                                app.status_message = format!("Authentication failed: {}", err);
                                            }
                                        }

                                        ctx_clone.request_repaint();
                                    });
                                });
                            }
                        },
                        AuthenticationMode::Wrangler => {
                            if app.database_uuid.is_empty() {
                                app.status_message = "Database UUID is required.".to_string();
                            } else {
                                let app_clone = Arc::clone(&self.app);
                                let ctx_clone = ctx.clone();

                                std::thread::spawn(move || {
                                  let rt = Runtime::new().expect("Failed to create Tokio runtime");

                                  rt.block_on(async move {
                                      let mut app = app_clone.lock().unwrap();

                                      match app.authenticate().await {
                                          Ok(_) => {
                                              app.is_authenticated = true;
                                              app.status_message = "Wrangler authentication successful.".to_string();
                                          }
                                          Err(err) => {
                                              app.status_message = format!("Authentication failed: {}", err);
                                          }
                                      }

                                      ctx_clone.request_repaint();
                                  });
                              });
                            }
                        },
                    }
                }

                if !app.status_message.is_empty() {
                    ui.label(&app.status_message);
                }

                return;
            }

            // Authenticated UI
            ui.horizontal(|ui| {
                if ui.button("Change Connection").clicked() {
                    app.is_authenticated = false;
                    app.account_id.clear();
                    app.api_token.clear();
                    app.database_uuid.clear();
                    app.database_name.clear();
                    app.database_context.clear();
                    app.status_message.clear();
                    app.query.clear();
                    app.results.clear();
                    app.history.clear();
                }
            });

            // Display status messages
            if !app.status_message.is_empty() {
                ui.label(&app.status_message);
                app.status_message.clear();
            }

            ui.separator();

            let context = app.database_context.clone();
            let mut local_context = false;
            let mut remote_context = false;
            let mut preview_context = false;

            ui.horizontal(|ui| {
                ui.label("Database Context:");
                
                // Local Context Checkbox
                if ui.checkbox(&mut local_context, "Use Local").clicked() {
                    if local_context {
                        // Uncheck the other checkboxes if "Use Local" is checked
                        remote_context = false;
                        preview_context = false;
                    }
                }

                // Remote Context Checkbox
                if ui.checkbox(&mut remote_context, "Use Remote").clicked() {
                    if remote_context {
                        // Uncheck the other checkboxes if "Use Remote" is checked
                        local_context = false;
                        preview_context = false;
                    }
                }

                // Preview Context Checkbox
                if ui.checkbox(&mut preview_context, "Use Preview").clicked() {
                    if preview_context {
                        // Uncheck the other checkboxes if "Use Preview" is checked
                        local_context = false;
                        remote_context = false;
                    }
                }
            });

            ui.separator();

            ui.label("Enter your SQL query:");
            ui.add(TextEdit::multiline(&mut app.query).desired_rows(5));

            if !app.is_executing && ui.button("Execute Query").clicked() {
                app.is_executing = true; // Prevent multiple queries

                let app_clone = Arc::clone(&self.app);
                let ctx_clone = ctx.clone();

                thread::spawn(move || {
                    let rt = Runtime::new().expect("Failed to create Tokio runtime");

                    rt.block_on(async move {
                        let mut app = app_clone.lock().unwrap();
                        match app.execute_query().await {
                            Ok(_) => {
                                app.status_message = "Query executed successfully.".to_string();
                            }
                            Err(err) => {
                                app.results = format!("Error: {}", err);
                            }
                        }

                        app.reset_after_query();
                        ctx_clone.request_repaint(); // Trigger a repaint to update the UI
                    });
                });
            }

            ui.separator();

            ui.label("Results:");
            ui.add(
                TextEdit::multiline(&mut app.results)
                    .desired_rows(10)
                    .font(egui::TextStyle::Monospace),
            );

            ui.separator();

            ui.label("Query History:");
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Collect history to avoid mutable and immutable borrow conflicts
                let query_history = app.history.clone();

                for past_query in query_history {
                    if ui.button(&past_query).clicked() {
                        app.query = past_query;
                    }
                }
            });
        });
    }
}

impl D1Gui {
    async fn authenticate(&mut self) -> Result<(), String> {
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
                        return Err("Authentication failed: API response indicated failure.".to_string());
                    }
                } else {
                    return Err("Malformed API response: missing 'success' field.".to_string());
                }

                Ok(())
            },
            AuthenticationMode::Wrangler => {
                let output = Command::new("wrangler")
                    .args(&["whoami"])
                    .output();

                match output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);

                        let combined_output = format!("{}\n{}", stdout, stderr);

                        if combined_output.contains("You are not authenticated") {
                            Err("Wrangler is not authenticated. Please run 'wrangler login'.".to_string())
                        } else if combined_output.contains("You are logged in") {
                            Ok(())
                        } else {
                            Err("Unable to determine Wrangler authentication status.".to_string())
                        }
                    },
                    Err(err) => {
                        Err(format!("Failed to execute 'wrangler whoami': {}", err))
                    }
                }
            },
        }
    }

    async fn execute_query(&mut self) -> Result<(), String> {
        if !self.is_authenticated {
            self.status_message = "Not authenticated. Please provide your API credentials.".to_string();
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
                      return Err("Authentication failed: API response indicated failure.".to_string());
                  }
              } else {
                  return Err("Malformed API response: missing 'success' field.".to_string());
              }
          
              Ok(())
            },
            AuthenticationMode::Wrangler => {
                if self.database_name.trim().is_empty() {
                    return Err("Database name is required.".to_string());
                }

                if self.database_uuid.trim().is_empty() {
                    return Err("Database UUID is required.".to_string());
                }

                let output = Command::new("wrangler")
                    .args(&[
                        "d1",
                        "execute",
                        self.database_name.trim(),
                        "--database",
                        self.database_uuid.trim(),
                        "--command",
                        self.query.trim(),
                        "--json",
                    ])
                    .output()
                    .map_err(|e| e.to_string())?;

                println!("Output: {:?}", output);

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(stderr.to_string());
                }

                let stdout = String::from_utf8_lossy(&output.stdout).to_string();

                // Parse the JSON output
                let value: Value = serde_json::from_str(&stdout).map_err(|e| e.to_string())?;

                // Extract the results
                if let Some(result) = value.get("result") {
                    self.results = serde_json::to_string_pretty(result).map_err(|e| e.to_string())?;
                } else {
                    self.results = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
                }

                // Save the query to history
                let trimmed_query = self.query.trim().to_string();
                if !trimmed_query.is_empty() {
                    if self.history.first() != Some(&trimmed_query) {
                        self.history.insert(0, trimmed_query);
                    }
                }

                Ok(())
            },
        }
    }

    fn reset_after_query(&mut self) {
        self.is_executing = false;
        self.status_message.clear();
    }
}
