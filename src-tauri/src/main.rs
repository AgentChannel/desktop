mod crypto;
mod mqtt;
mod mcp;

use mqtt::{MqttManager, Message};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChannelConfig {
    channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    subchannel: Option<String>,
    key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppConfig {
    name: String,
    channels: Vec<ChannelConfig>,
    #[serde(default)]
    muted: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Identity {
    #[serde(rename = "publicKeyPem")]
    public_key_pem: String,
    #[serde(rename = "privateKeyPem")]
    private_key_pem: String,
    fingerprint: String,
    #[serde(rename = "createdAt")]
    created_at: u64,
}

pub fn config_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".agentchannel")
}

pub fn load_config() -> AppConfig {
    let path = config_dir().join("config.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_else(|_| default_config())
    } else {
        default_config()
    }
}

const OFFICIAL_KEY: &str = "agentchannel-public-2026";

fn default_config() -> AppConfig {
    let config = AppConfig {
        name: whoami::username(),
        channels: vec![
            ChannelConfig { channel: "AgentChannel".into(), subchannel: None, key: OFFICIAL_KEY.into() },
            ChannelConfig { channel: "AgentChannel".into(), subchannel: Some("bugs".into()), key: OFFICIAL_KEY.into() },
            ChannelConfig { channel: "AgentChannel".into(), subchannel: Some("features".into()), key: OFFICIAL_KEY.into() },
        ],
        muted: vec![],
    };
    let dir = config_dir();
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(dir.join("config.json"), serde_json::to_string_pretty(&config).unwrap());
    config
}

pub fn load_or_create_identity() -> Identity {
    let dir = config_dir();
    let path = dir.join("identity.json");
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(id) = serde_json::from_str::<Identity>(&data) {
            return id;
        }
    }
    use ed25519_dalek::SigningKey;
    use sha2::{Sha256, Digest};
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let pub_der = {
        let prefix: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        let mut spki = Vec::with_capacity(44);
        spki.extend_from_slice(&prefix);
        spki.extend_from_slice(verifying_key.as_bytes());
        spki
    };
    let priv_der = {
        let prefix: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&prefix);
        pkcs8.extend_from_slice(signing_key.as_bytes());
        pkcs8
    };

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let pub_pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", b64.encode(&pub_der));
    let priv_pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", b64.encode(&priv_der));

    let fingerprint = {
        let mut hasher = Sha256::new();
        hasher.update(pub_pem.as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..6])
    };

    let identity = Identity {
        public_key_pem: pub_pem,
        private_key_pem: priv_pem,
        fingerprint,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    };

    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(&path, serde_json::to_string_pretty(&identity).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    identity
}

fn notifications_file() -> PathBuf {
    config_dir().join("notifications.json")
}

// ── Load History ────────────────────────────────

pub async fn load_history(mqtt: &MqttManager, channels: &[ChannelConfig]) {
    let client = reqwest::Client::new();

    // Fetch all channel histories in parallel
    let fetches: Vec<_> = channels.iter().map(|ch| {
        let client = client.clone();
        let ch = ch.clone();
        async move {
            let key = if let Some(sub) = &ch.subchannel {
                crypto::derive_sub_key(&ch.key, sub)
            } else {
                crypto::derive_key(&ch.key)
            };
            let hash = if let Some(sub) = &ch.subchannel {
                crypto::hash_sub(&ch.key, sub)
            } else {
                crypto::hash_room(&ch.key)
            };
            let url = format!(
                "https://api.agentchannel.workers.dev/messages?channel_hash={}&since=0&limit=100",
                hash
            );

            let mut decoded: Vec<Message> = Vec::new();
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(rows) = resp.json::<Vec<serde_json::Value>>().await {
                    for row in rows {
                        if let Some(ct) = row.get("ciphertext").and_then(|v| v.as_str()) {
                            if let Ok(enc) = serde_json::from_str::<crypto::EncryptedPayload>(ct) {
                                if let Ok(dec) = crypto::decrypt(&enc, &key) {
                                    if let Ok(mut msg) = serde_json::from_str::<Message>(&dec) {
                                        msg.channel = ch.channel.clone();
                                        msg.subchannel = ch.subchannel.clone();
                                        if msg.msg_type.as_deref() != Some("channel_meta") {
                                            decoded.push(msg);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            decoded
        }
    }).collect();

    let results = futures::future::join_all(fetches).await;

    let mut msgs = mqtt.messages.lock().await;
    for batch in results {
        for msg in batch {
            if !msgs.iter().any(|m| m.id == msg.id) {
                msgs.push(msg);
            }
        }
    }
    msgs.sort_by_key(|m| m.timestamp);
}

// ══════════════════════════════════════════════════
// Main — dual mode: --mcp for MCP server, default for UI
// ══════════════════════════════════════════════════

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--mcp") {
        // MCP mode: stdio server, no UI
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            if let Err(e) = mcp::run_mcp().await {
                eprintln!("MCP server error: {}", e);
                std::process::exit(1);
            }
        });
        return;
    }

    // UI mode: Tauri desktop app
    run_ui();
}

/// Register agentchannel MCP server in Claude Desktop config so Claude Code
/// discovers it automatically. Runs once on first launch; updates the binary
/// path on subsequent launches if the app was moved.
fn register_mcp_in_claude_config() {
    let Some(home) = dirs::home_dir() else { return };

    // Determine the binary path based on platform
    let binary_path = {
        #[cfg(target_os = "macos")]
        {
            // On macOS, the binary is inside the .app bundle
            // Use current_exe to find where we're actually running from
            std::env::current_exe()
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        }
        #[cfg(not(target_os = "macos"))]
        {
            std::env::current_exe()
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        }
    };
    let Some(binary_path) = binary_path else { return };

    // Claude Desktop config path
    #[cfg(target_os = "macos")]
    let config_path = home.join("Library/Application Support/Claude/claude_desktop_config.json");
    #[cfg(target_os = "linux")]
    let config_path = home.join(".config/Claude/claude_desktop_config.json");
    #[cfg(target_os = "windows")]
    let config_path = home.join("AppData/Roaming/Claude/claude_desktop_config.json");

    // Read existing config or start fresh
    let mut config: serde_json::Value = if let Ok(data) = fs::read_to_string(&config_path) {
        serde_json::from_str(&data).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let servers = config
        .as_object_mut()
        .and_then(|o| {
            o.entry("mcpServers")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
        });
    let Some(servers) = servers else { return };

    // Check if already registered with the same path
    if let Some(existing) = servers.get("agentchannel") {
        if existing.get("command").and_then(|v| v.as_str()) == Some(&binary_path) {
            return; // Already registered with correct path
        }
    }

    // Register (or update path if app was moved)
    servers.insert("agentchannel".to_string(), serde_json::json!({
        "command": binary_path,
        "args": ["--mcp"]
    }));

    if let Some(parent) = config_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&config) {
        let _ = fs::write(&config_path, json);
        eprintln!("Registered MCP server in Claude Desktop config");
    }
}

fn run_ui() {
    use tauri::Manager;
    use tauri_plugin_updater::UpdaterExt;

    let config = load_config();
    let identity = Some(load_or_create_identity());
    let mqtt_manager = MqttManager::new(config.name.clone());

    struct AppState {
        mqtt: Arc<Mutex<MqttManager>>,
        config: Arc<Mutex<AppConfig>>,
        identity: Arc<Mutex<Option<Identity>>>,
    }

    // ── Tauri Commands ──────────────────────────────

    #[tauri::command]
    async fn get_config(state: tauri::State<'_, AppState>) -> Result<AppConfig, String> {
        Ok(state.config.lock().await.clone())
    }

    #[tauri::command]
    async fn get_identity(state: tauri::State<'_, AppState>) -> Result<Option<Identity>, String> {
        Ok(state.identity.lock().await.clone())
    }

    #[tauri::command]
    async fn list_channels(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
        let config = state.config.lock().await;
        Ok(config.channels.iter().map(|c| {
            if let Some(sub) = &c.subchannel {
                format!("#{} ##{}", c.channel, sub)
            } else {
                format!("#{}", c.channel)
            }
        }).collect())
    }

    #[tauri::command]
    async fn send_message(
        state: tauri::State<'_, AppState>,
        channel: String,
        message: String,
        subchannel: Option<String>,
        subject: Option<String>,
        tags: Option<Vec<String>>,
    ) -> Result<Message, String> {
        let mqtt = state.mqtt.lock().await;
        let identity = state.identity.lock().await;
        let fp = identity.as_ref().map(|i| i.fingerprint.clone()).unwrap_or_default();
        let target = if let Some(sub) = subchannel {
            format!("{}/{}", channel, sub)
        } else {
            channel
        };
        mqtt.send_message(&target, &message, subject.as_deref(), tags, &fp).await
    }

    #[tauri::command]
    async fn read_messages(
        state: tauri::State<'_, AppState>,
        channel: Option<String>,
        limit: Option<usize>,
    ) -> Result<Vec<Message>, String> {
        let mqtt = state.mqtt.lock().await;
        Ok(mqtt.get_messages(channel.as_deref(), limit.unwrap_or(200)).await)
    }

    #[tauri::command]
    async fn unread_count(state: tauri::State<'_, AppState>) -> Result<usize, String> {
        let mqtt = state.mqtt.lock().await;
        Ok(mqtt.get_unread_count().await)
    }

    #[tauri::command]
    fn get_version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    #[tauri::command]
    fn get_pending_notifications() -> Result<Vec<serde_json::Value>, String> {
        let path = notifications_file();
        if !path.exists() {
            return Ok(vec![]);
        }
        let data = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let notifications: Vec<serde_json::Value> =
            serde_json::from_str(&data).unwrap_or_default();
        let _ = fs::write(&path, "[]");
        Ok(notifications)
    }

    #[tauri::command]
    async fn check_for_update(app: tauri::AppHandle) -> Result<Option<String>, String> {
        let updater = app.updater().map_err(|e| e.to_string())?;
        match updater.check().await {
            Ok(Some(update)) => Ok(Some(update.version.clone())),
            Ok(None) => Ok(None),
            Err(e) => {
                eprintln!("Update check failed: {}", e);
                Ok(None)
            }
        }
    }

    #[tauri::command]
    async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
        let updater = app.updater().map_err(|e| e.to_string())?;
        match updater.check().await {
            Ok(Some(update)) => {
                let mut downloaded = 0;
                update.download_and_install(|chunk, _total| {
                    downloaded += chunk;
                    eprintln!("Downloaded {} bytes", downloaded);
                }, || {
                    eprintln!("Download complete, installing...");
                }).await.map_err(|e| e.to_string())?;
                app.restart();
            }
            Ok(None) => Err("No update available".to_string()),
            Err(e) => Err(e.to_string()),
        }
    }

    // ── Build Tauri App ──────────────────────────────

    let app_state = AppState {
        mqtt: Arc::new(Mutex::new(mqtt_manager)),
        config: Arc::new(Mutex::new(config.clone())),
        identity: Arc::new(Mutex::new(identity)),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_config,
            get_identity,
            list_channels,
            send_message,
            read_messages,
            unread_count,
            get_version,
            get_pending_notifications,
            check_for_update,
            install_update,
        ])
        .setup(move |app| {
            let version = env!("CARGO_PKG_VERSION");
            eprintln!("AgentChannel Desktop v{}", version);

            // Auto-register MCP server in Claude Desktop config (once)
            register_mcp_in_claude_config();

            let app_handle = app.handle().clone();
            let config_clone = config.clone();

            // MQTT connect first, then load history in parallel (non-blocking)
            tauri::async_runtime::spawn(async move {
                let state: tauri::State<AppState> = app_handle.state();
                let mut mqtt = state.mqtt.lock().await;
                for ch in &config_clone.channels {
                    mqtt.add_channel(&ch.channel, ch.subchannel.as_deref(), &ch.key).await;
                }

                // UI mode: callback emits to Tauri frontend + native notification
                let handle = app_handle.clone();
                let notif_handle = app_handle.clone();
                let cfg_name = state.config.lock().await.name.clone();
                let callback: mqtt::MessageCallback = Arc::new(move |msg: Message| {
                    use tauri::Emitter;
                    let _ = handle.emit("new_message", &msg);

                    if msg.sender != cfg_name {
                        let label = if let Some(ref sub) = msg.subchannel {
                            format!("#{} ##{}", msg.channel, sub)
                        } else {
                            format!("#{}", msg.channel)
                        };
                        let title = format!("{} @{}", label, msg.sender);
                        let body = msg.subject.as_deref()
                            .unwrap_or_else(|| &msg.content)
                            .chars().take(100).collect::<String>();
                        // macOS: osascript works reliably even for unsigned apps
                        #[cfg(target_os = "macos")]
                        {
                            let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
                            let script = format!(
                                "display notification \"{}\" with title \"{}\"",
                                escape(&body),
                                escape(&title)
                            );
                            let _ = std::process::Command::new("osascript")
                                .arg("-e")
                                .arg(&script)
                                .spawn();
                        }
                        // Other platforms: use tauri notification plugin
                        #[cfg(not(target_os = "macos"))]
                        {
                            use tauri_plugin_notification::NotificationExt;
                            let _ = notif_handle.notification()
                                .builder()
                                .title(&title)
                                .body(&body)
                                .show();
                        }
                    }
                }) as mqtt::MessageCallback;

                // Connect MQTT — fast path, live messages start flowing
                mqtt.connect(Some(callback)).await;
                eprintln!("MQTT connected, {} channels", config_clone.channels.len());
                drop(mqtt);

                // Load history in parallel, emit each message as it's loaded
                let history_handle = app_handle.clone();
                let channels_for_history = config_clone.channels.clone();
                tauri::async_runtime::spawn(async move {
                    let state: tauri::State<AppState> = history_handle.state();
                    let mqtt = state.mqtt.lock().await;
                    load_history(&*mqtt, &channels_for_history).await;
                    // Emit all history messages to frontend
                    let msgs = mqtt.messages.lock().await.clone();
                    use tauri::Emitter;
                    for msg in msgs {
                        let _ = history_handle.emit("new_message", &msg);
                    }
                    eprintln!("History loaded");
                });
            });

            // Auto-check for updates after 3 seconds
            let update_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                use tauri_plugin_updater::UpdaterExt;
                use tauri::Emitter;
                match update_handle.updater() {
                    Ok(updater) => match updater.check().await {
                        Ok(Some(update)) => {
                            eprintln!("Update available: v{}", update.version);
                            let _ = update_handle.emit("update_available", &update.version);
                        }
                        Ok(None) => eprintln!("App is up to date"),
                        Err(e) => eprintln!("Update check failed: {}", e),
                    },
                    Err(e) => eprintln!("Updater init failed: {}", e),
                }
            });

            // System tray
            use tauri::tray::TrayIconBuilder;
            use tauri::menu::{Menu, MenuItem};

            let show_i = MenuItem::with_id(app, "show", "Show AgentChannel", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

            TrayIconBuilder::with_id("ac-tray")
                .icon(tauri::image::Image::from_bytes(include_bytes!("../icons/icon.png")).expect("tray icon"))
                .icon_as_template(true)
                .tooltip("AgentChannel")
                .menu(&menu)
                .on_menu_event(|app, event| {
                    match event.id().as_ref() {
                        "quit" => std::process::exit(0),
                        "show" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click { .. } = event {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
