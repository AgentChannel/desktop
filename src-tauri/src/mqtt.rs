/// MQTT persistent connection for AgentChannel
/// Decoupled from Tauri — uses callback for message delivery.

use crate::crypto;
use rumqttc::{MqttOptions, AsyncClient, QoS, Event, Packet, Transport, TlsConfiguration};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::fs;

const DEFAULT_BROKER: &str = "broker.emqx.io";
const DEFAULT_PORT: u16 = 8883;

/// Callback invoked when a new message arrives
pub type MessageCallback = Arc<dyn Fn(Message) + Send + Sync>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    pub id: String,
    pub channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subchannel: Option<String>,
    pub sender: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    pub timestamp: u64,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub msg_type: Option<String>,
    #[serde(rename = "senderKey", skip_serializing_if = "Option::is_none")]
    pub sender_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(rename = "replyTo", skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ChannelState {
    pub channel: String,
    pub subchannel: Option<String>,
    pub key: Vec<u8>,
    pub hash: String,
    pub raw_key: String,
}

pub struct MqttManager {
    client: Option<AsyncClient>,
    pub channels: Arc<Mutex<Vec<ChannelState>>>,
    pub messages: Arc<Mutex<Vec<Message>>>,
    pub name: String,
    last_read: Arc<Mutex<u64>>,
}

impl MqttManager {
    pub fn new(name: String) -> Self {
        Self {
            client: None,
            channels: Arc::new(Mutex::new(Vec::new())),
            messages: Arc::new(Mutex::new(Vec::new())),
            name,
            last_read: Arc::new(Mutex::new(0)),
        }
    }

    fn msg_topic(hash: &str) -> String {
        format!("ac/1/{}", hash)
    }

    fn pres_topic(hash: &str) -> String {
        format!("ac/1/{}/p", hash)
    }

    pub async fn add_channel(&self, channel: &str, subchannel: Option<&str>, raw_key: &str) {
        let key = if let Some(sub) = subchannel {
            crypto::derive_sub_key(raw_key, sub)
        } else {
            crypto::derive_key(raw_key)
        };
        let hash = if let Some(sub) = subchannel {
            crypto::hash_sub(raw_key, sub)
        } else {
            crypto::hash_room(raw_key)
        };

        let state = ChannelState {
            channel: channel.to_string(),
            subchannel: subchannel.map(|s| s.to_string()),
            key,
            hash: hash.clone(),
            raw_key: raw_key.to_string(),
        };

        self.channels.lock().await.push(state);

        // Subscribe if connected
        if let Some(client) = &self.client {
            let _ = client.subscribe(Self::msg_topic(&hash), QoS::AtLeastOnce).await;
            let _ = client.subscribe(Self::pres_topic(&hash), QoS::AtLeastOnce).await;
        }
    }

    /// Connect to MQTT broker. on_message callback is invoked for each new message.
    /// Pass None for no callback (MCP mode stores messages in self.messages only).
    pub async fn connect(&mut self, on_message: Option<MessageCallback>) {
        let client_id = format!("ach_{}", rand::random::<u32>());
        let mut opts = MqttOptions::new(&client_id, DEFAULT_BROKER, DEFAULT_PORT);
        opts.set_keep_alive(std::time::Duration::from_secs(60));
        opts.set_clean_session(true);
        // Load default root certs for rustls
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        opts.set_transport(Transport::Tls(TlsConfiguration::Rustls(Arc::new(tls_config))));

        let (client, mut eventloop) = AsyncClient::new(opts, 100);
        self.client = Some(client.clone());

        // Subscribe to all channels
        let channels = self.channels.lock().await.clone();
        for ch in &channels {
            let _ = client.subscribe(Self::msg_topic(&ch.hash), QoS::AtLeastOnce).await;
            let _ = client.subscribe(Self::pres_topic(&ch.hash), QoS::AtLeastOnce).await;
        }

        // Announce presence
        let name = self.name.clone();
        for ch in &channels {
            let payload = serde_json::json!({"name": name, "status": "online"}).to_string();
            let _ = client.publish(Self::pres_topic(&ch.hash), QoS::AtLeastOnce, false, payload.as_bytes()).await;
        }

        let channels_arc = self.channels.clone();
        let messages_arc = self.messages.clone();
        let my_name = self.name.clone();

        // Event loop in background
        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(Packet::Publish(publish))) => {
                        let topic = publish.topic.clone();
                        let payload = publish.payload.to_vec();

                        let channels = channels_arc.lock().await;
                        for ch in channels.iter() {
                            if topic == Self::msg_topic(&ch.hash) {
                                if let Ok(payload_str) = String::from_utf8(payload.clone()) {
                                    if let Ok(encrypted) = serde_json::from_str::<crypto::EncryptedPayload>(&payload_str) {
                                        if let Ok(decrypted) = crypto::decrypt(&encrypted, &ch.key) {
                                            if let Ok(mut msg) = serde_json::from_str::<Message>(&decrypted) {
                                                msg.channel = ch.channel.clone();
                                                msg.subchannel = ch.subchannel.clone();

                                                if msg.msg_type.as_deref() == Some("channel_meta") {
                                                    continue;
                                                }

                                                // Invoke callback (UI emit, etc.)
                                                if let Some(ref cb) = on_message {
                                                    cb(msg.clone());
                                                }

                                                // Write @mention notifications to file
                                                if msg.content.contains(&format!("@{}", my_name)) {
                                                    Self::write_notification(&msg);
                                                }

                                                // Store
                                                let mut msgs = messages_arc.lock().await;
                                                msgs.push(msg);
                                                if msgs.len() > 500 {
                                                    msgs.remove(0);
                                                }
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("[MQTT] Error: {:?}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    }
                }
            }
        });
    }

    fn write_notification(msg: &Message) {
        let notif_path = dirs::home_dir()
            .unwrap_or_default()
            .join(".agentchannel")
            .join("notifications.json");
        let mut notifs: Vec<serde_json::Value> =
            fs::read_to_string(&notif_path)
                .ok()
                .and_then(|d| serde_json::from_str(&d).ok())
                .unwrap_or_default();
        notifs.push(serde_json::json!({
            "id": msg.id,
            "channel": msg.channel,
            "subchannel": msg.subchannel,
            "sender": msg.sender,
            "content": msg.content,
            "subject": msg.subject,
            "timestamp": msg.timestamp,
        }));
        if notifs.len() > 50 {
            notifs = notifs.split_off(notifs.len() - 50);
        }
        let _ = fs::write(&notif_path, serde_json::to_string(&notifs).unwrap_or_default());
    }

    pub async fn send_message(&self, channel_id: &str, content: &str, subject: Option<&str>, tags: Option<Vec<String>>, sender_key: &str) -> Result<Message, String> {
        let client = self.client.as_ref().ok_or("Not connected")?;
        let channels = self.channels.lock().await;

        let target = channels.iter().find(|ch| {
            if let Some(sub) = &ch.subchannel {
                format!("{}/{}", ch.channel, sub) == channel_id
            } else {
                ch.channel == channel_id
            }
        }).ok_or(format!("Channel {} not found", channel_id))?;

        let msg = Message {
            id: format!("{:016x}", rand::random::<u64>()),
            channel: target.channel.clone(),
            subchannel: target.subchannel.clone(),
            sender: self.name.clone(),
            content: content.to_string(),
            subject: subject.map(|s| s.to_string()),
            tags,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            msg_type: Some("chat".to_string()),
            sender_key: Some(sender_key.to_string()),
            signature: None,
            reply_to: None,
        };

        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
        let encrypted = crypto::encrypt(&json, &target.key);
        let payload = serde_json::to_string(&encrypted).map_err(|e| e.to_string())?;

        client.publish(
            Self::msg_topic(&target.hash),
            QoS::AtLeastOnce,
            false,
            payload.as_bytes(),
        ).await.map_err(|e| e.to_string())?;

        // Persist to cloud (best-effort)
        let api_url = "https://api.agentchannel.workers.dev/messages".to_string();
        let body = serde_json::json!({
            "id": msg.id,
            "channel_hash": target.hash,
            "ciphertext": payload,
            "timestamp": msg.timestamp,
        });
        tokio::spawn(async move {
            let _ = reqwest::Client::new().post(&api_url).json(&body).send().await;
        });

        Ok(msg)
    }

    pub async fn get_messages(&self, channel: Option<&str>, limit: usize) -> Vec<Message> {
        let msgs = self.messages.lock().await;
        let filtered: Vec<&Message> = if let Some(ch) = channel {
            msgs.iter().filter(|m| {
                if ch.contains('/') {
                    let parts: Vec<&str> = ch.splitn(2, '/').collect();
                    m.channel == parts[0] && m.subchannel.as_deref() == Some(parts[1])
                } else {
                    m.channel == ch
                }
            }).collect()
        } else {
            msgs.iter().collect()
        };

        filtered.iter().rev().take(limit).rev().cloned().cloned().collect()
    }

    pub async fn get_message_by_id(&self, id: &str) -> Option<Message> {
        let msgs = self.messages.lock().await;
        msgs.iter().find(|m| m.id == id).cloned()
    }

    pub async fn get_unread_count(&self) -> usize {
        let last_read = *self.last_read.lock().await;
        let msgs = self.messages.lock().await;
        msgs.iter().filter(|m| m.timestamp > last_read).count()
    }

    pub async fn mark_as_read(&self) {
        let msgs = self.messages.lock().await;
        if let Some(last) = msgs.last() {
            *self.last_read.lock().await = last.timestamp;
        }
    }
}
