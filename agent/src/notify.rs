use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde_json::Value as JsonValue;
use tokio::process::Command;
use zbus::zvariant::Value;
use zbus::Connection;

use crate::state::PendingDecision;

pub fn settings_config_path() -> PathBuf {
    if let Ok(xdg_cfg) = std::env::var("XDG_CONFIG_HOME") {
        let trimmed = xdg_cfg.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed)
                .join("mint-security-suite")
                .join("settings.json");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed)
                .join(".config/mint-security-suite/settings.json");
        }
    }
    PathBuf::from("/nonexistent-mintsec-settings.json")
}

pub fn is_popup_suppressed_from_path(settings_path: &Path, decision: &PendingDecision) -> bool {
    if decision.kind == "paused_app" {
        return false;
    }
    let meta = match fs::symlink_metadata(settings_path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 262_144 {
        return false;
    }
    let raw = match fs::read_to_string(settings_path) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let parsed: JsonValue = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let dnd = parsed
        .get("do_not_disturb")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let game_mode = parsed
        .get("game_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if dnd || game_mode {
        return true;
    }
    let paused = parsed
        .get("protection_paused")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !paused {
        return false;
    }
    let mode = parsed
        .get("protection_pause_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    if mode == "timed" {
        if let Some(until_str) = parsed.get("protection_paused_until").and_then(|v| v.as_str()) {
            if let Ok(until_dt) = DateTime::parse_from_rfc3339(until_str) {
                return Utc::now() < until_dt.with_timezone(&Utc);
            }
        }
        return false;
    }
    matches!(mode, "until_restart" | "indefinite")
}

pub fn is_popup_suppressed(decision: &PendingDecision) -> bool {
    is_popup_suppressed_from_path(&settings_config_path(), decision)
}

#[derive(Debug, Default)]
pub struct NotificationTracker {
    group_to_notif_id: HashMap<String, u32>,
    notif_id_to_pending: HashMap<u32, String>,
}

impl NotificationTracker {
    pub fn group_key(decision: &PendingDecision) -> String {
        format!(
            "{}:{}:{}",
            decision.module_id, decision.kind, decision.app_name
        )
    }

    pub fn existing_id(&self, decision: &PendingDecision) -> u32 {
        let key = Self::group_key(decision);
        *self.group_to_notif_id.get(&key).unwrap_or(&0)
    }

    pub fn record_sent(&mut self, decision: &PendingDecision, notif_id: u32) {
        if notif_id == 0 {
            return;
        }
        if self.notif_id_to_pending.len() >= 256 {
            self.notif_id_to_pending.clear();
            self.group_to_notif_id.clear();
        }
        let key = Self::group_key(decision);
        self.group_to_notif_id.insert(key, notif_id);
        self.notif_id_to_pending
            .insert(notif_id, decision.pending_id.clone());
    }

    pub fn pending_for_notif(&self, notif_id: u32) -> Option<String> {
        self.notif_id_to_pending.get(&notif_id).cloned()
    }
}

pub async fn send_dbus_notification(
    conn: &Connection,
    tracker: &Arc<Mutex<NotificationTracker>>,
    decision: &PendingDecision,
) -> Option<u32> {
    if is_popup_suppressed(decision) {
        return None;
    }
    let replaces_id = tracker
        .lock()
        .map(|t| t.existing_id(decision))
        .unwrap_or(0);

    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
    )
    .await
    .ok()?;

    let action_label = if decision.kind == "paused_app" {
        "Revisar aplicativo"
    } else {
        "Revisar"
    };
    let actions: Vec<&str> = vec!["review", action_label];
    let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
    let urgency: u8 = if decision.kind == "paused_app" { 2 } else { 1 };
    hints.insert("urgency", Value::U8(urgency));

    let body = if decision.occurrences > 1 {
        format!(
            "{}\nEvidência: {}\n({} ocorrências agrupadas)",
            decision.summary, decision.evidence, decision.occurrences
        )
    } else {
        format!("{}\nEvidência: {}", decision.summary, decision.evidence)
    };

    let notif_id: u32 = proxy
        .call(
            "Notify",
            &(
                "NodusGuard",
                replaces_id,
                "security-medium",
                decision.title.as_str(),
                body.as_str(),
                actions,
                hints,
                0i32,
            ),
        )
        .await
        .ok()?;

    if let Ok(mut guard) = tracker.lock() {
        guard.record_sent(decision, notif_id);
    }
    Some(notif_id)
}

pub async fn spawn_action_listener(conn: Connection, tracker: Arc<Mutex<NotificationTracker>>) {
    let Ok(proxy) = zbus::Proxy::new(
        &conn,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
    )
    .await
    else {
        return;
    };

    let Ok(mut stream) = proxy.receive_signal("ActionInvoked").await else {
        return;
    };

    while let Some(msg) = stream.next().await {
        let Ok((notif_id, action_key)) = msg.body().deserialize::<(u32, String)>() else {
            continue;
        };
        if action_key == "review" {
            let pending_id = tracker
                .lock()
                .ok()
                .and_then(|t| t.pending_for_notif(notif_id));
            if let Some(pid) = pending_id {
                let valid = !pid.is_empty()
                    && pid.len() <= 128
                    && !pid.starts_with('-')
                    && pid
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
                if valid {
                    if let Ok(mut child) = Command::new("mint-security-dialog")
                        .args(["--pending-id", &pid])
                        .spawn()
                    {
                        tokio::spawn(async move {
                            let _ = child.wait().await;
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_replaces_id_per_app_group() {
        let mut tracker = NotificationTracker::default();
        let d = PendingDecision {
            pending_id: "p-1".into(),
            kind: "paused_app".into(),
            module_id: "recovery".into(),
            app_name: "app-x".into(),
            title: "App pausado".into(),
            summary: "Teste".into(),
            evidence: "Canário".into(),
            created_at: "2026-11-21T10:00:00-03:00".into(),
            status: "open".into(),
            fan_q_overflow: false,
            affected_paths: vec![],
            actions: vec![],
            incident_id: None,
            occurrences: 1,
            metadata: HashMap::new(),
        };
        assert_eq!(tracker.existing_id(&d), 0);
        tracker.record_sent(&d, 42);
        assert_eq!(tracker.existing_id(&d), 42);
        assert_eq!(tracker.pending_for_notif(42).as_deref(), Some("p-1"));
    }

    #[test]
    fn suppresses_non_critical_popups_on_dnd_game_and_pause() {
        let mut base = PendingDecision {
            pending_id: "p-2".into(),
            kind: "quarantine_detection".into(),
            module_id: "antimalware".into(),
            app_name: "eicar".into(),
            title: "Detection".into(),
            summary: "Summary".into(),
            evidence: "EICAR".into(),
            created_at: "2026-11-22T10:00:00-03:00".into(),
            status: "open".into(),
            fan_q_overflow: false,
            affected_paths: vec![],
            actions: vec![],
            incident_id: None,
            occurrences: 1,
            metadata: HashMap::new(),
        };

        let tmp_path =
            std::env::temp_dir().join(format!("nodusguard-notify-test-{}.json", uuid::Uuid::new_v4()));
        fs::write(
            &tmp_path,
            r#"{"do_not_disturb": true, "game_mode": false, "protection_paused": false}"#,
        )
        .unwrap();
        assert!(is_popup_suppressed_from_path(&tmp_path, &base));

        // Critical paused_app alert bypasses suppression
        base.kind = "paused_app".into();
        assert!(!is_popup_suppressed_from_path(&tmp_path, &base));

        // Protection paused until restart suppresses regular popups
        base.kind = "quarantine_detection".into();
        fs::write(
            &tmp_path,
            r#"{"do_not_disturb": false, "game_mode": false, "protection_paused": true, "protection_pause_mode": "until_restart"}"#,
        )
        .unwrap();
        assert!(is_popup_suppressed_from_path(&tmp_path, &base));

        let _ = fs::remove_file(&tmp_path);
    }
}
