use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use tokio::process::Command;
use zbus::zvariant::Value;
use zbus::Connection;

use crate::state::PendingDecision;

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
}
