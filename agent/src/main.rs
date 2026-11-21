mod notify;
mod sni;
mod state;

use std::sync::{Arc, Mutex};

use tokio::process::Command;
use zbus::object_server::SignalEmitter;
use zbus::{fdo, interface, Connection};

use crate::notify::{send_dbus_notification, spawn_action_listener, NotificationTracker};
use crate::sni::{emit_sni_update, register_with_watcher, StatusNotifierItem};
use crate::state::{PendingDecision, StateStore};

struct SessionAgent {
    store: StateStore,
    conn: Connection,
    tracker: Arc<Mutex<NotificationTracker>>,
}

#[interface(name = "org.mintsecurity.SessionAgent")]
impl SessionAgent {
    async fn ping(&self) -> &str {
        "pong"
    }

    async fn get_pending_count(&self) -> fdo::Result<u32> {
        self.store
            .open_count()
            .map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    async fn list_pending(&self) -> fdo::Result<String> {
        let items = self
            .store
            .list_open()
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        serde_json::to_string(&items).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    async fn notify_alert(
        &self,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
        payload_json: &str,
    ) -> fdo::Result<String> {
        let decision: PendingDecision = serde_json::from_str(payload_json)
            .map_err(|e| fdo::Error::InvalidArgs(format!("JSON inválido: {e}")))?;
        let saved = self
            .store
            .add_or_group(decision, true)
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        let count = self
            .store
            .open_count()
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;

        let _ = send_dbus_notification(&self.conn, &self.tracker, &saved).await;
        emit_sni_update(&self.conn, count).await;
        let _ = Self::pending_changed(&ctxt, count).await;
        let _ = Self::alert_received(&ctxt, &saved.pending_id).await;
        Ok(saved.pending_id)
    }

    async fn resolve_pending(
        &self,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
        pending_id: &str,
        resolution: &str,
    ) -> fdo::Result<bool> {
        let changed = self
            .store
            .resolve(pending_id, resolution)
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        if changed {
            let count = self
                .store
                .open_count()
                .map_err(|e| fdo::Error::Failed(e.to_string()))?;
            emit_sni_update(&self.conn, count).await;
            let _ = Self::pending_changed(&ctxt, count).await;
        }
        Ok(changed)
    }

    async fn open_panel(&self, page: &str) -> fdo::Result<bool> {
        if !matches!(
            page,
            "" | "home" | "scans" | "protections" | "recovery" | "activity" | "settings"
        ) {
            return Err(fdo::Error::InvalidArgs(format!("Página inválida: {page}")));
        }
        let mut cmd = Command::new("mint-security-suite");
        if !page.is_empty() {
            cmd.args(["--page", page]);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| fdo::Error::Failed(format!("Falha ao abrir painel: {e}")))?;
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        Ok(true)
    }

    async fn open_pending_dialog(&self, pending_id: &str) -> fdo::Result<bool> {
        if !is_valid_pending_id(pending_id) {
            return Err(fdo::Error::InvalidArgs(
                "Identificador de pendência inválido".to_string(),
            ));
        }
        let mut child = Command::new("mint-security-dialog")
            .args(["--pending-id", pending_id])
            .spawn()
            .map_err(|e| fdo::Error::Failed(format!("Falha ao abrir diálogo: {e}")))?;
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        Ok(true)
    }

    #[zbus(signal)]
    async fn pending_changed(ctxt: &SignalEmitter<'_>, count: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn alert_received(ctxt: &SignalEmitter<'_>, pending_id: &str) -> zbus::Result<()>;
}

pub fn is_valid_pending_id(pending_id: &str) -> bool {
    !pending_id.is_empty()
        && pending_id.len() <= 128
        && !pending_id.starts_with('-')
        && pending_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = StateStore::new(StateStore::default_path());
    let initial_count = store.open_count().unwrap_or(0);
    let tracker = Arc::new(Mutex::new(NotificationTracker::default()));

    let conn = Connection::session().await?;
    let sni = StatusNotifierItem::new(initial_count);
    conn.object_server()
        .at("/StatusNotifierItem", sni)
        .await?;

    let agent = SessionAgent {
        store,
        conn: conn.clone(),
        tracker: tracker.clone(),
    };
    conn.object_server()
        .at("/org/mintsecurity/SessionAgent", agent)
        .await?;

    conn.request_name("org.mintsecurity.SessionAgent").await?;
    register_with_watcher(&conn).await;

    let action_conn = conn.clone();
    let action_tracker = tracker.clone();
    tokio::spawn(async move {
        spawn_action_listener(action_conn, action_tracker).await;
    });

    tokio::signal::ctrl_c().await?;
    Ok(())
}
