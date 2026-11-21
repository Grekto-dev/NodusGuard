use std::sync::{Arc, Mutex};

use tokio::process::Command;
use zbus::object_server::SignalEmitter;
use zbus::{interface, zvariant::ObjectPath, Connection};

pub type SniTooltip = (String, Vec<(i32, i32, Vec<u8>)>, String, String);

#[derive(Debug, Clone)]
pub struct SniState {
    pub pending_count: u32,
}

pub struct StatusNotifierItem {
    pub state: Arc<Mutex<SniState>>,
}

impl StatusNotifierItem {
    pub fn new(pending_count: u32) -> Self {
        Self {
            state: Arc::new(Mutex::new(SniState { pending_count })),
        }
    }

    pub fn current_status(&self) -> String {
        let count = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending_count;
        if count > 0 {
            "NeedsAttention".to_string()
        } else {
            "Active".to_string()
        }
    }

    pub fn current_icon(&self) -> String {
        let count = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending_count;
        if count > 0 {
            "security-medium".to_string()
        } else {
            "security-high".to_string()
        }
    }

    pub fn current_tooltip(&self) -> SniTooltip {
        let count = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending_count;
        let icon = if count > 0 {
            "security-medium".to_string()
        } else {
            "security-high".to_string()
        };
        let desc = if count > 0 {
            format!("{count} pendência(s) aguardando revisão.")
        } else {
            "Nenhuma pendência em aberto.".to_string()
        };
        (icon, Vec::new(), "NodusGuard".to_string(), desc)
    }

    fn spawn_panel(&self) {
        let has_pending = self
            .state
            .lock()
            .map(|g| g.pending_count > 0)
            .unwrap_or(false);
        let mut cmd = Command::new("mint-security-suite");
        if has_pending {
            cmd.args(["--page", "activity", "--tab", "pending"]);
        }
        if let Ok(mut child) = cmd.spawn() {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
}

#[interface(name = "org.kde.StatusNotifierItem")]
impl StatusNotifierItem {
    #[zbus(property)]
    async fn category(&self) -> &str {
        "SystemServices"
    }

    #[zbus(property)]
    async fn id(&self) -> &str {
        "mint-security-suite"
    }

    #[zbus(property)]
    async fn title(&self) -> &str {
        "NodusGuard"
    }

    #[zbus(property)]
    async fn status(&self) -> String {
        self.current_status()
    }

    #[zbus(property)]
    async fn icon_name(&self) -> String {
        self.current_icon()
    }

    #[zbus(property)]
    async fn attention_icon_name(&self) -> &str {
        "security-medium"
    }

    #[zbus(property)]
    async fn item_is_menu(&self) -> bool {
        false
    }

    #[zbus(property)]
    async fn menu(&self) -> ObjectPath<'_> {
        ObjectPath::from_static_str_unchecked("/NO_DBUSMENU")
    }

    #[zbus(property)]
    async fn tool_tip(&self) -> SniTooltip {
        self.current_tooltip()
    }

    async fn activate(&self, _x: i32, _y: i32) {
        self.spawn_panel();
    }

    async fn secondary_activate(&self, _x: i32, _y: i32) {
        self.spawn_panel();
    }

    async fn context_menu(&self, _x: i32, _y: i32) {
        self.spawn_panel();
    }

    async fn scroll(&self, _delta: i32, _orientation: &str) {}

    #[zbus(signal)]
    pub async fn new_status(ctxt: &SignalEmitter<'_>, status: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn new_icon(ctxt: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn new_tool_tip(ctxt: &SignalEmitter<'_>) -> zbus::Result<()>;
}

pub async fn register_with_watcher(conn: &Connection) {
    let Ok(proxy) = zbus::Proxy::new(
        conn,
        "org.kde.StatusNotifierWatcher",
        "/StatusNotifierWatcher",
        "org.kde.StatusNotifierWatcher",
    )
    .await
    else {
        return;
    };
    let _: zbus::Result<()> = proxy
        .call("RegisterStatusNotifierItem", &("/StatusNotifierItem",))
        .await;
}

pub async fn emit_sni_update(conn: &Connection, pending_count: u32) {
    let iface_ref = conn
        .object_server()
        .interface::<_, StatusNotifierItem>("/StatusNotifierItem")
        .await;
    let Ok(iface_ref) = iface_ref else {
        return;
    };
    let status = {
        let iface = iface_ref.get().await;
        if let Ok(mut guard) = iface.state.lock() {
            guard.pending_count = pending_count;
        }
        iface.current_status()
    };
    let ctxt = iface_ref.signal_emitter();
    let _ = StatusNotifierItem::new_status(ctxt, &status).await;
    let _ = StatusNotifierItem::new_icon(ctxt).await;
    let _ = StatusNotifierItem::new_tool_tip(ctxt).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tooltip_returns_without_deadlock() {
        let idle = StatusNotifierItem::new(0);
        let (icon0, _, title0, desc0) = idle.current_tooltip();
        assert_eq!(icon0, "security-high");
        assert_eq!(title0, "NodusGuard");
        assert!(desc0.contains("Nenhuma"));

        let busy = StatusNotifierItem::new(3);
        let (icon3, _, title3, desc3) = busy.current_tooltip();
        assert_eq!(icon3, "security-medium");
        assert_eq!(title3, "NodusGuard");
        assert!(desc3.contains("3 pendência"));
    }
}
