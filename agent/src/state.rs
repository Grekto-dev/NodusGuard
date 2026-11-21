use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Local;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum StateError {
    #[error("Erro de I/O ao acessar pendências: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON inválido no arquivo de pendências: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingDecision {
    pub pending_id: String,
    pub kind: String,
    pub module_id: String,
    #[serde(default)]
    pub app_name: String,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub evidence: String,
    pub created_at: String,
    #[serde(default = "default_open_status")]
    pub status: String,
    #[serde(default)]
    pub fan_q_overflow: bool,
    #[serde(default)]
    pub affected_paths: Vec<String>,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub incident_id: Option<String>,
    #[serde(default = "default_occurrences")]
    pub occurrences: u32,
    #[serde(default)]
    pub metadata: HashMap<String, Value>,
}

fn default_open_status() -> String {
    "open".to_string()
}

fn default_occurrences() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub items: Vec<PendingDecision>,
}

fn default_version() -> u32 {
    1
}

impl Default for PendingFile {
    fn default() -> Self {
        Self {
            version: 1,
            updated_at: Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
            items: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn default_path() -> PathBuf {
        if let Ok(xdg_state) = std::env::var("XDG_STATE_HOME") {
            let trimmed = xdg_state.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed)
                    .join("mint-security-suite")
                    .join("pending.json");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let trimmed = home.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed)
                    .join(".local/state/mint-security-suite/pending.json");
            }
        }
        if let Ok(xdg_rt) = std::env::var("XDG_RUNTIME_DIR") {
            let trimmed = xdg_rt.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed)
                    .join("mint-security-suite")
                    .join("pending.json");
            }
        }
        PathBuf::from(format!(
            "/tmp/mint-security-suite-{}/pending.json",
            std::process::id()
        ))
    }

    pub fn load(&self) -> Result<PendingFile, StateError> {
        if !self.path.exists() {
            return Ok(PendingFile::default());
        }
        let raw = fs::read_to_string(&self.path)?;
        if raw.trim().is_empty() {
            return Ok(PendingFile::default());
        }
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save(&self, file: &PendingFile) -> Result<(), StateError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(".pending.{}.{}.tmp", std::process::id(), seq);
        let tmp_path = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(tmp_name);

        let payload = serde_json::to_string_pretty(file)?;
        let write_res: std::io::Result<()> = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(payload.as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        if let Err(err) = fs::rename(&tmp_path, &self.path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        Ok(())
    }

    pub fn add_or_group(
        &self,
        mut decision: PendingDecision,
        group_repeated: bool,
    ) -> Result<PendingDecision, StateError> {
        let mut file = self.load()?;
        if decision.pending_id.is_empty() {
            decision.pending_id = Uuid::new_v4().to_string();
        }
        if decision.created_at.is_empty() {
            decision.created_at =
                Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
        }
        if decision.status.is_empty() {
            decision.status = "open".to_string();
        }
        if decision.occurrences == 0 {
            decision.occurrences = 1;
        }

        if group_repeated && !decision.app_name.is_empty() {
            for existing in &mut file.items {
                if existing.status == "open"
                    && existing.kind == decision.kind
                    && existing.module_id == decision.module_id
                    && existing.app_name == decision.app_name
                {
                    existing.occurrences = existing.occurrences.saturating_add(1);
                    existing.evidence = decision.evidence.clone();
                    existing.summary = decision.summary.clone();
                    existing.fan_q_overflow = existing.fan_q_overflow || decision.fan_q_overflow;
                    for p in &decision.affected_paths {
                        if !existing.affected_paths.contains(p) {
                            existing.affected_paths.push(p.clone());
                        }
                    }
                    for (k, v) in &decision.metadata {
                        existing.metadata.insert(k.clone(), v.clone());
                    }
                    let result = existing.clone();
                    file.updated_at =
                        Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
                    self.save(&file)?;
                    return Ok(result);
                }
            }
        }

        file.items.push(decision.clone());
        file.updated_at = Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
        self.save(&file)?;
        Ok(decision)
    }

    pub fn resolve(&self, pending_id: &str, resolution: &str) -> Result<bool, StateError> {
        let mut file = self.load()?;
        let mut changed = false;
        for item in &mut file.items {
            if item.pending_id == pending_id {
                item.status = resolution.to_string();
                changed = true;
                break;
            }
        }
        if changed {
            file.updated_at = Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
            self.save(&file)?;
        }
        Ok(changed)
    }

    pub fn list_open(&self) -> Result<Vec<PendingDecision>, StateError> {
        let file = self.load()?;
        Ok(file
            .items
            .into_iter()
            .filter(|i| i.status == "open")
            .collect())
    }

    pub fn open_count(&self) -> Result<u32, StateError> {
        Ok(self.list_open()?.len() as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_decision(app: &str, path: &str) -> PendingDecision {
        PendingDecision {
            pending_id: String::new(),
            kind: "paused_app".to_string(),
            module_id: "recovery".to_string(),
            app_name: app.to_string(),
            title: "Um aplicativo está pausado".to_string(),
            summary: "Alteração suspeita em canário".to_string(),
            evidence: "Canário modificado + cgroup exclusivo".to_string(),
            created_at: String::new(),
            status: "open".to_string(),
            fan_q_overflow: false,
            affected_paths: vec![path.to_string()],
            actions: vec!["keep_paused".to_string(), "resume".to_string()],
            incident_id: Some("inc-1".to_string()),
            occurrences: 1,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn groups_repeated_open_alerts_for_same_app() {
        let dir = std::env::temp_dir().join(format!("mintsec-agent-test-{}", Uuid::new_v4()));
        let store = StateStore::new(dir.join("pending.json"));

        let d1 = store
            .add_or_group(sample_decision("suspeito-bin", "/tmp/a.txt"), true)
            .unwrap();
        let d2 = store
            .add_or_group(sample_decision("suspeito-bin", "/tmp/b.txt"), true)
            .unwrap();

        assert_eq!(d1.pending_id, d2.pending_id);
        assert_eq!(d2.occurrences, 2);
        assert_eq!(d2.affected_paths.len(), 2);
        assert_eq!(store.open_count().unwrap(), 1);

        assert!(store.resolve(&d1.pending_id, "terminated").unwrap());
        assert_eq!(store.open_count().unwrap(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_python_pending_json_interoperably() {
        let dir = std::env::temp_dir().join(format!("mintsec-agent-interop-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pending.json");
        let python_json = r#"{
          "version": 1,
          "updated_at": "2026-11-21T10:30:00-03:00",
          "items": [
            {
              "pending_id": "abc-123",
              "kind": "quarantine_detection",
              "module_id": "antimalware",
              "app_name": "amostra.exe",
              "title": "Detecção em amostra.exe",
              "summary": "Assinatura Eicar encontrada",
              "evidence": "Assinatura: Eicar-Test-Signature",
              "created_at": "2026-11-21T10:30:00-03:00",
              "status": "open",
              "fan_q_overflow": false,
              "affected_paths": ["/home/user/Downloads/sample.exe"],
              "actions": ["quarantine", "ignore"],
              "incident_id": null,
              "occurrences": 1,
              "metadata": {}
            }
          ]
        }"#;
        fs::write(&p, python_json).unwrap();
        let store = StateStore::new(p);
        let items = store.list_open().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].pending_id, "abc-123");
        assert_eq!(items[0].module_id, "antimalware");
        let _ = fs::remove_dir_all(&dir);
    }
}
