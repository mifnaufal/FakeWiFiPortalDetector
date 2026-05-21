use rusqlite::{Connection, Result as SqliteResult, params};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustedNetwork {
    pub id: i64,
    pub ssid: String,
    pub bssid: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanLog {
    pub id: i64,
    pub ssid: String,
    pub domain: String,
    pub risk_score: i32,
    pub risk_level: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppSetting {
    pub id: i64,
    pub key: String,
    pub value: String,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(path: Option<PathBuf>) -> SqliteResult<Self> {
        let db_path = path.unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".local/share/fakewifi-detector/history.db")
        });

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let conn = Connection::open(&db_path)?;
        let db = Database { conn };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> SqliteResult<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS trusted_networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid TEXT NOT NULL,
                bssid TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid TEXT NOT NULL,
                domain TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                value TEXT NOT NULL
            );"
        )?;
        Ok(())
    }

    pub fn add_trusted_network(&self, ssid: &str, bssid: Option<&str>) -> SqliteResult<()> {
        self.conn.execute(
            "INSERT INTO trusted_networks (ssid, bssid) VALUES (?1, ?2)",
            params![ssid, bssid],
        )?;
        Ok(())
    }

    pub fn remove_trusted_network(&self, ssid: &str) -> SqliteResult<()> {
        self.conn.execute(
            "DELETE FROM trusted_networks WHERE ssid = ?1",
            params![ssid],
        )?;
        Ok(())
    }

    pub fn is_trusted_network(&self, ssid: &str) -> SqliteResult<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM trusted_networks WHERE ssid = ?1",
            params![ssid],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn list_trusted_networks(&self) -> SqliteResult<Vec<TrustedNetwork>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ssid, bssid, created_at FROM trusted_networks ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TrustedNetwork {
                id: row.get(0)?,
                ssid: row.get(1)?,
                bssid: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        let mut networks = Vec::new();
        for row in rows {
            networks.push(row?);
        }
        Ok(networks)
    }

    pub fn insert_scan_log(
        &self,
        ssid: &str,
        domain: &str,
        risk_score: i32,
        risk_level: &str,
        reason: &str,
    ) -> SqliteResult<()> {
        self.conn.execute(
            "INSERT INTO scan_logs (ssid, domain, risk_score, risk_level, reason) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ssid, domain, risk_score, risk_level, reason],
        )?;
        Ok(())
    }

    pub fn get_recent_logs(&self, limit: i64) -> SqliteResult<Vec<ScanLog>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ssid, domain, risk_score, risk_level, reason, created_at FROM scan_logs ORDER BY created_at DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(ScanLog {
                id: row.get(0)?,
                ssid: row.get(1)?,
                domain: row.get(2)?,
                risk_score: row.get(3)?,
                risk_level: row.get(4)?,
                reason: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?;
        let mut logs = Vec::new();
        for row in rows {
            logs.push(row?);
        }
        Ok(logs)
    }

    pub fn get_setting(&self, key: &str) -> SqliteResult<Option<String>> {
        let result = self.conn.query_row(
            "SELECT value FROM app_settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );
        match result {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> SqliteResult<()> {
        self.conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_db() -> Database {
        let path = PathBuf::from("/tmp/fakewifi_test.db");
        let _ = std::fs::remove_file(&path);
        Database::new(Some(path)).unwrap()
    }

    #[test]
    fn test_create_tables() {
        let db = test_db();
        let trusted = db.list_trusted_networks().unwrap();
        assert!(trusted.is_empty());
    }

    #[test]
    fn test_add_and_check_trusted() {
        let db = test_db();
        db.add_trusted_network("TestSSID", None).unwrap();
        assert!(db.is_trusted_network("TestSSID").unwrap());
        assert!(!db.is_trusted_network("Unknown").unwrap());
    }

    #[test]
    fn test_add_and_remove_trusted() {
        let db = test_db();
        db.add_trusted_network("TestSSID", None).unwrap();
        db.remove_trusted_network("TestSSID").unwrap();
        assert!(!db.is_trusted_network("TestSSID").unwrap());
    }

    #[test]
    fn test_list_trusted() {
        let db = test_db();
        db.add_trusted_network("NetA", None).unwrap();
        db.add_trusted_network("NetB", None).unwrap();
        let list = db.list_trusted_networks().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_insert_scan_log() {
        let db = test_db();
        db.insert_scan_log("TestSSID", "example.com", 25, "Suspicious", "SSL issue")
            .unwrap();
        let logs = db.get_recent_logs(10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].ssid, "TestSSID");
        assert_eq!(logs[0].risk_score, 25);
    }

    #[test]
    fn test_get_recent_logs_limit() {
        let db = test_db();
        for i in 0..5 {
            db.insert_scan_log(
                &format!("SSID{}", i),
                "example.com",
                i * 10,
                "Safe",
                "",
            )
            .unwrap();
        }
        let logs = db.get_recent_logs(3).unwrap();
        assert_eq!(logs.len(), 3);
    }

    #[test]
    fn test_settings() {
        let db = test_db();
        assert!(db.get_setting("theme").unwrap().is_none());
        db.set_setting("theme", "dark").unwrap();
        assert_eq!(db.get_setting("theme").unwrap(), Some("dark".to_string()));
        db.set_setting("theme", "light").unwrap();
        assert_eq!(db.get_setting("theme").unwrap(), Some("light".to_string()));
    }
}
