//! Database module for user accounts and settings persistence.
//!
//! This module provides SQLite-based storage for user accounts,
//! preferences, and subscriptions.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rusqlite::{params, Connection, Result as SqliteResult};
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::config::get_setting;

/// Global database connection pool
pub static DB_POOL: LazyLock<Option<Mutex<Connection>>> = LazyLock::new(|| {
    match get_setting("REDLIB_DB_PATH") {
        Some(db_path) => match initialize_database(&db_path) {
            Ok(conn) => Some(Mutex::new(conn)),
            Err(e) => {
                log::error!("Failed to initialize database: {}", e);
                None
            }
        },
        None => {
            log::info!("No database path configured (REDLIB_DB_PATH), running without accounts");
            None
        }
    }
});

/// Check if database/accounts feature is enabled
pub fn is_db_enabled() -> bool {
    DB_POOL.is_some()
}

/// Initialize the SQLite database with required tables
fn initialize_database(db_path: &str) -> SqliteResult<Connection> {
    let conn = Connection::open(Path::new(db_path))?;
    
    // Create users table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            totp_enabled INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            updated_at INTEGER DEFAULT (strftime('%s', 'now'))
        )",
        [],
    )?;
    
    // Create sessions table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
        [],
    )?;
    
    // Create user preferences table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_prefs (
            user_id INTEGER PRIMARY KEY,
            theme TEXT DEFAULT '',
            front_page TEXT DEFAULT '',
            layout TEXT DEFAULT '',
            wide TEXT DEFAULT '',
            blur_spoiler TEXT DEFAULT '',
            show_nsfw TEXT DEFAULT '',
            blur_nsfw TEXT DEFAULT '',
            hide_hls_notification TEXT DEFAULT '',
            video_quality TEXT DEFAULT '',
            hide_sidebar_and_summary TEXT DEFAULT '',
            use_hls TEXT DEFAULT '',
            autoplay_videos TEXT DEFAULT '',
            fixed_navbar TEXT DEFAULT 'on',
            comment_sort TEXT DEFAULT '',
            post_sort TEXT DEFAULT '',
            hide_awards TEXT DEFAULT '',
            hide_score TEXT DEFAULT '',
            remove_default_feeds TEXT DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
        [],
    )?;
    
    // Create subscriptions table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subreddit TEXT NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            UNIQUE(user_id, subreddit),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
        [],
    )?;
    
    // Create filters table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subreddit TEXT NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            UNIQUE(user_id, subreddit),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
        [],
    )?;
    
    // Create indexes for faster lookups
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_subs_user ON subscriptions(user_id)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_filters_user ON filters(user_id)", [])?;
    
    Ok(conn)
}

/// User account data
#[derive(Debug, Clone)]
pub struct UserAccount {
    pub id: i64,
    pub username: String,
    pub totp_enabled: bool,
}

/// Result of authentication attempt
#[derive(Debug)]
pub enum AuthResult {
    Success(UserAccount, String), // User and session token
    RequiresTwoFactor(i64),       // User ID for 2FA verification
    InvalidCredentials,
    AccountLocked,
    DatabaseError(String),
}

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Password hashing failed: {}", e))
}

/// Verify a password against its hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Generate a new session token
pub fn generate_session_token() -> String {
    use base64::Engine;
    let mut token_bytes = [0u8; 32];
    getrandom::getrandom(&mut token_bytes).expect("Failed to generate random bytes");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
}

/// Create a new user account
pub fn create_user(username: &str, password: &str) -> Result<i64, String> {
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    // Validate username
    if username.len() < 3 || username.len() > 32 {
        return Err("Username must be 3-32 characters".into());
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err("Username can only contain letters, numbers, and underscores".into());
    }
    
    // Validate password
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".into());
    }
    
    let pw_hash = hash_password(password)?;
    
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        params![username, pw_hash],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint") {
            "Username already exists".into()
        } else {
            format!("Database error: {}", e)
        }
    })?;
    
    let user_id = conn.last_insert_rowid();
    
    // Create default preferences for the user
    conn.execute("INSERT INTO user_prefs (user_id) VALUES (?1)", params![user_id])
        .map_err(|e| format!("Failed to create user preferences: {}", e))?;
    
    Ok(user_id)
}

/// Authenticate a user with username and password
pub fn authenticate_user(username: &str, password: &str) -> AuthResult {
    let db = match DB_POOL.as_ref() {
        Some(d) => d,
        None => return AuthResult::DatabaseError("Database not available".into()),
    };
    
    let conn = match db.lock() {
        Ok(c) => c,
        Err(e) => return AuthResult::DatabaseError(format!("DB lock error: {}", e)),
    };
    
    let result: SqliteResult<(i64, String, String, bool)> = conn.query_row(
        "SELECT id, username, password_hash, totp_enabled FROM users WHERE username = ?1",
        params![username],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get::<_, i32>(3)? != 0)),
    );
    
    match result {
        Ok((user_id, uname, pw_hash, totp_enabled)) => {
            if !verify_password(password, &pw_hash) {
                return AuthResult::InvalidCredentials;
            }
            
            if totp_enabled {
                return AuthResult::RequiresTwoFactor(user_id);
            }
            
            // Create session
            match create_session(user_id, &conn) {
                Ok(token) => AuthResult::Success(
                    UserAccount {
                        id: user_id,
                        username: uname,
                        totp_enabled,
                    },
                    token,
                ),
                Err(e) => AuthResult::DatabaseError(e),
            }
        }
        Err(_) => AuthResult::InvalidCredentials,
    }
}

/// Create a new session for a user
fn create_session(user_id: i64, conn: &Connection) -> Result<String, String> {
    let token = generate_session_token();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0) + (7 * 24 * 60 * 60); // 7 days
    
    conn.execute(
        "INSERT INTO sessions (user_id, token, expires_at) VALUES (?1, ?2, ?3)",
        params![user_id, token, expires_at],
    )
    .map_err(|e| format!("Failed to create session: {}", e))?;
    
    Ok(token)
}

/// Validate a session token and return the user
pub fn validate_session(token: &str) -> Option<UserAccount> {
    let db = DB_POOL.as_ref()?;
    let conn = db.lock().ok()?;
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    
    conn.query_row(
        "SELECT u.id, u.username, u.totp_enabled 
         FROM users u 
         JOIN sessions s ON u.id = s.user_id 
         WHERE s.token = ?1 AND s.expires_at > ?2",
        params![token, now],
        |row| {
            Ok(UserAccount {
                id: row.get(0)?,
                username: row.get(1)?,
                totp_enabled: row.get::<_, i32>(2)? != 0,
            })
        },
    )
    .ok()
}

/// Delete a session (logout)
pub fn delete_session(token: &str) -> Result<(), String> {
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])
        .map_err(|e| format!("Failed to delete session: {}", e))?;
    
    Ok(())
}

/// Generate TOTP secret for 2FA setup
pub fn generate_totp_secret(username: &str) -> Result<(String, String), String> {
    let secret = Secret::generate_secret();
    let secret_bytes = secret.to_bytes().map_err(|e| format!("Secret error: {}", e))?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(String::from("Redlib")),
        username.to_string(),
    )
    .map_err(|e| format!("TOTP creation failed: {}", e))?;
    
    let secret_base32 = secret.to_encoded().to_string();
    let otpauth_url = totp.get_url();
    
    Ok((secret_base32, otpauth_url))
}

/// Enable 2FA for a user
pub fn enable_totp(user_id: i64, secret: &str, code: &str) -> Result<(), String> {
    // Verify the code first
    if !verify_totp_code(secret, code)? {
        return Err("Invalid verification code".into());
    }
    
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    conn.execute(
        "UPDATE users SET totp_secret = ?1, totp_enabled = 1, updated_at = strftime('%s', 'now') WHERE id = ?2",
        params![secret, user_id],
    )
    .map_err(|e| format!("Failed to enable 2FA: {}", e))?;
    
    Ok(())
}

/// Disable 2FA for a user
pub fn disable_totp(user_id: i64) -> Result<(), String> {
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    conn.execute(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = strftime('%s', 'now') WHERE id = ?1",
        params![user_id],
    )
    .map_err(|e| format!("Failed to disable 2FA: {}", e))?;
    
    Ok(())
}

/// Verify a TOTP code
pub fn verify_totp_code(secret: &str, code: &str) -> Result<bool, String> {
    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|e| format!("Invalid secret: {}", e))?;
    
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes, None, String::new())
        .map_err(|e| format!("TOTP error: {}", e))?;
    
    Ok(totp.check_current(code).unwrap_or(false))
}

/// Complete 2FA verification and create session
pub fn verify_totp_and_login(user_id: i64, code: &str) -> AuthResult {
    let db = match DB_POOL.as_ref() {
        Some(d) => d,
        None => return AuthResult::DatabaseError("Database not available".into()),
    };
    
    let conn = match db.lock() {
        Ok(c) => c,
        Err(e) => return AuthResult::DatabaseError(format!("DB lock error: {}", e)),
    };
    
    let result: SqliteResult<(String, String, String)> = conn.query_row(
        "SELECT username, totp_secret, password_hash FROM users WHERE id = ?1",
        params![user_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );
    
    match result {
        Ok((username, totp_secret, _)) => {
            match verify_totp_code(&totp_secret, code) {
                Ok(true) => {
                    match create_session(user_id, &conn) {
                        Ok(token) => AuthResult::Success(
                            UserAccount {
                                id: user_id,
                                username,
                                totp_enabled: true,
                            },
                            token,
                        ),
                        Err(e) => AuthResult::DatabaseError(e),
                    }
                }
                Ok(false) => AuthResult::InvalidCredentials,
                Err(e) => AuthResult::DatabaseError(e),
            }
        }
        Err(_) => AuthResult::InvalidCredentials,
    }
}

/// Get user subscriptions
pub fn get_user_subscriptions(user_id: i64) -> Result<Vec<String>, String> {
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    let mut stmt = conn
        .prepare("SELECT subreddit FROM subscriptions WHERE user_id = ?1 ORDER BY subreddit")
        .map_err(|e| format!("Query error: {}", e))?;
    
    let subs = stmt
        .query_map(params![user_id], |row| row.get(0))
        .map_err(|e| format!("Query error: {}", e))?
        .filter_map(|r| r.ok())
        .collect();
    
    Ok(subs)
}

/// Add a subscription for a user
pub fn add_subscription(user_id: i64, subreddit: &str) -> Result<(), String> {
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    conn.execute(
        "INSERT OR IGNORE INTO subscriptions (user_id, subreddit) VALUES (?1, ?2)",
        params![user_id, subreddit],
    )
    .map_err(|e| format!("Failed to add subscription: {}", e))?;
    
    Ok(())
}

/// Remove a subscription for a user
pub fn remove_subscription(user_id: i64, subreddit: &str) -> Result<(), String> {
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    conn.execute(
        "DELETE FROM subscriptions WHERE user_id = ?1 AND subreddit = ?2",
        params![user_id, subreddit],
    )
    .map_err(|e| format!("Failed to remove subscription: {}", e))?;
    
    Ok(())
}

/// Get user filters
pub fn get_user_filters(user_id: i64) -> Result<Vec<String>, String> {
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    let mut stmt = conn
        .prepare("SELECT subreddit FROM filters WHERE user_id = ?1 ORDER BY subreddit")
        .map_err(|e| format!("Query error: {}", e))?;
    
    let filters = stmt
        .query_map(params![user_id], |row| row.get(0))
        .map_err(|e| format!("Query error: {}", e))?
        .filter_map(|r| r.ok())
        .collect();
    
    Ok(filters)
}

/// Add a filter for a user
pub fn add_filter(user_id: i64, subreddit: &str) -> Result<(), String> {
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    conn.execute(
        "INSERT OR IGNORE INTO filters (user_id, subreddit) VALUES (?1, ?2)",
        params![user_id, subreddit],
    )
    .map_err(|e| format!("Failed to add filter: {}", e))?;
    
    Ok(())
}

/// Remove a filter for a user
pub fn remove_filter(user_id: i64, subreddit: &str) -> Result<(), String> {
    let db = DB_POOL.as_ref().ok_or("Database not available")?;
    let conn = db.lock().map_err(|e| format!("DB lock error: {}", e))?;
    
    conn.execute(
        "DELETE FROM filters WHERE user_id = ?1 AND subreddit = ?2",
        params![user_id, subreddit],
    )
    .map_err(|e| format!("Failed to remove filter: {}", e))?;
    
    Ok(())
}

/// Check if authentication is required for access
pub fn is_auth_required() -> bool {
    get_setting("REDLIB_REQUIRE_AUTH")
        .map(|v| v == "on" || v == "true" || v == "1")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = hash_password(password).expect("Hashing should succeed");
        
        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong_password", &hash));
    }
    
    #[test]
    fn test_session_token_generation() {
        let token1 = generate_session_token();
        let token2 = generate_session_token();
        
        assert_ne!(token1, token2);
        assert!(token1.len() >= 32);
    }
}
