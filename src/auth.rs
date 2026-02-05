//! Authentication handlers for user login, registration, and 2FA.

use askama::Template;
use cookie::Cookie;
use futures_lite::StreamExt;
use hyper::{Body, Request, Response};
use std::collections::HashMap;
use time::{Duration, OffsetDateTime};

use crate::db::{
    self, authenticate_user, create_user, delete_session, generate_totp_secret,
    is_auth_required, is_db_enabled, validate_session, verify_totp_and_login, AuthResult,
    UserAccount,
};
use crate::server::{RequestExt, ResponseExt};
use crate::utils::{redirect, template, Preferences};

const SESSION_COOKIE_NAME: &str = "redlib_session";

/// Template for login page
#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    prefs: Preferences,
    error_msg: String,
    require_2fa: bool,
    user_id: i64,
}

/// Template for registration page
#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    prefs: Preferences,
    error_msg: String,
    success_msg: String,
}

/// Template for 2FA setup page
#[derive(Template)]
#[template(path = "totp_setup.html")]
struct TotpSetupTemplate {
    prefs: Preferences,
    secret: String,
    otpauth_url: String,
    error_msg: String,
}

/// Template for account page
#[derive(Template)]
#[template(path = "account.html")]
struct AccountTemplate {
    prefs: Preferences,
    user: UserAccount,
    subscriptions: Vec<String>,
    filters: Vec<String>,
    message: String,
}

/// Get current user from session cookie
pub fn get_current_user(req: &Request<Body>) -> Option<UserAccount> {
    let session_token = req.cookie(SESSION_COOKIE_NAME)?.value().to_string();
    validate_session(&session_token)
}

/// Check if request is authenticated (for middleware)
pub fn is_authenticated(req: &Request<Body>) -> bool {
    if !is_db_enabled() {
        return true; // No auth when DB is disabled
    }
    if !is_auth_required() {
        return true; // Auth not required
    }
    get_current_user(req).is_some()
}

/// Display login page
pub async fn login_page(req: Request<Body>) -> Result<Response<Body>, String> {
    if !is_db_enabled() {
        return Ok(redirect("/"));
    }

    // If already logged in, redirect to account
    if get_current_user(&req).is_some() {
        return Ok(redirect("/account"));
    }

    Ok(template(&LoginTemplate {
        prefs: Preferences::new(&req),
        error_msg: String::new(),
        require_2fa: false,
        user_id: 0,
    }))
}

/// Handle login form submission
pub async fn login_submit(req: Request<Body>) -> Result<Response<Body>, String> {
    if !is_db_enabled() {
        return Ok(redirect("/"));
    }

    let (_, mut body) = req.into_parts();

    let body_bytes = body
        .try_fold(Vec::new(), |mut data, chunk| {
            data.extend_from_slice(&chunk);
            Ok(data)
        })
        .await
        .map_err(|e| e.to_string())?;

    let form: HashMap<String, String> = url::form_urlencoded::parse(&body_bytes)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let username = form.get("username").map(|s| s.as_str()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let totp_code = form.get("totp_code").map(|s| s.as_str()).unwrap_or("");
    let user_id_str = form.get("user_id").map(|s| s.as_str()).unwrap_or("0");

    // Handle 2FA verification
    if !totp_code.is_empty() {
        let user_id: i64 = user_id_str.parse().unwrap_or(0);
        if user_id > 0 {
            return match verify_totp_and_login(user_id, totp_code) {
                AuthResult::Success(_, token) => {
                    let mut response = redirect("/account");
                    set_session_cookie(&mut response, &token);
                    Ok(response)
                }
                _ => Ok(template(&LoginTemplate {
                    prefs: Preferences::default(),
                    error_msg: "Invalid 2FA code".to_string(),
                    require_2fa: true,
                    user_id,
                })),
            };
        }
    }

    // Regular login
    match authenticate_user(username, password) {
        AuthResult::Success(_, token) => {
            let mut response = redirect("/account");
            set_session_cookie(&mut response, &token);
            Ok(response)
        }
        AuthResult::RequiresTwoFactor(user_id) => Ok(template(&LoginTemplate {
            prefs: Preferences::default(),
            error_msg: String::new(),
            require_2fa: true,
            user_id,
        })),
        AuthResult::InvalidCredentials => Ok(template(&LoginTemplate {
            prefs: Preferences::default(),
            error_msg: "Invalid username or password".to_string(),
            require_2fa: false,
            user_id: 0,
        })),
        AuthResult::DatabaseError(e) => Ok(template(&LoginTemplate {
            prefs: Preferences::default(),
            error_msg: format!("Database error: {}", e),
            require_2fa: false,
            user_id: 0,
        })),
        _ => Ok(template(&LoginTemplate {
            prefs: Preferences::default(),
            error_msg: "Login failed".to_string(),
            require_2fa: false,
            user_id: 0,
        })),
    }
}

/// Display registration page
pub async fn register_page(req: Request<Body>) -> Result<Response<Body>, String> {
    if !is_db_enabled() {
        return Ok(redirect("/"));
    }

    Ok(template(&RegisterTemplate {
        prefs: Preferences::new(&req),
        error_msg: String::new(),
        success_msg: String::new(),
    }))
}

/// Handle registration form submission
pub async fn register_submit(req: Request<Body>) -> Result<Response<Body>, String> {
    if !is_db_enabled() {
        return Ok(redirect("/"));
    }

    let (_, mut body) = req.into_parts();

    let body_bytes = body
        .try_fold(Vec::new(), |mut data, chunk| {
            data.extend_from_slice(&chunk);
            Ok(data)
        })
        .await
        .map_err(|e| e.to_string())?;

    let form: HashMap<String, String> = url::form_urlencoded::parse(&body_bytes)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let username = form.get("username").map(|s| s.as_str()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let confirm_password = form.get("confirm_password").map(|s| s.as_str()).unwrap_or("");

    if password != confirm_password {
        return Ok(template(&RegisterTemplate {
            prefs: Preferences::default(),
            error_msg: "Passwords do not match".to_string(),
            success_msg: String::new(),
        }));
    }

    match create_user(username, password) {
        Ok(_) => Ok(template(&RegisterTemplate {
            prefs: Preferences::default(),
            error_msg: String::new(),
            success_msg: "Account created successfully! You can now log in.".to_string(),
        })),
        Err(e) => Ok(template(&RegisterTemplate {
            prefs: Preferences::default(),
            error_msg: e,
            success_msg: String::new(),
        })),
    }
}

/// Handle logout
pub async fn logout(req: Request<Body>) -> Result<Response<Body>, String> {
    if let Some(cookie) = req.cookie(SESSION_COOKIE_NAME) {
        let _ = delete_session(cookie.value());
    }

    let mut response = redirect("/");
    clear_session_cookie(&mut response);
    Ok(response)
}

/// Display account page
pub async fn account_page(req: Request<Body>) -> Result<Response<Body>, String> {
    if !is_db_enabled() {
        return Ok(redirect("/"));
    }

    let user = match get_current_user(&req) {
        Some(u) => u,
        None => return Ok(redirect("/login")),
    };

    let subscriptions = db::get_user_subscriptions(user.id).unwrap_or_default();
    let filters = db::get_user_filters(user.id).unwrap_or_default();

    Ok(template(&AccountTemplate {
        prefs: Preferences::new(&req),
        user,
        subscriptions,
        filters,
        message: String::new(),
    }))
}

/// Display 2FA setup page
pub async fn totp_setup_page(req: Request<Body>) -> Result<Response<Body>, String> {
    if !is_db_enabled() {
        return Ok(redirect("/"));
    }

    let user = match get_current_user(&req) {
        Some(u) => u,
        None => return Ok(redirect("/login")),
    };

    if user.totp_enabled {
        return Ok(redirect("/account"));
    }

    let (secret, otpauth_url) = generate_totp_secret(&user.username)?;

    Ok(template(&TotpSetupTemplate {
        prefs: Preferences::new(&req),
        secret,
        otpauth_url,
        error_msg: String::new(),
    }))
}

/// Handle 2FA setup form submission
pub async fn totp_setup_submit(req: Request<Body>) -> Result<Response<Body>, String> {
    if !is_db_enabled() {
        return Ok(redirect("/"));
    }

    let user = match get_current_user(&req) {
        Some(u) => u,
        None => return Ok(redirect("/login")),
    };

    let (_, mut body) = req.into_parts();

    let body_bytes = body
        .try_fold(Vec::new(), |mut data, chunk| {
            data.extend_from_slice(&chunk);
            Ok(data)
        })
        .await
        .map_err(|e| e.to_string())?;

    let form: HashMap<String, String> = url::form_urlencoded::parse(&body_bytes)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let secret = form.get("secret").map(|s| s.as_str()).unwrap_or("");
    let code = form.get("code").map(|s| s.as_str()).unwrap_or("");

    match db::enable_totp(user.id, secret, code) {
        Ok(()) => Ok(redirect("/account")),
        Err(e) => {
            let (_, otpauth_url) = generate_totp_secret(&user.username)?;
            Ok(template(&TotpSetupTemplate {
                prefs: Preferences::default(),
                secret: secret.to_string(),
                otpauth_url,
                error_msg: e,
            }))
        }
    }
}

/// Disable 2FA
pub async fn totp_disable(req: Request<Body>) -> Result<Response<Body>, String> {
    if !is_db_enabled() {
        return Ok(redirect("/"));
    }

    let user = match get_current_user(&req) {
        Some(u) => u,
        None => return Ok(redirect("/login")),
    };

    let _ = db::disable_totp(user.id);
    Ok(redirect("/account"))
}

/// Set session cookie on response
fn set_session_cookie(response: &mut Response<Body>, token: &str) {
    response.insert_cookie(
        Cookie::build((SESSION_COOKIE_NAME.to_owned(), token.to_owned()))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(cookie::SameSite::Lax)
            .expires(OffsetDateTime::now_utc() + Duration::days(7))
            .into(),
    );
}

/// Clear session cookie on response
fn clear_session_cookie(response: &mut Response<Body>) {
    response.remove_cookie(SESSION_COOKIE_NAME.to_string());
}
