use crate::utils::token_generator::generate_verification_token;
use crate::{
    auth::{
        jwt::generate_token,
        middleware::RequireAuth,
        password::{hash_password, verify_password},
    },
    schemas::auth_schemas::*,
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use validator::Validate;

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    eprintln!("REGISTER HANDLER CALLED");

    eprintln!("Validating...");
    payload
        .user
        .validate()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    eprintln!("Checking email exists...");
    if state
        .user_repository
        .find_by_email(&payload.user.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    eprintln!("Checking username exists...");
    if state
        .user_repository
        .find_by_username(&payload.user.username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    eprintln!("Hashing password...");
    let password_hash =
        hash_password(&payload.user.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    eprintln!("Creating user...");
    let user = state
        .user_repository
        .create(&payload.user.username, &payload.user.email, &password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    eprintln!("User created: {}", user.email);

    // Generate verification token
    let verification_token = generate_verification_token();
    let expires_at = Utc::now() + Duration::hours(24);

    eprintln!("Generated token: {}", verification_token);

    // Save token to database
    state
        .email_verification_repository
        .create_token(user.id, &verification_token, expires_at)
        .await
        .map_err(|e| {
            eprintln!("Failed to create token in DB: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    eprintln!("💾 Token saved to database");

    // Send verification email
    eprintln!("Attempting to send email...");
    state
        .email_service
        .send_verification_email(&user.email, &user.username, &verification_token)
        .await
        .map_err(|e| {
            eprintln!("Failed to send verification email: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    eprintln!("Email sent successfully");

    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user_data = UserData::from_user_with_token(user, token);
    let response = UserResponse { user: user_data };

    eprintln!("Registration complete");

    Ok(Json(response))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    // Validate input
    payload
        .user
        .validate()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Find user by email
    let user = state
        .user_repository
        .find_by_email(&payload.user.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Verify password
    let password_valid = verify_password(&payload.user.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !password_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Generate JWT token
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build response
    let user_data = UserData::from_user_with_token(user, token);
    let response = UserResponse { user: user_data };

    Ok(Json(response))
}

pub async fn current_user(
    RequireAuth(user): RequireAuth,
) -> Result<Json<UserResponse>, StatusCode> {
    // Generate fresh JWT token
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build response
    let user_data = UserData::from_user_with_token(user, token);
    let response = UserResponse { user: user_data };

    Ok(Json(response))
}

pub async fn verify_email(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = params.get("token").ok_or(StatusCode::BAD_REQUEST)?;

    let verification_token = state
        .email_verification_repository
        .find_by_token(token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if verification_token.is_expired() {
        state
            .email_verification_repository
            .delete_token(token)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        return Err(StatusCode::GONE);
    }

    state
        .email_verification_repository
        .verify_user_email(verification_token.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .email_verification_repository
        .delete_token(token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "message": "Email verified successfully!"
    })))
}
