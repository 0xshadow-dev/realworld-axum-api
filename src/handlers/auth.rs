use crate::auth::tokens::generate_refresh_token;
use crate::schemas::{RefreshTokenRequest, RefreshTokenResponse};
use crate::utils::token_generator::generate_verification_token;
use crate::{
    auth::{
        jwt::generate_token,
        middleware::RequireAuth,
        password::{hash_password, verify_password},
    },
    schemas::auth_schemas::*,
    schemas::password_reset_schemas::*,
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use validator::Validate;

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
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

    // Generate JWT access token (15 minutes)
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate refresh token (UUID, no expiration)
    let refresh_token = generate_refresh_token();

    // Save refresh token to database
    state
        .refresh_token_repository
        .create_token(user.id, &refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build response with BOTH tokens
    let response = LoginResponse {
        user: UserData::from_user(user),
        access_token,
        refresh_token,
    };
    eprintln!("Registration complete");

    Ok(Json(response))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginUserRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
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

    // Generate JWT access token (15 minutes)
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate refresh token (UUID, no expiration)
    let refresh_token = generate_refresh_token();

    // Save refresh token to database
    state
        .refresh_token_repository
        .create_token(user.id, &refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build response with BOTH tokens
    let response = LoginResponse {
        user: UserData::from_user(user),
        access_token,
        refresh_token,
    };

    Ok(Json(response))
}
pub async fn current_user(
    RequireAuth(user): RequireAuth,
) -> Result<Json<UserResponse>, StatusCode> {
    // Build response (no token needed - they already have one)
    let user_data = UserData::from_user(user);
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

// Handler for "Forgot Password" - generates and emails reset token
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, StatusCode> {
    // Validate email format
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Look up user by email
    let user = state
        .user_repository
        .find_by_email(&payload.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // SECURITY: Always return success even if email doesn't exist
    // This prevents attackers from discovering which emails are registered
    if user.is_none() {
        return Ok(Json(ForgotPasswordResponse {
            message: "If that email exists, a password reset link has been sent.".to_string(),
        }));
    }

    let user = user.unwrap();

    // Generate reset token
    let reset_token = generate_verification_token();
    let expires_at = Utc::now() + Duration::hours(1); // 1 hour expiration

    // Save token to database
    state
        .password_reset_repository
        .create_token(user.id, &reset_token, expires_at)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Send reset email
    state
        .email_service
        .send_password_reset_email(&user.email, &user.username, &reset_token)
        .await
        .map_err(|e| {
            eprintln!("Failed to send password reset email: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(ForgotPasswordResponse {
        message: "If that email exists, a password reset link has been sent.".to_string(),
    }))
}

// Handler for actually resetting the password
pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, StatusCode> {
    // Validate new password
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Look up token
    let reset_token = state
        .password_reset_repository
        .find_by_token(&payload.token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Check expiration
    if reset_token.is_expired() {
        // Clean up expired token
        state
            .password_reset_repository
            .delete_token(&payload.token)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        return Err(StatusCode::GONE);
    }

    // Hash new password
    let new_password_hash =
        hash_password(&payload.new_password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update user password
    state
        .user_repository
        .update_password(reset_token.user_id, &new_password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Delete ALL reset tokens for this user (invalidate any other pending requests)
    state
        .password_reset_repository
        .delete_all_user_tokens(reset_token.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ResetPasswordResponse {
        message: "Password has been reset successfully. You can now login with your new password."
            .to_string(),
    }))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>, StatusCode> {
    // Look up the refresh token in database
    let refresh_token = state
        .refresh_token_repository
        .find_by_token(&payload.refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Update last_used_at timestamp
    state
        .refresh_token_repository
        .update_last_used(&payload.refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate new access token
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token = generate_token(&refresh_token.user_id, &jwt_secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Return new access token
    Ok(Json(RefreshTokenResponse { access_token }))
}
