use crate::{
    auth::middleware::RequireAuth,
    auth::{
        jwt::generate_token,
        password::{hash_password, verify_password},
    },
    schemas::auth_schemas::*,
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use validator::Validate;

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    // Validate input
    payload
        .user
        .validate()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Check if user already exists
    if state
        .user_repository
        .find_by_email(&payload.user.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    // Hash password
    let password_hash =
        hash_password(&payload.user.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create user
    let user = state
        .user_repository
        .create(&payload.user.username, &payload.user.email, &password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate JWT token
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Return response
    let response = UserResponse {
        user: UserData {
            email: user.email,
            token,
            username: user.username,
            bio: user.bio.unwrap_or_default(),
            image: user.image,
        },
    };

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
    verify_password(&payload.user.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .then_some(())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Generate JWT token
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Return response
    let response = UserResponse {
        user: UserData {
            email: user.email,
            token,
            username: user.username,
            bio: user.bio.unwrap_or_default(),
            image: user.image,
        },
    };

    Ok(Json(response))
}

pub async fn current_user(
    RequireAuth(user): RequireAuth,
) -> Result<Json<UserResponse>, StatusCode> {
    // Generate fresh token
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = UserResponse {
        user: UserData {
            email: user.email,
            token,
            username: user.username,
            bio: user.bio.unwrap_or_default(),
            image: user.image,
        },
    };

    Ok(Json(response))
}
