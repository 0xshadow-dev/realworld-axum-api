use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize)]
pub struct RegisterUserRequest {
    pub user: RegisterUserData,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterUserData {
    #[validate(length(min = 3, max = 50))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginUserRequest {
    pub user: LoginUserData,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginUserData {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 1))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub user: UserData,
}

#[derive(Debug, Serialize)]
pub struct UserData {
    pub email: String,
    pub token: String,
    pub username: String,
    pub bio: String,
    pub image: Option<String>,
}
