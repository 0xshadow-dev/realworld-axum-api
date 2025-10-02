use crate::models::{EmailVerificationToken, User};
use async_trait::async_trait;
use sqlx::Error as SqlxError;
use uuid::Uuid;

#[async_trait]
pub trait UserRepositoryTrait: Send + Sync {
    async fn create(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<User, SqlxError>;

    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, SqlxError>;

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, SqlxError>;

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, SqlxError>;

    async fn update(
        &self,
        id: Uuid,
        username: Option<&str>,
        email: Option<&str>,
        bio: Option<&str>,
        image: Option<&str>,
    ) -> Result<Option<User>, SqlxError>;
}

#[async_trait]
pub trait EmailVerificationRepositoryTrait: Send + Sync {
    async fn create_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<EmailVerificationToken, SqlxError>;

    async fn find_by_token(&self, token: &str)
        -> Result<Option<EmailVerificationToken>, SqlxError>;

    async fn delete_token(&self, token: &str) -> Result<(), SqlxError>;

    async fn verify_user_email(&self, user_id: Uuid) -> Result<(), SqlxError>;
}
