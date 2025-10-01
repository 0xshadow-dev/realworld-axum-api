use super::traits::EmailVerificationRepositoryTrait;
use crate::models::EmailVerificationToken;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct EmailVerificationRepository {
    db: PgPool,
}

impl EmailVerificationRepository {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl EmailVerificationRepositoryTrait for EmailVerificationRepository {
    async fn create_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<EmailVerificationToken, sqlx::Error> {
        let verification_token = sqlx::query_as::<_, EmailVerificationToken>(
            r#"
            INSERT INTO email_verification_tokens (user_id, token, expires_at)
            VALUES ($1, $2, $3)
            RETURNING id, user_id, token, expires_at, created_at
            "#,
        )
        .bind(user_id)
        .bind(token)
        .bind(expires_at)
        .fetch_one(&self.db)
        .await?;

        Ok(verification_token)
    }

    async fn find_by_token(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationToken>, sqlx::Error> {
        let verification_token = sqlx::query_as::<_, EmailVerificationToken>(
            r#"
            SELECT id, user_id, token, expires_at, created_at
            FROM email_verification_tokens
            WHERE token = $1
            "#,
        )
        .bind(token)
        .fetch_optional(&self.db)
        .await?;

        Ok(verification_token)
    }

    async fn delete_token(&self, token: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM email_verification_tokens
            WHERE token = $1
            "#,
        )
        .bind(token)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn verify_user_email(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE users
            SET email_verified = TRUE
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }
}
