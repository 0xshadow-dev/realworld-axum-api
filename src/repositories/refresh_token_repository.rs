use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use super::traits::RefreshTokenRepositoryTrait;
use crate::models::RefreshToken;

#[derive(Clone)]
pub struct RefreshTokenRepository {
    db: PgPool,
}

impl RefreshTokenRepository {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl RefreshTokenRepositoryTrait for RefreshTokenRepository {
    async fn create_token(&self, user_id: Uuid, token: &str) -> Result<RefreshToken, sqlx::Error> {
        let refresh_token = sqlx::query_as::<_, RefreshToken>(
            r#"
            INSERT INTO refresh_tokens (user_id, token)
            VALUES ($1, $2)
            RETURNING id, user_id, token, created_at, last_used_at
            "#,
        )
        .bind(user_id)
        .bind(token)
        .fetch_one(&self.db)
        .await?;

        Ok(refresh_token)
    }

    async fn find_by_token(&self, token: &str) -> Result<Option<RefreshToken>, sqlx::Error> {
        let refresh_token = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT id, user_id, token, created_at, last_used_at
            FROM refresh_tokens
            WHERE token = $1
            "#,
        )
        .bind(token)
        .fetch_optional(&self.db)
        .await?;

        Ok(refresh_token)
    }

    async fn update_last_used(&self, token: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET last_used_at = $1
            WHERE token = $2
            "#,
        )
        .bind(Utc::now())
        .bind(token)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_token(&self, token: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM refresh_tokens
            WHERE token = $1
            "#,
        )
        .bind(token)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_all_user_tokens(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM refresh_tokens
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }
}
