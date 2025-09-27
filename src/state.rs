use crate::repositories::UserRepository;
use axum::extract::FromRef;
use sqlx::PgPool;

#[derive(Clone, FromRef)] // Add FromRef derive
pub struct AppState {
    pub db: PgPool,
    pub user_repository: UserRepository,
}

impl AppState {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let db = PgPool::connect(database_url).await?;
        sqlx::migrate!("./migrations").run(&db).await?;
        let user_repository = UserRepository::new(db.clone());

        Ok(Self {
            db,
            user_repository,
        })
    }
}
