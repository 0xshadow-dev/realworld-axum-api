use crate::repositories::UserRepository;
use axum::extract::FromRef;
use sqlx::PgPool;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub db: PgPool,
    pub user_repository: UserRepository,
}

impl AppState {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        // Create the database connection pool
        let db = PgPool::connect(database_url).await?;

        // Run migrations
        sqlx::migrate!("./migrations").run(&db).await?;

        // Create the user repository
        let user_repository = UserRepository::new(db.clone());

        Ok(Self {
            db,
            user_repository,
        })
    }
}
