use uuid::Uuid;

pub fn generate_refresh_token() -> String {
    // Generate a random UUID and convert to string
    // This creates a unique, unpredictable token
    Uuid::new_v4().to_string()
}
