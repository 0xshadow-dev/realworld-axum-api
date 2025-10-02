use uuid::Uuid;

pub fn generate_verification_token() -> String {
    // Generate a random UUID and convert to string without hyphens
    // Example: "550e8400e29b41d4a716446655440000"
    Uuid::new_v4().simple().to_string()
}
