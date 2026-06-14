use serde::{Serialize, Deserialize};

// Bu iki derive niteliği (attribute) sayesinde Rust bu yapıyı otomatik JSON yapar/okur.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerProfile {
    pub hostname: String,
    pub username: String,
    pub password: String,
    pub port: u16,
    pub profile_name: String,
}