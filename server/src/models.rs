use super::schema::*;
use diesel::{r2d2::ConnectionManager, SqliteConnection};

// type alias to use in multiple places
pub type Pool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

#[derive(Debug, Serialize, Deserialize, Queryable, Insertable)]
#[table_name = "users"]
pub struct User {
  pub username: String,
  pub password: String,
  pub has_voted: bool,
}

impl From<RegisterUser> for User {
  fn from(register_user: RegisterUser) -> Self {
    User {
      username: register_user.username,
      password: register_user.password,
      has_voted: true,
    }
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterUser {
  pub username: String,
  pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlimUser {
  pub username: String,
  pub x: String,
}

impl From<User> for SlimUser {
  fn from(user: User) -> Self {
    SlimUser {
      username: user.username,
      x: "not set".to_string(),
    }
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreSignRequest {
  pub a: String,
  pub alpha: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
  pub a: String,
  pub alpha: String,
  pub beta: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
  pub beta_invert: String,
  pub t: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyResponse {
  pub n: String,
  pub e: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreSignResponse {
  pub x: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
  pub a: String,
  pub m: String,
  pub c: String,
  pub s: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ballot {
  title: String,
  multiple: bool,
  candidates: Candidates,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Candidates {
  number: usize,
  candidates: Vec<String>,
}
