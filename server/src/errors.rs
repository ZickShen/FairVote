use actix_web::{error::ResponseError, HttpResponse};
use derive_more::Display;
use diesel::result::{DatabaseErrorKind, Error as DBError};
use std::convert::From;

#[derive(Debug, Display)]
pub enum ServiceError {
  #[display(fmt = "Internal Server Error")]
  InternalServerError,

  #[display(fmt = "BadRequest: {}", _0)]
  BadRequest(String),

  #[display(fmt = "Unauthorized")]
  Unauthorized,

  #[display(fmt = "Unacceptable Expire Date")]
  UnacceptableDate,

  #[display(fmt = "Already Signed")]
  Signed,

  #[display(fmt = "Presign Not Requested")]
  NoPresign,
}

// impl ResponseError trait allows to convert our errors into http responses with appropriate data
impl ResponseError for ServiceError {
  fn error_response(&self) -> HttpResponse {
    match self {
      ServiceError::InternalServerError => {
        HttpResponse::InternalServerError().json("Internal Server Error, Please try later")
      }
      ServiceError::BadRequest(ref message) => HttpResponse::BadRequest().json(message),
      ServiceError::Unauthorized => HttpResponse::Unauthorized().json("Unauthorized"),
      ServiceError::UnacceptableDate => {
        HttpResponse::NotAcceptable().json("Unacceptable Expire Date")
      }
      ServiceError::Signed => HttpResponse::NotAcceptable().json("Already Signed"),
      ServiceError::NoPresign => HttpResponse::NotAcceptable().json("Presign Not Requested"),
    }
  }
}

impl From<DBError> for ServiceError {
  fn from(error: DBError) -> ServiceError {
    // Right now we just care about UniqueViolation from diesel
    // But this would be helpful to easily map errors as our app grows
    match error {
      DBError::DatabaseError(kind, info) => {
        if let DatabaseErrorKind::UniqueViolation = kind {
          let message = info.details().unwrap_or_else(|| info.message()).to_string();
          return ServiceError::BadRequest(message);
        }
        ServiceError::InternalServerError
      }
      _ => ServiceError::InternalServerError,
    }
  }
}
