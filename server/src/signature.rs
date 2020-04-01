use actix_identity::Identity;
use actix_web::{
  error::BlockingError, web, HttpResponse, Responder, HttpRequest
};
use num_bigint::{RandBigInt, BigUint};
use futures::future::err;
use futures::future::Either;
use futures::Future;
use diesel::prelude::*;
use std::str::FromStr;

use crate::errors::ServiceError;
use crate::models::{
  Pool, User, SlimUser, PreSignRequest, SignRequest, SignResponse, Signature,
  PreSignResponse, PublicKeyResponse
};
use crate::keys::{PUBLIC_KEY, PRIVATE_KEY};
use rand::thread_rng;

pub fn pre_request_sign(
  pre_sign_data: web::Json<PreSignRequest>,
  id: Identity,
) -> Result<HttpResponse, ServiceError> {
  match id.identity().as_ref() {
      Some(identity) => {
          if pre_sign_data.a != "2020-11-28" {
            return Result::Err(ServiceError::UnacceptableDate);
          }
          let user: SlimUser = serde_json::from_str(&identity).unwrap();
          let mut rng = thread_rng();
          let user = SlimUser {
              username: user.username,
              x: rng.gen_biguint_below(&*PUBLIC_KEY.n()).to_string(),
          };
          id.forget();
          id.remember(serde_json::to_string(&user).unwrap());
          let x = PreSignResponse {
            x: user.x,
          };
          Ok(HttpResponse::Ok().body(serde_json::to_string(&x).unwrap()))
      }
      _ => Result::Err(ServiceError::Unauthorized)
  }
}

pub fn request_sign(
  sign_data: web::Json<SignRequest>,
  id: Identity,
  pool: web::Data<Pool>
) -> impl Future<Item = HttpResponse, Error = ServiceError> {
  match id.identity().as_ref() {
      Some(identity) => {
          if sign_data.a != "2020-11-28" {
            return Either::B(err(ServiceError::Unauthorized));
          }
          let user: SlimUser = serde_json::from_str(&identity).unwrap();
          match BigUint::from_str(&user.x) {
            Ok(x) => {
              let (beta_invert, t) = PRIVATE_KEY.sign(
              sign_data.a.clone(),
              BigUint::from_str(&sign_data.alpha).unwrap(),
              BigUint::from_str(&sign_data.beta).unwrap(),
              x
            );
            let signature = SignResponse {
              beta_invert: beta_invert.to_string(),
              t: t.to_string(),
            };
            Either::A(
              web::block(move || query_sign(user, pool)).then(
                move | res: Result<SlimUser, BlockingError<ServiceError>> | match res {
                  Ok(_) => {
                    Ok(HttpResponse::Ok().body(serde_json::to_string(&signature).unwrap()))
                  }
                  Err(err) => match err {
                    BlockingError::Error(service_error) => Err(service_error),
                    BlockingError::Canceled => Err(ServiceError::InternalServerError),
                  },
                }
              )
            )
          }
          Err(_) => {
            Either::B(err(ServiceError::NoPresign))
          }
        }
      }
      _ => Either::B(err(ServiceError::Unauthorized)),
  }
}


fn query_sign(
  auth_data: SlimUser,
  pool: web::Data<Pool>,
) -> Result<SlimUser, ServiceError> {
  use crate::schema::users::dsl::{username, users, has_voted};
  let conn: &SqliteConnection = &pool.get().unwrap();
  let mut items = users
      .filter(username.eq(&auth_data.username))
      .load::<User>(conn)?;
  if let Some(user) = items.pop() {
    if user.has_voted == true {
      return Err(ServiceError::Signed);
    } else {
      let _ = diesel::update(users.find(&auth_data.username))
      .set(has_voted.eq(true))
      .execute(conn)?;
      return Ok(auth_data);
    }
  }
  Err(ServiceError::BadRequest("Username not exist !".into()))
}

pub fn verify(signature: web::Json<Signature>) -> Result<HttpResponse, ServiceError> {
  let message = signature.m.clone();
  let signature = pbs_rsa::Signature {
      a: signature.a.clone(),
      c: BigUint::from_str(&signature.c).unwrap(),
      s: BigUint::from_str(&signature.s).unwrap(),
  };
  match PUBLIC_KEY.verify(message, &signature) {
    Ok(_) => Ok(HttpResponse::Ok().body("Signed Message")),
    Err(_) => Ok(HttpResponse::Ok().body("Unsigned Message"))
  }
}

pub fn public_key(_req: HttpRequest) -> impl Responder {
  let n = &*PUBLIC_KEY.n();
  let e = &*PUBLIC_KEY.e();
  let pubkey = PublicKeyResponse{
    n: n.to_string(),
    e: e.to_string(),
  };
  HttpResponse::Ok().body(serde_json::to_string(&pubkey).unwrap())
}