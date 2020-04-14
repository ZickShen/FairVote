use crate::models::Ballot;
use actix_web::{HttpRequest, HttpResponse, Responder};
use std::fs::File;
use std::io::Read;

lazy_static::lazy_static! {
  pub static ref BALLOT_FILE: String = std::env::var("BALLOT").unwrap();
  pub static ref BALLOT: Ballot = {
    let mut file = match File::open(&*BALLOT_FILE) {
      Ok(f) => f,
      Err(e) => panic!("Error occurred opening file: {} - Err: {}", &*BALLOT_FILE, e)
    };
    let mut s = String::new();
    match file.read_to_string(&mut s) {
          Ok(s) => s
        , Err(e) => panic!("Error Reading file: {}", e)
    };
    let ballot: Ballot = toml::from_str(&s).unwrap();
    ballot
  };
}

pub fn display_ballot(_req: HttpRequest) -> impl Responder {
  HttpResponse::Ok().body(serde_json::to_string(&&*BALLOT).unwrap())
}
