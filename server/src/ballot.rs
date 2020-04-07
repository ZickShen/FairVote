use crate::models::Ballot;
use std::fs::{File};
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
