use pbs_rsa::{PublicKey, PrivateKey};
use std::fs::{File};
use std::io::Read;

lazy_static::lazy_static! {
  pub static ref BITS: String = std::env::var("KEY_SIZE").unwrap();
  pub static ref PRIVATE_KEY: PrivateKey = {
    let mut rng = rand::thread_rng();
    let bits: usize = BITS.parse().unwrap();
    PrivateKey::new(&mut rng, bits).unwrap()
  };
  pub static ref PUBLIC_KEY: PublicKey = PublicKey::from(&*PRIVATE_KEY);
  
  pub static ref PUBLIC_FILE: String = std::env::var("ENC_PUBLIC").unwrap();
  pub static ref ENC_PUBLIC_KEY: String = {
    let mut file = match File::open(&*PUBLIC_FILE) {
      Ok(f) => f,
      Err(e) => panic!("Error occurred opening file: {} - Err: {}", &*PUBLIC_FILE, e)
    };
    let mut s = String::new();
    match file.read_to_string(&mut s) {
      Ok(s) => s,
      Err(e) => panic!("Error Reading file: {}", e)
    };
    s
  };
}
lazy_static::lazy_static! {
}