#[macro_use]
extern crate serde_derive;
use pbs_rsa::PublicKey;
use std::collections::HashMap;
use threshold_crypto::PublicKeySet;
#[macro_use]
extern crate prettytable;
use num_bigint_dig::BigUint;
use prettytable::Table;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct Candidates {
  candidates: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
  pub a: String,
  pub m: String,
  pub c: String,
  pub s: String,
}

lazy_static::lazy_static! {
  pub static ref PUBLIC_FILE: String = std::env::var("ENC_PUBLIC").unwrap();
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
  dotenv::dotenv().ok();
  let mut stat = HashMap::new();
  let mut statistics = Table::new();
  let public_key = reqwest::get("http://192.168.16.128:8000/sign_public_key")
    .await?
    .text()
    .await?;
  let public_key = parse_public_key(public_key);
  let public_keyset = parse_public_keyset(&*PUBLIC_FILE);
  let mut unsigned_votes = Table::new();
  unsigned_votes.add_row(row!["Unsigned Votes"]);
  let table = reqwest::get("http://192.168.16.128:8080/")
    .await?
    .text()
    .await?;
  let table = table_extract::Table::find_first(&table).unwrap();
  for row in &table {
    let vote = row.get("m").unwrap_or("<vote missing>");
    let vote: Candidates = serde_json::from_str(vote).unwrap();
    let a = row.get("a").unwrap().to_string();
    let m = row.get("m").unwrap().to_string();
    let c = row.get("c").unwrap().to_string();
    let s = row.get("s").unwrap().to_string();
    let signature = Signature {
      a: a.clone(),
      m: m.clone(),
      c: c.clone(),
      s: s.clone(),
    };
    if verify(signature, &public_key) {
      for candidate in vote.candidates {
        let entry = stat.entry(candidate).or_insert(0);
        *entry += 1;
      }
    } else {
      unsigned_votes.add_row(row![format!(
        "common massage: {}\nvotes: {}\nsignature-c: {}...\nsignature-s: {}...",
        a,
        m,
        &c[..30],
        &s[..30]
      )]);
    }
  }
  statistics.add_row(row!["candidate", "amount"]);
  for (candidate, amount) in stat {
    statistics.add_row(row![candidate, amount]);
  }
  statistics.printstd();
  unsigned_votes.printstd();
  Ok(())
}

fn verify(signature: Signature, public_key: &PublicKey) -> bool {
  let message = signature.m.clone();
  let signature = pbs_rsa::Signature {
    a: signature.a.clone(),
    c: BigUint::from_str(&signature.c).unwrap(),
    s: BigUint::from_str(&signature.s).unwrap(),
  };
  match public_key.verify(message, &signature) {
    Ok(_) => true,
    Err(_) => false,
  }
}

fn parse_public_key(json: String) -> PublicKey {
  #[derive(Debug, Serialize, Deserialize)]
  pub struct PubKey {
    pub e: String,
    pub n: String,
  }
  let public_key: PubKey = serde_json::from_str(&json).unwrap();
  let n = BigUint::from_str(&public_key.n).unwrap();
  let e = BigUint::from_str(&public_key.e).unwrap();
  PublicKey::new(n, e).unwrap()
}

fn parse_public_keyset(path: &String) -> PublicKeySet {
  let mut file = match File::open(path) {
    Ok(f) => f,
    Err(e) => panic!(
      "Error occurred opening file: {} - Err: {}",
      &*PUBLIC_FILE, e
    ),
  };
  let mut s = String::new();
  match file.read_to_string(&mut s) {
    Ok(s) => s,
    Err(e) => panic!("Error Reading file: {}", e),
  };
  let public_key: PublicKeySet = serde_json::from_str(&s).unwrap();
  public_key
}
