#[macro_use]
extern crate serde_derive;
use pbs_rsa::PublicKey;
use std::collections::HashMap;
use threshold_crypto::{Ciphertext, PublicKeySet, SecretKeyShare};
#[macro_use]
extern crate prettytable;
use num_bigint_dig::BigUint;
use prettytable::Table;
use std::fs::File;
use std::str::FromStr;

mod decrypt;
use decrypt::{send_msg, Actor, SecretSociety};

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
  pub static ref ACTOR_STR: String = std::env::var("ACTOR").unwrap();
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
  dotenv::dotenv().ok();
  let actor: usize = ACTOR_STR.parse().unwrap();
  let mut stat: HashMap<String, usize> = HashMap::new();
  let mut statistics = Table::new();
  let public_key = reqwest::get("http://192.168.16.128:8000/sign_public_key")
    .await?
    .text()
    .await?;
  let public_key = parse_public_key(public_key);
  let public_keyset: PublicKeySet = parse_key_file(&*PUBLIC_FILE);
  let mut actors: Vec<Actor> = Vec::new();
  for i in 0..actor {
    let sk_share: SecretKeyShare = parse_key_file(&format!("private_{}.key", i));
    let actor = Actor::new(i, sk_share);
    actors.push(actor);
  }
  let mut society = SecretSociety::new(actors, public_keyset);
  let mut unsigned_votes = Table::new();
  unsigned_votes.add_row(row!["Unsigned Votes"]);
  let mut decrypt_failed_votes = Table::new();
  decrypt_failed_votes.add_row(row!["Decryption Failed Votes"]);
  let table = reqwest::get("http://192.168.16.128:8080/")
    .await?
    .text()
    .await?;
  let table = table_extract::Table::find_first(&table).unwrap();
  for row in &table {
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
      let cipher: Ciphertext = match serde_json::from_str(&m) {
        Ok(c) => c,
        Err(_) => {
          add_failed_vote(&mut decrypt_failed_votes, &a, &m, &c, &s);
          continue;
        }
      };
      let mut meeting = society.start_decryption_meeting();
      for id in 0..actor {
        send_msg(society.get_actor(id), cipher.clone());
        meeting.accept_decryption_share(society.get_actor(id));
      }
      let res = meeting.decrypt_message().unwrap();
      let vote = match std::str::from_utf8(&res) {
        Ok(v) => v,
        Err(_) => {
          add_failed_vote(&mut decrypt_failed_votes, &a, &m, &c, &s);
          continue;
        }
      };
      let vote = match serde_json::from_str::<Candidates>(vote) {
        Ok(v) => v,
        Err(_) => {
          add_failed_vote(&mut decrypt_failed_votes, &a, &m, &c, &s);
          continue;
        }
      };
      for candidate in vote.candidates {
        let entry = stat.entry(candidate).or_insert(0);
        *entry += 1;
      }
    } else {
      add_failed_vote(&mut unsigned_votes, &a, &m, &c, &s);
    }
  }
  statistics.add_row(row!["candidate", "amount"]);
  for (candidate, amount) in stat {
    statistics.add_row(row![candidate, amount]);
  }
  statistics.printstd();
  unsigned_votes.printstd();
  decrypt_failed_votes.printstd();
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

fn parse_key_file<T>(path: &String) -> T
where
  T: serde::de::DeserializeOwned,
{
  let file = match File::open(path) {
    Ok(f) => f,
    Err(e) => panic!("Error occurred opening file: {} - Err: {}", path, e),
  };
  let reader = std::io::BufReader::new(file);
  let public_key: T = serde_json::from_reader(reader).unwrap();
  public_key
}

fn add_failed_vote(table: &mut Table, a: &String, m: &String, c: &String, s: &String) {
  let m = if m.len() <= 30 {
    m.clone()
  } else {
    format!("{}...", &m[..30])
  };
  let c = if c.len() <= 30 {
    c.clone()
  } else {
    format!("{}...", &c[..30])
  };
  let s = if s.len() <= 30 {
    s.clone()
  } else {
    format!("{}...", &s[..30])
  };
  table.add_row(row![format!(
    "common massage: {}\nvotes: {}\nsignature-c: {}\nsignature-s: {}",
    a, m, c, s
  )]);
}
