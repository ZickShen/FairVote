use pbs_rsa::{PublicKey, PrivateKey};

lazy_static::lazy_static! {
  pub static ref BITS: String = std::env::var("KEY_SIZE").unwrap();
  pub static ref PRIVATE_KEY: PrivateKey = {
    let mut rng = rand::thread_rng();
    let bits: usize = BITS.parse().unwrap();
    PrivateKey::new(&mut rng, bits).unwrap()
  };
  pub static ref PUBLIC_KEY: PublicKey = PublicKey::from(&*PRIVATE_KEY);
}