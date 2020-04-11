use threshold_crypto::{serde_impl::SerdeSecret, SecretKeySet};
use std::{
    fs::File,
    io::{BufWriter, Write},
};

lazy_static::lazy_static! {
    pub static ref THRESHOLD_STR: String = std::env::var("THRESHOLD").unwrap();
    pub static ref ACTOR_STR: String = std::env::var("ACTOR").unwrap();
    
}
fn main() {
    dotenv::dotenv().ok();
    let threshold: usize = THRESHOLD_STR.parse().unwrap();
    let actor: usize = ACTOR_STR.parse().unwrap();
    if actor < threshold {
        panic!("Actors is small than threshold!")
    }
    let mut rng = rand::thread_rng();
    let sks = SecretKeySet::random(threshold, &mut rng);
    let pk = sks.public_keys().public_key();

    let public_key_file = File::create("pub.key").unwrap();
    let mut writer = BufWriter::new(&public_key_file);
    match write!(&mut writer, "{}", serde_json::to_string(&pk).unwrap()) {
        Ok(_)=> (),
        Err(err)=> panic!(err),
    };

    for i in 0..actor{
        let sk_share = sks.secret_key_share(i);
        let share_key_file = File::create(format!("private_{}.key", i)).unwrap();
        let mut writer = BufWriter::new(&share_key_file);
        match write!(&mut writer, "{}", serde_json::to_string(&SerdeSecret(sk_share)).unwrap()) {
            Ok(_)=> (),
            Err(err)=> panic!(err),
        };
    }
}