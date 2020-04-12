use threshold_crypto::{PublicKey};

fn main() {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).expect("Did not enter a correct string");
    s = s.trim_end_matches("\n").to_string();
    let public_key: PublicKey = serde_json::from_str(&s).unwrap();
    std::io::stdin().read_line(&mut s).expect("Did not enter a correct string");
    s = s.trim_end_matches("\n").to_string();
    let cipher = public_key.encrypt(s);
    println!("{}", serde_json::to_string(&cipher).unwrap());
}
