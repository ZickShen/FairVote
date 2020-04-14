
use threshold_crypto::{PublicKeySet, Ciphertext, SecretKeyShare, PublicKeyShare, DecryptionShare};
use std::collections::BTreeMap;

pub struct SecretSociety {
  actors: Vec<Actor>,
  pk_set: PublicKeySet,
}

impl SecretSociety {
  pub fn new(actors: Vec<Actor>, pk_set: PublicKeySet) -> Self {
      SecretSociety { actors, pk_set }
  }

  pub fn get_actor(&mut self, id: usize) -> &mut Actor {
      self.actors
          .get_mut(id)
          .expect("No `Actor` exists with that ID")
  }
  // the ciphertext.
  pub fn start_decryption_meeting(&self) -> DecryptionMeeting {
      DecryptionMeeting {
          pk_set: self.pk_set.clone(),
          ciphertext: None,
          dec_shares: BTreeMap::new(),
      }
  }
}

// A member of the secret society.
#[derive(Clone, Debug)]
pub struct Actor {
  id: usize,
  sk_share: SecretKeyShare,
  pk_share: PublicKeyShare,
  msg_inbox: Option<Ciphertext>,
}

impl Actor {
  pub fn new(id: usize, sk_share: SecretKeyShare) -> Self {
    let pk_share = sk_share.public_key_share();
    Actor {
        id,
        sk_share,
        pk_share,
        msg_inbox: None,
    }
  }
}

// Sends an encrypted message to an `Actor`.
pub fn send_msg(actor: &mut Actor, enc_msg: Ciphertext) {
  actor.msg_inbox = Some(enc_msg);
}

// A meeting of the secret society. At this meeting, actors collaborate to decrypt a shared
// ciphertext.
pub struct DecryptionMeeting {
  pk_set: PublicKeySet,
  ciphertext: Option<Ciphertext>,
  dec_shares: BTreeMap<usize, DecryptionShare>,
}

impl DecryptionMeeting {
  // An actor contributes their decryption share to the decryption process.
  pub fn accept_decryption_share(&mut self, actor: &mut Actor) {
      let ciphertext = actor.msg_inbox.take().unwrap();

      // Check that the actor's ciphertext is the same ciphertext decrypted at the meeting.
      // The first actor to arrive at the decryption meeting sets the meeting's ciphertext.
      if let Some(ref meeting_ciphertext) = self.ciphertext {
          if ciphertext != *meeting_ciphertext {
              return;
          }
      } else {
          self.ciphertext = Some(ciphertext.clone());
      }

      let dec_share = actor.sk_share.decrypt_share(&ciphertext).unwrap();
      let dec_share_is_valid = actor
          .pk_share
          .verify_decryption_share(&dec_share, &ciphertext);
      assert!(dec_share_is_valid);
      self.dec_shares.insert(actor.id, dec_share);
  }

  // Tries to decrypt the shared ciphertext using the decryption shares.
  pub fn decrypt_message(&self) -> Result<Vec<u8>, ()> {
      let ciphertext = self.ciphertext.clone().unwrap();
      self.pk_set
          .decrypt(&self.dec_shares, &ciphertext)
          .map_err(|_| ())
  }
}