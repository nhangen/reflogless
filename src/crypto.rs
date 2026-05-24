use crate::error::{Error, Result};
use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use std::io::{Read, Write};
use std::str::FromStr;

pub fn generate_identity() -> Identity {
    Identity::generate()
}

pub fn identity_to_string(identity: &Identity) -> String {
    identity.to_string().expose_secret().to_string()
}

pub fn parse_identity(s: &str) -> Result<Identity> {
    Identity::from_str(s.trim()).map_err(|e| Error::Keychain(format!("parsing identity: {e}")))
}

pub fn recipient_of(identity: &Identity) -> Recipient {
    identity.to_public()
}

pub fn parse_recipient(s: &str) -> Result<Recipient> {
    Recipient::from_str(s.trim()).map_err(|e| Error::Encryption(format!("parsing recipient: {e}")))
}

pub fn encrypt(plaintext: &[u8], recipient: &Recipient) -> Result<Vec<u8>> {
    let recipients: Vec<&dyn age::Recipient> = vec![recipient];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|e| Error::Encryption(format!("building encryptor: {e}")))?;
    let mut out = Vec::with_capacity(plaintext.len() + 256);
    let mut w = encryptor
        .wrap_output(&mut out)
        .map_err(|e| Error::Encryption(e.to_string()))?;
    w.write_all(plaintext)
        .map_err(|e| Error::Encryption(e.to_string()))?;
    w.finish().map_err(|e| Error::Encryption(e.to_string()))?;
    Ok(out)
}

pub fn decrypt(ciphertext: &[u8], identity: &Identity) -> Result<Vec<u8>> {
    let decryptor =
        age::Decryptor::new(ciphertext).map_err(|e| Error::Decryption(e.to_string()))?;
    if decryptor.is_scrypt() {
        return Err(Error::Decryption(
            "ciphertext uses passphrase recipient; expected x25519".into(),
        ));
    }
    let identities: [&dyn age::Identity; 1] = [identity];
    let mut r = decryptor
        .decrypt(identities.into_iter())
        .map_err(|e| Error::Decryption(e.to_string()))?;
    let mut out = Vec::new();
    r.read_to_end(&mut out)
        .map_err(|e| Error::Decryption(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_random_payloads() {
        let id = generate_identity();
        let rcp = recipient_of(&id);
        for payload in &[
            b"".to_vec(),
            b"x".to_vec(),
            b"hello world\n".to_vec(),
            (0..1024u16).map(|n| (n & 0xFF) as u8).collect::<Vec<_>>(),
        ] {
            let ct = encrypt(payload, &rcp).unwrap();
            assert_ne!(&ct, payload, "ciphertext must differ from plaintext");
            let pt = decrypt(&ct, &id).unwrap();
            assert_eq!(&pt, payload);
        }
    }

    #[test]
    fn wrong_identity_fails_to_decrypt() {
        let id_a = generate_identity();
        let id_b = generate_identity();
        let ct = encrypt(b"secret", &recipient_of(&id_a)).unwrap();
        assert!(matches!(decrypt(&ct, &id_b), Err(Error::Decryption(_))));
    }

    #[test]
    fn identity_serialization_roundtrips() {
        let id = generate_identity();
        let s = identity_to_string(&id);
        let parsed = parse_identity(&s).unwrap();
        let ct = encrypt(b"abc", &recipient_of(&parsed)).unwrap();
        let pt = decrypt(&ct, &id).unwrap();
        assert_eq!(pt, b"abc");
    }

    #[test]
    fn parse_identity_rejects_garbage() {
        assert!(parse_identity("").is_err());
        assert!(parse_identity("not-an-age-key").is_err());
    }

    #[test]
    fn parse_recipient_rejects_garbage() {
        assert!(parse_recipient("").is_err());
        assert!(parse_recipient("not-a-recipient").is_err());
    }

    #[test]
    fn decrypt_rejects_passphrase_ciphertext() {
        // Build a passphrase-encrypted age payload and confirm we reject it
        // rather than wandering past `is_scrypt()` and trying x25519 unwrap.
        use age::scrypt::Recipient as ScryptRecipient;
        use age::secrecy::SecretString;
        let passphrase = SecretString::from("pw");
        let rcp = ScryptRecipient::new(passphrase);
        let recipients: Vec<&dyn age::Recipient> = vec![&rcp];
        let encryptor = age::Encryptor::with_recipients(recipients.into_iter()).unwrap();
        let mut ct = Vec::new();
        let mut w = encryptor.wrap_output(&mut ct).unwrap();
        w.write_all(b"hello").unwrap();
        w.finish().unwrap();
        let id = generate_identity();
        match decrypt(&ct, &id) {
            Err(Error::Decryption(msg)) => assert!(msg.contains("passphrase")),
            other => panic!("expected Decryption(passphrase...), got {other:?}"),
        }
    }

    #[test]
    fn recipient_serialization_roundtrips() {
        let id = generate_identity();
        let rcp_str = recipient_of(&id).to_string();
        let rcp = parse_recipient(&rcp_str).unwrap();
        let ct = encrypt(b"abc", &rcp).unwrap();
        assert_eq!(decrypt(&ct, &id).unwrap(), b"abc");
    }
}
