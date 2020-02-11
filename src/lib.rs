#![forbid(unsafe_code)]

use num::traits::One;
use num::BigInt;

mod math_extensions;
use math_extensions::{gcd, gen_prime, l_function, lcm, mod_inv, power_mod, Modulo};
pub mod types;
pub use types::{CipherText, PlainText, PrivateKey, PublicKey};

/// Generates a keypair for encrypting and decrypting.
///
/// Returns `None` if key generation failed.
///
/// # Examples
///
/// Generating a keypair can be done as follows:
///
/// ```
/// # use paillier::generate_keypair;
/// let (public_key, private_key) = generate_keypair().expect("Key generation failed");
/// ```
pub fn generate_keypair() -> Option<(PublicKey, PrivateKey)> {
  use rand::Rng;

  let bits = 256;
  let p = gen_prime(bits)?;
  let q = gen_prime(bits)?;
  let n = &p * &q;

  assert_eq!(
    gcd(&n, &(&(&p - BigInt::one()) * &(&q - BigInt::one()))),
    BigInt::one()
  );

  let lambda = lcm(&(&p - BigInt::one()), &(&q - BigInt::one()));
  let n_square = &n * &n;

  assert!(n_square > num::traits::Zero::zero());

  let mut rng = rand::thread_rng();
  let bits = num::bigint::RandomBits::new(n_square.bits());
  let g = rng.sample(bits);

  // If mu doesn't exist the generation failed
  let pmod = power_mod(&g, &lambda, &n_square);
  let l_value = l_function(&pmod, &n);
  let mu = mod_inv(&l_value, &n)?;

  Some((
    PublicKey {
      g,
      n: n.clone(),
      n_square: n_square.clone(),
    },
    PrivateKey {
      lambda,
      mu,
      n,
      n_square,
    },
  ))
}

/// Encrypts a given [PlainText](types/struct.PlainText.html) with a given [PublicKey](types/struct.PublicKey.html)
/// and converts it into a [CipherText](types/struct.CipherText.html) on success and returns `None` on failure.
///
/// # Examples
///
/// Values can be encrypted as follows:
///
/// ```
/// # use paillier::{encrypt, generate_keypair, PlainText};
/// let (public_key, _private_key) = generate_keypair().unwrap();
/// let plaintext = PlainText::from(0);
/// let encrypted = encrypt(&plaintext, &public_key).expect("Encryption failed");
/// ```
pub fn encrypt(plaintext: &PlainText, key: &PublicKey) -> Option<CipherText> {
  let PublicKey {
    ref n,
    ref g,
    ref n_square,
  } = key;

  let mut rng = rand::thread_rng();
  use num::bigint::RandBigInt;

  let r = loop {
    let r = rng.gen_bigint(n.bits());
    if gcd(&r, &n) == BigInt::one() && (BigInt::one()..n.clone()).contains(&r) {
      break r;
    }
  };

  assert_eq!(gcd(&r, &n), BigInt::one());

  let PlainText(ref m) = plaintext;
  let c = (power_mod(g, m, n_square) * power_mod(&r, n, n_square)).modulo(n_square);
  CipherText::new(&c, n_square)
}

pub fn decrypt(ciphertext: &CipherText, key: &PrivateKey) -> Option<PlainText> {
  let CipherText {
    data,
    n_square: cipher_n_square,
  } = ciphertext;

  let PrivateKey {
    ref lambda,
    ref mu,
    ref n,
    ref n_square,
  } = key;

  assert_eq!(n_square, cipher_n_square); // Ensure ciphertext was encrypted with corresponding key
  assert!(data < n_square);

  let m = (l_function(&power_mod(data, lambda, &n_square), &n) * mu).modulo(&n);
  PlainText::new(&m, &n)
}

#[test]
fn can_encrypt_and_decrypt() {
  let (public_key, private_key) = generate_keypair().expect("Couldn't generate keypair");
  let plaintext = 123.into();

  let ciphertext = encrypt(&plaintext, &public_key).expect("Couldn't encrypt plaintext");
  let decrypted = decrypt(&ciphertext, &private_key).expect("Couldn't decrypt ciphertext");

  assert_eq!(plaintext, decrypted);
}

#[cfg(test)]
mod tests {
  use super::*;
  use num::traits::ToPrimitive;
  use proptest::prelude::*;

  proptest! {
    #![proptest_config(ProptestConfig { cases: 25, ..ProptestConfig::default() })]

    #[test]
    fn can_add_ciphertexts(x in 0u64..1_000_000, y in 0u64..1_000_000) {
      let p1 = PlainText::from(x);
      let p2 = PlainText::from(y);
      let (public_key, private_key) = generate_keypair().expect("Key generation failed");
      let c1 = encrypt(&p1, &public_key).expect("c1 encryption failed");
      let c2 = encrypt(&p2, &public_key).expect("c2 encryption failed");

      let c = c1 + c2;

      let PlainText(decrypted) = decrypt(&c, &private_key).expect("Couldn't decrypt result!");
      assert_eq!(x + y, decrypted.to_u64().expect("Couldn't convert decrypted result to u64"));
    }

    #[test]
    fn can_multiply_ciphertext_and_plaintext(x in 0u64..1_000_000, y in 0u64..1_000) {
      let p1 = PlainText::from(x);
      let p2 = PlainText::from(y);
      let (public_key, private_key) = generate_keypair().expect("Key generation failed");
      let c1 = encrypt(&p1, &public_key).expect("c1 encryption failed");

      let c = c1 * p2;

      let PlainText(decrypted) = decrypt(&c, &private_key).expect("Couldn't decrypt result!");
      assert_eq!(x * y, decrypted.to_u64().expect("Couldn't convert decrypted result to u64"));
    }
  }
}
