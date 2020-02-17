#![forbid(unsafe_code)]

use num::traits::One;
use num::BigInt;

mod math_extensions;
use math_extensions::{gcd, gen_prime, l_function, lcm, mod_inv, power_mod, Modulo};
mod types;
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

  // Ensure ciphertext was encrypted with corresponding key
  assert_eq!(n_square, cipher_n_square);
  assert!(data < n_square);

  let m = (l_function(&power_mod(data, lambda, &n_square), &n) * mu).modulo(&n);
  PlainText::new(&m, &n)
}
