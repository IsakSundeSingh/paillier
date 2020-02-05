use num::traits::{One, Zero};
use num::BigInt;
use std::ops::{Add, Mul};

#[derive(PartialEq)]
pub struct PublicKey {
  g: BigInt,
  n: BigInt,
  n_square: BigInt,
}

#[derive(PartialEq)]
pub struct PrivateKey {
  p: BigInt,
  q: BigInt,
  p_square: BigInt,
  q_square: BigInt,
  lambda: BigInt,
  mu: BigInt,
}

#[derive(Debug, PartialEq)]
pub struct PlainText(BigInt);
impl PlainText {
  pub fn new(m: &BigInt, n: &BigInt) -> Option<Self> {
    if m >= &BigInt::zero() && m < n {
      Some(PlainText(m.clone()))
    } else {
      None
    }
  }
}

#[derive(Debug)]
pub struct CipherText {
  data: BigInt,
  n_square: BigInt,
}
impl CipherText {
  fn new(c: &BigInt, n_square: &BigInt) -> Option<Self> {
    if c >= &Zero::zero() && c < n_square {
      Some(CipherText {
        data: c.clone(),
        n_square: n_square.clone(),
      })
    } else {
      None
    }
  }
}

impl Add<CipherText> for CipherText {
  type Output = CipherText;
  fn add(self, rhs: Self) -> <Self as Add<Self>>::Output {
    use quick_maths::Modulo;

    let CipherText {
      data: c1,
      n_square: c1_n_square,
    } = self;

    let CipherText {
      data: c2,
      n_square: c2_n_square,
    } = rhs;
    assert_eq!(&c1_n_square, &c2_n_square); // Ensure ciphertexts were encrypted with the same keys

    CipherText {
      data: (c1 * c2).modulo(&c1_n_square),
      n_square: c1_n_square.clone(),
    }
  }
}

impl Mul<PlainText> for CipherText {
  type Output = Self;
  fn mul(self, rhs: PlainText) -> <Self as Mul<PlainText>>::Output {
    use quick_maths::power_mod;

    let PlainText(p) = rhs;
    // TODO: Assert that ciphertext and plaintext are generated using the same keyset
    CipherText {
      data: power_mod(&self.data, &p, &self.n_square),
      ..self
    }
  }
}

pub fn generate_keypair() -> Option<(PublicKey, PrivateKey)> {
  use quick_maths::*;
  use rand::Rng;
  let bits = 256;
  let p = gen_prime(bits)?;
  let q = gen_prime(bits)?;
  let n = (&p) * (&q);
  assert_eq!(
    gcd(&n, &(&(&p - BigInt::one()) * &(&q - BigInt::one()))),
    BigInt::one()
  );
  let lambda = lcm(&(&p - BigInt::one()), &(&q - BigInt::one()));
  let n_square = (&n) * (&n);
  assert!(&n_square > &num::traits::Zero::zero());
  let mut rng = rand::thread_rng();
  let bits = num::bigint::RandomBits::new(n_square.bits());
  let g = rng.sample(bits);
  // If mu doesn't exist the generation failed
  let pmod = power_mod(&g, &lambda, &n_square);
  let l_value = l_function(&pmod, &n);
  let mu = mod_inv(&l_value, &n)?;
  //.expect(&format!("n ({}) does not divide g ({})", n, g));
  let p_square = (&p) * (&p);
  let q_square = (&q) * (&q);
  Some((
    PublicKey { g, n, n_square },
    PrivateKey {
      p,
      q,
      p_square,
      q_square,
      lambda,
      mu,
    },
  ))
}

pub fn encrypt(plaintext: &PlainText, key: &PublicKey) -> Option<CipherText> {
  use quick_maths::{gcd, power_mod, Modulo};
  let PublicKey {
    ref n,
    ref g,
    ref n_square,
    ..
  } = key;
  // FIXME: This is not random at all! Need to choose r s.t. 0 < r < n, with gcd(r,n) = 1
  let mut r = n - BigInt::one();
  while gcd(&r, &n) != One::one() {
    r -= BigInt::one();
  }
  let r = r;
  assert_eq!(gcd(&r, &n), BigInt::one());

  let PlainText(ref m) = plaintext;
  let c = (power_mod(g, m, n_square) * power_mod(&r, n, n_square)).modulo(n_square);
  CipherText::new(&c, n_square)
}

pub fn decrypt(ciphertext: &CipherText, key: &PrivateKey) -> Option<PlainText> {
  use quick_maths::{l_function, power_mod, Modulo};
  let CipherText {
    data,
    n_square: cipher_n_square,
  } = ciphertext;
  let PrivateKey {
    ref lambda,
    ref mu,
    ref p,
    ref q,
    ..
  } = key;

  let n = p * q;
  let n_square = &n * &n;

  assert_eq!(&n_square, cipher_n_square); // Ensure ciphertext was encrypted with corresponding key
  assert!(data < &n_square);

  let m = (l_function(&power_mod(data, lambda, &n_square), &n) * mu).modulo(&n);
  PlainText::new(&m, &n)
}

#[test]
fn can_encrypt_and_decrypt() {
  use num::traits::FromPrimitive;
  let (public_key, private_key) = generate_keypair().expect("Couldn't generate keypair");
  let plaintext = PlainText::new(&BigInt::from_u64(123).unwrap(), &public_key.n)
    .expect("Couldn't encode plaintext");
  let ciphertext = encrypt(&plaintext, &public_key).expect("Couldn't encrypt plaintext");
  let decrypted = decrypt(&ciphertext, &private_key).expect("Couldn't decrypt ciphertext");
  assert_eq!(plaintext, decrypted);
}

#[cfg(test)]
mod tests {
  use super::*;
  use num::traits::{FromPrimitive, ToPrimitive};
  use proptest::prelude::*;
  proptest! {
    #![proptest_config(ProptestConfig { cases: 10, ..ProptestConfig::default() })]

    #[test]
    fn can_add_ciphertexts(x in 0u64..1_000_000, y in 0u64..1_000_000) {
      let p1 = PlainText(BigInt::from_u64(x).unwrap());
      let p2 = PlainText(BigInt::from_u64(y).unwrap());
      let (public_key, private_key) = generate_keypair().expect("Key generation failed");
      let c1 = encrypt(&p1, &public_key).expect("c1 encryption failed");
      let c2 = encrypt(&p2, &public_key).expect("c2 encryption failed");
      let c = c1 + c2;
      let PlainText(decrypted) = decrypt(&c, &private_key).expect("Couldn't decrypt result!");
      assert_eq!(x + y, decrypted.to_u64().expect("Couldn't convert decrypted result to u64"));
    }

    #[test]
    fn can_multiply_ciphertext_and_plaintext(x in 0u64..1_000_000, y in 0u64..1_000) {
      let p1 = PlainText(BigInt::from_u64(x).unwrap());
      let p2 = PlainText(BigInt::from_u64(y).unwrap());
      let (public_key, private_key) = generate_keypair().expect("Key generation failed");
      let c1 = encrypt(&p1, &public_key).expect("c1 encryption failed");
      let c = c1 * p2;
      let PlainText(decrypted) = decrypt(&c, &private_key).expect("Couldn't decrypt result!");
      assert_eq!(x * y, decrypted.to_u64().expect("Couldn't convert decrypted result to u64"));
    }
  }
}

mod quick_maths {
  use num::traits::{FromPrimitive, One, Zero};
  use num::BigInt;
  pub(crate) fn lcm(a: &BigInt, b: &BigInt) -> BigInt {
    num::integer::lcm(a.clone(), b.clone())
  }
  pub(crate) fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    num::integer::gcd(a.clone(), b.clone())
  }
  pub(crate) fn mod_inv(a: &BigInt, b: &BigInt) -> Option<BigInt> {
    let x = mod_inv2(a.clone(), b.clone());
    // TODO: Fix modular inverse possibly being non-existent
    Some(x)
  }

  fn mod_inv2(a: BigInt, modulus: BigInt) -> BigInt {
    let mut mn = (modulus.clone(), a);
    let mut xy = (BigInt::zero(), BigInt::one());
    while mn.1 != BigInt::zero() {
      let b = (&mn.0).modulo(&mn.1);
      xy = (xy.1.clone(), (xy.0 - ((&mn.0) / (&mn.1)) * xy.1));
      mn = (mn.1, b);
    }
    while xy.0 < BigInt::zero() {
      xy = (((&xy.0) + (&modulus)), xy.1);
    }
    xy.0
  }

  pub(crate) fn power_mod(a: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
    a.modpow(exponent, modulus)
  }

  pub(crate) fn div(a: &BigInt, b: &BigInt) -> BigInt {
    let (quotient, _remainder) = num::Integer::div_rem(a, b);
    quotient
  }

  pub(crate) fn l_function(x: &BigInt, n: &BigInt) -> BigInt {
    div(&(x - BigInt::one()), n)
  }

  pub(crate) fn gen_prime(bits: usize) -> Option<BigInt> {
    glass_pumpkin::prime::new(bits)
      .ok()
      .map(|big| BigInt::from_biguint(num::bigint::Sign::Plus, big))
  }

  pub trait Modulo<RHS = Self> {
    type Output;
    fn modulo(&self, rhs: &RHS) -> Self::Output;
  }
  impl Modulo<BigInt> for BigInt {
    type Output = BigInt;
    fn modulo(&self, rhs: &BigInt) -> Self::Output {
      use num::traits::sign::Signed;
      let r = self % rhs;
      if r < BigInt::zero() {
        r + rhs.abs()
      } else {
        r
      }
    }
  }

  #[cfg(test)]
  mod tests {
    use super::*;

    #[test]
    fn div_works() {
      let a = BigInt::from_u64(10).unwrap();
      let b = BigInt::from_u64(3).unwrap();
      let v = div(&a, &b);
      assert_ne!(a, (&v + BigInt::one()) * &b);
      assert!(a >= v * b);
    }
  }
}
