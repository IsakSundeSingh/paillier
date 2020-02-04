use num::traits::{One, ToPrimitive, Zero};
use num::BigInt;

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
  fn new(m: &BigInt, n: &BigInt) -> Option<Self> {
    if m >= &BigInt::zero() && m < n {
      Some(PlainText(m.clone()))
    } else {
      None
    }
  }
}

#[derive(Debug)]
pub struct CipherText(BigInt);
impl CipherText {
  fn new(c: BigInt, n_square: BigInt) -> Option<Self> {
    if c >= Zero::zero() && c < n_square {
      Some(CipherText(c))
    } else {
      None
    }
  }
}

pub fn generate_keypair() -> Option<(PublicKey, PrivateKey)> {
  use num::bigint::RandBigInt;
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
  let lambda = lcm(&p - BigInt::one(), &q - BigInt::one());
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

fn encrypt(plaintext: &PlainText, key: &PublicKey) -> CipherText {
  use quick_maths::{gcd, power_mod};
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
  let c = (power_mod(g, m, n_square) * power_mod(&r, n, n_square)) % n_square;
  CipherText(c)
}

fn decrypt(ciphertext: &CipherText, key: &PrivateKey) -> Option<PlainText> {
  use quick_maths::{l_function, power_mod};
  let CipherText(c) = ciphertext;
  let PrivateKey {
    ref lambda,
    ref mu,
    ref p,
    ref q,
    ..
  } = key;

  let n = p * q;
  let n_square = &n * &n;

  assert!(c < &n_square);

  let m = (l_function(&power_mod(c, lambda, &n_square), &n) * mu) % &n;
  PlainText::new(&m, &n)
}

#[test]
fn can_encrypt_and_decrypt() {
  use num::traits::FromPrimitive;
  let (public_key, private_key) = generate_keypair().expect("Couldn't generate keypair");
  let plaintext = PlainText::new(&BigInt::from_u64(123).unwrap(), &public_key.n)
    .expect("Couldn't encode plaintext");
  let ciphertext = encrypt(&plaintext, &public_key);
  let decrypted = decrypt(&ciphertext, &private_key);
  if let Some(decrypted_plaintext) = decrypted {
    assert_eq!(plaintext, decrypted_plaintext);
  } else {
    panic!("Error")
  }
}

mod quick_maths {
  use num::traits::{FromPrimitive, One, ToPrimitive, Zero};
  use num::BigInt;
  pub(crate) fn lcm(a: BigInt, b: BigInt) -> BigInt {
    num::integer::lcm(a, b)
  }
  pub(crate) fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    num::integer::gcd(a.clone(), b.clone())
  }
  pub(crate) fn mod_inv(a: &BigInt, b: &BigInt) -> Option<BigInt> {
    let x = mod_inv2(a.clone(), b.clone());
    Some(x)
  }

  fn mod_inv2(a: BigInt, modulus: BigInt) -> BigInt {
    let mut mn = (modulus.clone(), a);
    let mut xy = (BigInt::zero(), BigInt::one());
    while mn.1 != BigInt::zero() {
      let b = (&mn.0) % (&mn.1);
      xy = (xy.1.clone(), (xy.0 - ((&mn.0) / (&mn.1)) * xy.1));
      mn = (mn.1, b);
    }
    while xy.0 < BigInt::zero() {
      xy = (((&xy.0) + (&modulus)), xy.1);
    }
    xy.0
  }

  pub(crate) fn power_mod(a: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
    modular_exponentiation(a, exponent, modulus)
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

  fn modular_exponentiation<T: num::bigint::ToBigInt>(n: &T, e: &T, m: &T) -> BigInt {
    // Convert n, e, and m to BigInt:
    let n = n.to_bigint().unwrap();
    let e = e.to_bigint().unwrap();
    let m = m.to_bigint().unwrap();
    // Sanity check:  Verify that the exponent is not negative:
    assert!(e >= Zero::zero());

    // As most modular exponentiations do, return 1 if the exponent is 0:
    if e == Zero::zero() {
      return One::one();
    }
    // Now do the modular exponentiation algorithm:
    let mut result: BigInt = One::one();
    let mut base = n % &m;
    let mut exp = e;
    // Loop until we can return out result:
    macro_rules! two {
      () => {
        BigInt::from_u64(2).unwrap()
      };
    }
    loop {
      if &exp % two!() == One::one() {
        result *= &base;
        result %= &m;
      }

      if exp == One::one() {
        return result;
      }

      exp /= two!();
      base *= base.clone();
      base %= &m;
    }
  }

  #[cfg(test)]
  mod tests {
    use super::*;
    use proptest::prelude::*;

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
