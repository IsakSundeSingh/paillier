use num::traits::{One, ToPrimitive};
use num::BigInt;

#[derive(PartialEq)]
pub struct PublicKey {
  g: BigInt,
  n: BigInt,
  n_square: BigInt,
}

impl PublicKey {
  fn new(g: BigInt, n: BigInt) -> PublicKey {
    let n_square = (&n) * (&n);
    PublicKey { g, n, n_square }
  }
}

#[derive(PartialEq)]
pub struct PrivateKey {
  p: BigInt,
  q: BigInt,
  p_square: BigInt,
  q_square: BigInt,
}

impl PrivateKey {
  fn new(p: BigInt, q: BigInt) -> PrivateKey {
    let p_square = (&p) * (&p);
    let q_square = (&p) * (&p);
    PrivateKey {
      p,
      q,
      p_square,
      q_square,
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
  assert!(n_square > num::traits::Zero::zero());
  let mut rng = rand::thread_rng();
  let bits = num::bigint::RandomBits::new(n_square.bits());
  let g = rng.sample(bits);
  // If mu doesn't exist the generation failed
  let pmod = power_mod(&g, &lambda, &n_square);
  let l_value = l_function(&pmod, &n);
  let _mu = mod_inv(&l_value, &n)?;
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
    },
  ))
}

#[test]
fn same() {
  let _x = generate_keypair().expect("Generation success");
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
