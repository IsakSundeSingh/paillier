use num::traits::{One, Zero};
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
    xy = (xy.1.clone(), xy.0 - (&mn.0 / &mn.1) * xy.1);
    mn = (mn.1, b);
  }
  while xy.0 < BigInt::zero() {
    xy = (&xy.0 + &modulus, xy.1);
  }
  xy.0
}

pub(crate) fn power_mod(a: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
  a.modpow(exponent, modulus)
}

pub fn div(a: &BigInt, b: &BigInt) -> BigInt {
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
  use num::traits::FromPrimitive;

  #[test]
  fn div_works() {
    let a = BigInt::from_u64(10).unwrap();
    let b = BigInt::from_u64(3).unwrap();
    let v = div(&a, &b);
    assert_ne!(a, (&v + BigInt::one()) * &b);
    assert!(a >= v * b);
  }
}
