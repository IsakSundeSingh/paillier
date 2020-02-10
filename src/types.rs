use num::traits::Zero;
use num::BigInt;
use std::ops::{Add, Mul};

use crate::math_extensions::{power_mod, Modulo};

#[derive(PartialEq)]
pub struct PublicKey {
  pub(crate) g: BigInt,
  pub n: BigInt,
  pub(crate) n_square: BigInt,
}

#[derive(PartialEq)]
pub struct PrivateKey {
  pub(crate) n: BigInt,
  pub(crate) n_square: BigInt,
  pub(crate) lambda: BigInt,
  pub(crate) mu: BigInt,
}

#[derive(Debug, PartialEq)]
pub struct PlainText(pub(crate) BigInt);
impl PlainText {
  pub fn new(m: &BigInt, n: &BigInt) -> Option<Self> {
    if *m >= BigInt::zero() && m < n {
      Some(PlainText(m.clone()))
    } else {
      None
    }
  }
}

#[derive(Debug)]
pub struct CipherText {
  pub(crate) data: BigInt,
  pub(crate) n_square: BigInt,
}
impl CipherText {
  pub(crate) fn new(c: &BigInt, n_square: &BigInt) -> Option<Self> {
    if *c >= Zero::zero() && c < n_square {
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

  #[allow(clippy::suspicious_arithmetic_impl)]
  fn add(self, rhs: Self) -> <Self as Add<Self>>::Output {
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
    let PlainText(p) = rhs;
    // TODO: Assert that ciphertext and plaintext are generated using the same keyset
    CipherText {
      data: power_mod(&self.data, &p, &self.n_square),
      ..self
    }
  }
}
