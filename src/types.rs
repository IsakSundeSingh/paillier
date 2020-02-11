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

/// Type representing a PlainText
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
  type Output = Self;

  /// Homomorphically adds two ciphertexts so that the resulting ciphertext represents the sum of the underlying plaintexts.
  ///
  /// # Panics
  ///
  /// Will panic if the two ciphertexts are not encrypted using the same keyset.
  ///
  /// # Examples
  ///
  /// Correct use:
  /// ```
  /// # use paillier::{generate_keypair, encrypt, decrypt, PlainText};
  /// let (public_key, private_key) = generate_keypair().unwrap();
  /// let c1 = encrypt(&PlainText::from(1), &public_key).unwrap();
  /// let c2 = encrypt(&PlainText::from(1), &public_key).unwrap();
  ///
  /// let c = c1 + c2;
  ///
  /// let decrypted = decrypt(&c, &private_key).unwrap();
  ///
  /// assert_eq!(decrypted, PlainText::from(2));
  /// ```
  ///
  /// Incorrect use:
  /// ```should_panic
  /// # use paillier::{generate_keypair, encrypt, PlainText};
  /// # let (public_key1, _private_key1) = generate_keypair().expect("Key generation failed");
  /// # let (public_key2, _private_key2) = generate_keypair().expect("Key generation failed");
  /// let c1 = encrypt(&PlainText::from(1), &public_key1).expect("Encryption failed");
  /// let c2 = encrypt(&PlainText::from(1), &public_key2).expect("Encryption failed");
  ///
  /// let c = c1 + c2; // panics!
  ///
  /// ```
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

    // Ensure ciphertexts were encrypted with the same keys
    assert_eq!(&c1_n_square, &c2_n_square);

    CipherText {
      data: (c1 * c2).modulo(&c1_n_square),
      n_square: c1_n_square.clone(),
    }
  }
}

impl Mul<PlainText> for CipherText {
  type Output = Self;

  /// Homomorphically multiplies two a ciphertext with a plaintext so that the resulting ciphertext represents the product of the underlying plaintext and the given plaintext.
  ///
  /// # Examples
  ///
  /// ```
  /// # use paillier::{generate_keypair, encrypt, decrypt, PlainText};
  /// let (public_key, private_key) = generate_keypair().unwrap();
  /// let c = encrypt(&PlainText::from(2), &public_key).unwrap();
  /// let p = PlainText::from(3);
  ///
  /// let c = c * p;
  ///
  /// let decrypted = decrypt(&c, &private_key).unwrap();
  ///
  /// assert_eq!(decrypted, PlainText::from(6));
  /// ```
  fn mul(self, rhs: PlainText) -> <Self as Mul<PlainText>>::Output {
    let PlainText(p) = rhs;
    // TODO: If p is negative, perhaps find modular inverse and complete multiplication?
    // TODO: Assert that ciphertext and plaintext are generated using the same keyset
    CipherText {
      data: power_mod(&self.data, &p, &self.n_square),
      ..self
    }
  }
}

mod impls {
  use super::PlainText;
  use doc_comment::doc_comment;

  macro_rules! impl_from_for_single_plaintext {
    ($t: ty) => {
      paste::item! {
        impl ::std::convert::From<$t> for PlainText {
          doc_comment!{
            concat!("Convert from `", stringify!($t), "` to a `PlainText`
              Note: This is a raw conversion and the `PlainText` value may potentially be invalid in use if
              `x` is not in the range `0 < x < n`, where `n` is the public modulus of the encryption scheme.
              `x >= n` is unlikely as for the scheme to be secure `n` should be `512` bits or larger while any
              primitive type is always 128 bit or less."
            ),
            fn from(x: $t) -> Self {
              use num::BigInt;
              use num::traits::FromPrimitive;

              PlainText(
                BigInt::[<from_ $t>](x).unwrap()
              )
            }
          }
        }
      }
    };
  }

  macro_rules! impl_from_for_plaintext {
    ($($t:ty),+) => {
      $(
        impl_from_for_single_plaintext!($t);
      )+
    };
  }

  impl_from_for_plaintext!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);
}
