use num::traits::ToPrimitive;
use paillier::*;
use proptest::prelude::*;

#[test]
fn can_encrypt_and_decrypt() {
  let (public_key, private_key) = generate_keypair().expect("Couldn't generate keypair");
  let plaintext = 123.into();

  let ciphertext = encrypt(&plaintext, &public_key).expect("Couldn't encrypt plaintext");
  let decrypted = decrypt(&ciphertext, &private_key).expect("Couldn't decrypt ciphertext");

  assert_eq!(plaintext, decrypted);
}

proptest! {
  #![proptest_config(ProptestConfig { cases: 25, ..ProptestConfig::default() })]

  #[test]
  fn can_add_ciphertexts(x: u64, y: u64) {
    // Ensure that x + y doesn't overflow
    prop_assume!(x.checked_add(y).is_some());

    let p1 = PlainText::from(x);
    let p2 = PlainText::from(y);
    let (public_key, private_key) = generate_keypair().expect("Key generation failed");
    let c1 = encrypt(&p1, &public_key).expect("c1 encryption failed");
    let c2 = encrypt(&p2, &public_key).expect("c2 encryption failed");

    let c = c1 + c2;

    let PlainText(decrypted) = decrypt(&c, &private_key).expect("Couldn't decrypt result!");
    prop_assert_eq!(x + y, decrypted.to_u64().expect("Couldn't convert decrypted result to u64"));
  }

  #[test]
  fn can_multiply_ciphertext_and_plaintext(x in 0u64..1_000_000, y in 0u64..1_000) {
    let p1 = PlainText::from(x);
    let p2 = PlainText::from(y);
    let (public_key, private_key) = generate_keypair().expect("Key generation failed");
    let c1 = encrypt(&p1, &public_key).expect("c1 encryption failed");

    let c = c1.clone() * p2.clone();
    let c_commutative = p2 * c1;

    let PlainText(decrypted) = decrypt(&c, &private_key).expect("Couldn't decrypt result!");
    prop_assert_eq!(x * y, decrypted.to_u64().expect("Couldn't convert decrypted result to u64"));
    prop_assert_eq!(c, c_commutative);
  }


  #[test]
  fn can_subtract_cipertexts(x: u64, y: u64) {
    // Ensure that x - y >= 0
    prop_assume!(x >= y);

    let p1 = PlainText::from(x);
    let p2 = PlainText::from(y);
    let (public_key, private_key) = generate_keypair().expect("Key generation failed");
    let c1 = encrypt(&p1, &public_key).expect("c1 encryption failed");
    let c2 = encrypt(&p2, &public_key).expect("c2 encryption failed");

    let c = c1 - c2;

    let PlainText(decrypted) = decrypt(&c, &private_key).expect("Couldn't decrypt result!");
    prop_assert_eq!(x - y, decrypted.to_u64().expect("Couldn't convert decrypted result to i64"));
  }
}
