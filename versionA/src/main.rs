use std::collections::HashMap;

use ark_bls12_381::*;
use ark_ec::{bls12::Bls12, PairingEngine};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::*;
use ark_std::test_rng;

type UniPoly_381 = DensePolynomial<<Bls12_381 as PairingEngine>::Fr>;

struct RLN {
    limit: u8,
    trusted_setup_params: UniversalParams<Bls12<Parameters>>,
}

impl RLN {
    fn new(limit: u8) -> Self {
        let rng = &mut test_rng();
        let trusted_setup_params =
            KZG10::<Bls12_381, UniPoly_381>::setup(limit as usize, false, rng)
                .expect("Setup failed");

        Self {
            limit,
            trusted_setup_params,
        }
    }
}

struct User {}

impl User {
    fn new() -> Self {
        Self {}
    }

    fn send(&self, message: &str) {
        todo!()
    }
}

fn main() {
    let rln = RLN::new(1);
    let user = User::new();

    // user.send("Hello");
    // user.send("I'm spammer");

    let rng = &mut test_rng();
    let trusted_setup_params =
        KZG10::<Bls12_381, UniPoly_381>::setup(1, false, rng).expect("Setup failed");

    println!("{:#?}", trusted_setup_params);
}
