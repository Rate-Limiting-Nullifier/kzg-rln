#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use std::collections::HashMap;

use ark_bls12_381::*;
use ark_ec::PairingEngine;
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_poly_commit::kzg10::*;
use ark_std::test_rng;

use once_cell::sync::Lazy;

type UniPoly_381 = DensePolynomial<<Bls12_381 as PairingEngine>::Fr>;
type KZG = KZG10<Bls12_381, UniPoly_381>;

const EPOCH_LIMIT: u8 = 1;
const DEGREE: usize = EPOCH_LIMIT as usize;

static KEYS: Lazy<(Powers<Bls12_381>, VerifierKey<Bls12_381>)> = Lazy::new(|| {
    let rng = &mut test_rng();
    let pp = KZG::setup(DEGREE, true, rng).unwrap();

    let powers_of_g = pp.powers_of_g.clone();
    let powers_of_gamma_g = vec![pp.powers_of_gamma_g[&0], pp.powers_of_gamma_g[&1]];

    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };

    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[&0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };

    (powers, vk)
});

struct RLN {
    limit: u8,
    shares: HashMap<Commitment<Bls12_381>, Vec<Fr>>,
}

impl RLN {
    fn new(limit: u8) -> Self {
        let rng = &mut test_rng();

        Self {
            limit,
            shares: HashMap::new(),
        }
    }

    // fn register()

    fn add(&mut self) {
        todo!()
    }
}

struct User {
    polynomial: UniPoly_381,
}

impl User {
    fn new(degree: usize) -> Self {
        let rng = &mut test_rng();
        let polynomial = UniPoly_381::rand(degree, rng);

        Self { polynomial }
    }

    fn secret(&self) -> Fr {
        self.polynomial.evaluate(&Fr::from(0))
    }

    fn register(&self, rln: &mut RLN) {
        let rng = &mut test_rng();
        let (comm, rand) = KZG::commit(&KEYS.0, &self.polynomial, None, None).unwrap();

        let proof = KZG::open(&KEYS.0, &self.polynomial, Fr::from(0), &rand).unwrap();

        assert!(KZG::check(&KEYS.1, &comm, Fr::from(0), value, proof));
    }

    // fn send(&self, message: &str, rln: &mut RLN) {
    //     rln.add();
    //     todo!()
    // }
}

fn main() {
    let mut rln = RLN::new(EPOCH_LIMIT);
    let user = User::new(DEGREE);

    println!("User's secret is {:?}", user.secret());

    user.register(&mut rln);

    // user.send("Hello", &mut rln);
    // user.send("I'm spammer", &mut rln);
}
