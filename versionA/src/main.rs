#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::type_complexity)]

use std::{collections::HashMap, time::SystemTime};

use ark_bls12_381::*;
use ark_ec::{AffineCurve, PairingEngine};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_poly_commit::{kzg10::*, PCRandomness};
use ark_std::{test_rng, UniformRand};

use once_cell::sync::Lazy;

type UniPoly_381 = DensePolynomial<<Bls12_381 as PairingEngine>::Fr>;
type KZG = KZG10<Bls12_381, UniPoly_381>;

const EPOCH_LIMIT: u8 = 3;
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
    shares: HashMap<G1Projective, (Commitment<Bls12_381>, Vec<(Fr, Fr)>)>,
}

impl RLN {
    fn new(limit: u8) -> Self {
        Self {
            limit,
            shares: HashMap::new(),
        }
    }

    fn register(
        &mut self,
        comm: Commitment<Bls12_381>,
        proof: Proof<Bls12_381>,
        pubkey: G1Projective,
    ) {
        assert!(Self::pairing_check(comm, proof, pubkey, Fr::from(0)));
        self.shares.insert(pubkey, (comm, vec![]));
    }

    fn pairing_check(
        comm: Commitment<Bls12_381>,
        proof: Proof<Bls12_381>,
        pubkey: G1Projective,
        point: Fr,
    ) -> bool {
        let inner = comm.0.into_projective() - pubkey;
        let lhs = Bls12_381::pairing(inner, KEYS.1.h);

        let inner = KEYS.1.beta_h.into_projective() - KEYS.1.h.mul(point);
        let rhs = Bls12_381::pairing(proof.w, inner);

        lhs == rhs
    }

    fn new_message(
        &mut self,
        pubkey: G1Projective,
        message_hash: Fr,
        evaluation: Fr,
        proof: Proof<Bls12_381>,
    ) {
        let (comm, messages) = self.shares.get_mut(&pubkey).unwrap();
        assert!(KZG::check(&KEYS.1, comm, message_hash, evaluation, &proof)
            .expect("Wrong opening proof"));

        messages.push((message_hash, evaluation));

        if messages.len() > self.limit as usize {
            let key = Self::recover_key(messages);
            let pubkey = KEYS.1.g.mul(key);
            assert!(self.shares.get(&pubkey).is_some());

            self.shares.remove(&pubkey).unwrap();
        }
    }

    fn recover_key(shares: &Vec<(Fr, Fr)>) -> Fr {
        let size = (EPOCH_LIMIT + 1) as usize;
        let vec_x: Vec<Fr> = shares.iter().map(|a| {a.0}).collect();
        let vec_y: Vec<Fr> = shares.iter().map(|a| {a.1}).collect();

        let mut matrix: Vec<Vec<Fr>> = vec![vec![Fr::from(1); size]];
        matrix.push(vec_x.clone());

        for i in 2..size {
            let next_row = matrix[i-1].iter().zip(&vec_x).map(|(&a, &b)| {a * b}).collect();
            matrix.push(next_row);
        }

        let denominator = determinant(matrix.clone());
        _ = std::mem::replace(&mut matrix[0], vec_y);
        let numerator = determinant(matrix);

        numerator / denominator
    }
}

fn determinant(mut matrix: Vec<Vec<Fr>>) -> Fr {
    let n = matrix.len();
    let mut det = Fr::from(1);

    for i in 0..n {
        let mut pivot_row = i;
        for j in (i + 1)..n {
            if matrix[j][i] != Fr::from(0) {
                pivot_row = j;
                break;
            }
        }

        if pivot_row != i {
            matrix.swap(i, pivot_row);
            det = -det;
        }

        let pivot = matrix[i][i];

        if pivot == Fr::from(0) {
            return Fr::from(0);
        }

        det *= pivot;

        for j in (i + 1)..n {
            let factor = matrix[j][i] / pivot;
            for k in (i + 1)..n {
                matrix[j][k] = matrix[j][k] - factor * matrix[i][k];
            }
        }
    }

    det
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

    fn register(&self, rln: &mut RLN) {
        let cur_time = SystemTime::now();

        // [f(alpha)]
        let (comm, rand) = KZG::commit(&KEYS.0, &self.polynomial, None, None).unwrap();

        // [psi(alpha)]
        let proof = KZG::open(&KEYS.0, &self.polynomial, Fr::from(0), &rand).unwrap();

        // [f(0)]
        let pubkey = self.pubkey();

        rln.register(comm, proof, pubkey);

        println!(
            "Registration time (milliseconds): {}",
            cur_time.elapsed().unwrap().as_millis()
        );
    }

    fn send(&self, message_hash: Fr, rln: &mut RLN) {
        let cur_time = SystemTime::now();
        let evaluation = self.polynomial.evaluate(&message_hash);
        let proof = KZG::open(
            &KEYS.0,
            &self.polynomial,
            message_hash,
            &Randomness::<Fr, UniPoly_381>::empty(),
        )
        .expect("Cannot make proof");

        println!(
            "Send Message Time (microseconds): {}",
            cur_time.elapsed().unwrap().as_micros()
        );

        rln.new_message(self.pubkey(), message_hash, evaluation, proof);
    }

    fn secret(&self) -> Fr {
        self.polynomial.evaluate(&Fr::from(0))
    }

    fn pubkey(&self) -> G1Projective {
        KEYS.1.g.mul(self.secret())
    }
}

fn main() {
    let rng = &mut test_rng();

    let mut rln = RLN::new(EPOCH_LIMIT);
    let user = User::new(DEGREE);

    user.register(&mut rln);
    assert!(rln.shares.get(&user.pubkey()).is_some());

    for _ in 0..EPOCH_LIMIT+1 {
        user.send(Fr::rand(rng), &mut rln);
    }

    assert!(rln.shares.get(&user.pubkey()).is_none());
}
