use serde::{Deserialize, Serialize};

pub mod dl_solvers;
pub mod elgamal;
pub mod prime;
pub mod rfc7919_groups;

pub use curv::arithmetic::BigInt;

pub struct ElGamal;
pub struct ExponentElGamal;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalPP {
    pub g: BigInt,
    pub q: BigInt,
    pub p: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalPublicKey {
    pub pp: ElGamalPP,
    pub h: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalPrivateKey {
    pub pp: ElGamalPP,
    pub x: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalKeyPair {
    pub pk: ElGamalPublicKey,
    pub sk: ElGamalPrivateKey,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    pub c1: BigInt,
    pub c2: BigInt,
    pub pp: ElGamalPP,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ElGamalError {
    EncryptionError,
    DecryptionError,
    HomomorphicError,
    ParamError,
}

/// Generating random BigInt
pub trait Rand {
    /// Generates random number within `[0; upper)` range
    ///
    /// ## Panics
    /// Panics if `upper <= 0`
    fn sample_below(&self, upper: &BigInt) -> BigInt;
    /// Generates random number within `[lower; upper)` range
    ///
    /// ## Panics
    /// Panics if `upper <= lower`
    fn sample_range(&self, lower: &BigInt, upper: &BigInt) -> BigInt;
    /// Generates number within `[0; 2^bit_size)` range
    fn sample(&self, bit_size: usize) -> BigInt;
}

use curv::arithmetic::traits::Samplable;

pub struct BigIntRand {}

impl Rand for BigIntRand {
    fn sample_below(&self, upper: &BigInt) -> BigInt {
        BigInt::sample_below(upper)
    }

    fn sample_range(&self, lower: &BigInt, upper: &BigInt) -> BigInt {
        BigInt::sample_range(lower, upper)
    }

    fn sample(&self, bit_size: usize) -> BigInt {
        BigInt::sample(bit_size)
    }
}
