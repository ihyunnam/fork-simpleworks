use ark_ec::AffineRepr;
use std::ops::Mul;

use ark_crypto_primitives::{Error, signature::SignatureScheme};
// use ark_ec::{AffineCurve, CurveGroup};
use ark_ec::CurveGroup;
use ark_ed_on_bn254::Fr;
use ark_ff::{
    // bytes::ToBytes,
    BigInteger,
    fields::{Field, PrimeField}, MontBackend, ToConstraintField, UniformRand
};
use ark_serialize::CanonicalSerialize;
use ark_std::io::{Result as IoResult, Write};
use ark_std::rand::Rng;
use ark_std::{hash::Hash, marker::PhantomData, vec::Vec};
use blake2::Blake2s;
use digest::Digest;

use derivative::Derivative;

use crate::hash::poseidon2_hash;

// use super::ConstraintF;

pub struct Schnorr<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup"), Debug)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
    pub salt: Option<[u8; 32]>,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

#[derive(Clone, Default, Debug)]
pub struct SecretKey<C: CurveGroup> {
    pub secret_key: C::ScalarField,
    pub public_key: PublicKey<C>,
}

/* Dummy impl */
impl<C: CurveGroup> CanonicalSerialize for SecretKey<C> {
    // #[inline]
    // fn write<W: Write>(&self, writer: W) -> IoResult<()> {
    //     self.secret_key.write(writer)
    // }
    fn compressed_size(&self) -> usize {
        0
    }

    fn serialize_compressed<W: Write>(&self, writer: W) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }

    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }

    fn serialize_with_mode<W: Write>(
            &self,
            writer: W,
            compress: ark_serialize::Compress,
        ) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        0
    }

    fn uncompressed_size(&self) -> usize {
        0
    }

}

#[derive(Clone, Default, Debug)]
pub struct Signature<C: CurveGroup> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: Vec<u8>,
}

impl<C: CurveGroup + Hash> SignatureScheme for Schnorr<C>
where
    C::ScalarField: PrimeField,
    // <C as CurveGroup>::Affine: Mul<ark_ff::Fp<MontBackend<ark_ed_on_bn254::FrConfig, 4>, 4>>
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        let salt = None;
        let generator = C::Affine::generator();

        Ok(Parameters { generator, salt })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>  {
        // Secret is a random scalar x
        // the pubkey is y = xG
        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into_affine();

        Ok((
            public_key,
            SecretKey {
                secret_key,
                public_key,
            },
        ))
    }

    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        // (k, e);
        let (random_scalar, verifier_challenge_fe) = {
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(rng);      // SCALARFIELD IS Fr
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();
            println!("actual prover commitment {:?}", prover_commitment);
            // Hash everything to get verifier challenge.
            // e := H(salt || pubkey || r || msg);
            let mut hash_input = Vec::new();
            if let Some(salt) = parameters.salt {
                hash_input.extend_from_slice(&salt);
                // println!("salt actual {:?}", salt); - NO SALT
            }
            let mut writer = vec![];
            sk.public_key.serialize_uncompressed(&mut writer).unwrap();
            hash_input.extend_from_slice(&writer);
            writer.clear();
            prover_commitment.serialize_uncompressed(&mut writer).unwrap();
            hash_input.extend_from_slice(&writer);
            hash_input.extend_from_slice(message);

            let verifier_challenge_fe = poseidon2_hash(&hash_input).unwrap();   // make this constraintF<C> by making poseidon return such

            (random_scalar, verifier_challenge_fe)
        };

        // println!("VERIFIER CHALLENGE HERE {:?}", &verifier_challenge_fe.into_bigint().to_bytes_le());
        let verifier_challenge = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge_fe.into_bigint().to_bytes_le());

        let verifier_challenge_bytes = verifier_challenge_fe.into_bigint().to_bytes_le();

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge.mul(sk.secret_key));
        let signature = Signature {
            prover_response,
            verifier_challenge: verifier_challenge_bytes,     // TODO: CONSTRAINTF<C> INTO BYTES --> var as vec<uint<constraintf<C>>>
        };

        Ok(signature)
    }

    /* NOT USED */
    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        // let Signature {
        //     prover_response,
        //     verifier_challenge,
        // } = signature;
        // let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(verifier_challenge);
        // // sG = kG - eY
        // // kG = sG + eY
        // // so we first solve for kG.
        // let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        // let public_key_times_verifier_challenge = pk.mul(verifier_challenge_fe);
        // claimed_prover_commitment += &public_key_times_verifier_challenge;
        // let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        // // e = H(salt, kG, msg)
        // let mut hash_input = Vec::new();
        // if let Some(salt) = parameters.salt {
        //     hash_input.extend_from_slice(&salt);
        // }
        // hash_input.extend_from_slice(&to_bytes![pk]?);
        // hash_input.extend_from_slice(&to_bytes![claimed_prover_commitment]?);
        // hash_input.extend_from_slice(message);

        // // cast the hash output to get e
        // let obtained_verifier_challenge = poseidon2_hash(&hash_input).unwrap();

        // // The signature is valid iff the computed verifier challenge is the same as the one
        // // provided in the signature
        // Ok(verifier_challenge == obtained_verifier_challenge)
        Ok(true)
    }

    // TODO: Implement
    #[allow(clippy::todo)]
    fn randomize_public_key(
        _pp: &Self::Parameters,
        _public_key: &Self::PublicKey,
        _randomness: &[u8],
    ) -> Result<Self::PublicKey, Error> {
        todo!()
    }

    // TODO: Implement
    #[allow(clippy::todo)]
    fn randomize_signature(
        _pp: &Self::Parameters,
        _signature: &Self::Signature,
        _randomness: &[u8],
    ) -> Result<Self::Signature, Error> {
        todo!()
    }
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0_i32..8_i32 {
            let bit = (*byte >> (8_i32 - i - 1_i32)) & 1;
            bits.push(bit == 1);
        }
    }
    bits
}

impl<ConstraintF: Field, C: CurveGroup + ToConstraintField<ConstraintF>>
    ToConstraintField<ConstraintF> for Parameters<C>
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        self.generator.into_group().to_field_elements()     // CHANGED FROM into_projective()
    }
}
