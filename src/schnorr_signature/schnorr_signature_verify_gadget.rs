use ark_crypto_primitives::crh::sha256::digest::KeyInit;
use ark_r1cs_std::R1CSVar;
use crate::gadgets::poseidon2_hash;

use super::{
    blake2s::{ROGadget, RandomOracleGadget},
    parameters_var::ParametersVar,
    public_key_var::PublicKeyVar,
    schnorr::Schnorr,
    signature_var::SignatureVar,
    Blake2sParametersVar,
};
use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, MontBackend, PrimeField};
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::{ToBitsGadget, ToBytesGadget};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, CurveVar, EqGadget, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError};
use std::borrow::Borrow;
use std::marker::PhantomData;

use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
// use ark_bn254::Fr;
type C = JubJub;
type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

pub struct SchnorrSignatureVerifyGadget<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC> SigVerifyGadget<Schnorr<C>, ConstraintF<C>> for SchnorrSignatureVerifyGadget<C, GC>
where
    C: CurveGroup<BaseField = ark_ff::Fp<MontBackend<ark_bn254::FrConfig, 4>, 4>>,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    // C::BaseField: Field<BasePrimeField = ark_ed_on_bn254::Fq>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<C, GC>;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<C>>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError>
    {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();
        let mut claimed_prover_commitment = parameters
            .generator
            .scalar_mul_le(prover_response.to_bits_le()?.iter())?;
        let public_key_times_verifier_challenge = public_key
            .pub_key
            .scalar_mul_le(verifier_challenge.to_bits_le()?.iter())?;
        claimed_prover_commitment += &public_key_times_verifier_challenge;

        let mut hash_input = Vec::new();
        if let Some(salt) = parameters.salt.as_ref() {
            hash_input.extend_from_slice(salt);
        }
        hash_input.extend_from_slice(&public_key.pub_key.to_bytes()?);
        hash_input.extend_from_slice(&claimed_prover_commitment.to_bytes()?);
        hash_input.extend_from_slice(message);

        let b2s_params = <Blake2sParametersVar as AllocVar<_, ConstraintF<C>>>::new_constant(
            ConstraintSystemRef::None,
            (),
        )?;
        let obtained_verifier_challenge = ROGadget::evaluate(&b2s_params, &hash_input)?.0;

        obtained_verifier_challenge.is_eq(&verifier_challenge.to_vec())
    }
}
