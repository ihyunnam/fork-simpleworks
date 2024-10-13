use crate::gadgets::poseidon2_hash;

use super::{
    // blake2s::{ROGadget, RandomOracleGadget},
    parameters_var::ParametersVar,
    public_key_var::PublicKeyVar,
    schnorr::Schnorr,
    signature_var::SignatureVar,
    // Blake2sParametersVar, ConstraintF,
};
use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, MontBackend};
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBitsGadget;
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
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    Namespace<ark_ff::Fp<MontBackend<ark_ed_on_bn254::FqConfig, 4>, 4>>: From<Namespace<<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField>>,
    <C as Group>::ScalarField: Borrow<ark_ff::Fp<MontBackend<ark_ed_on_bn254::FqConfig, 4>, 4>>,
    UInt8<<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField>: ark_sponge::constraints::AbsorbGadget<ark_ff::Fp<MontBackend<ark_ed_on_bn254::FqConfig, 4>, 4>>,
    C::BaseField: Field<BasePrimeField = ark_ed_on_bn254::Fq>,
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

        // let b2s_params = <Blake2sParametersVar as AllocVar<_, ConstraintF<C>>>::new_constant(
        //     ConstraintSystemRef::None,
        //     (),
        // )?;
        // let obtained_verifier_challenge = ROGadget::evaluate(&b2s_params, &hash_input)?.0;
        let obtained_verifier_challenge = poseidon2_hash(&hash_input).unwrap();
        // POSEIDON RETURNS FPVAR, EITHER FR OR CONSTRAINTF<C>
        
        // let mut bits: Vec<ark_r1cs_std::prelude::Boolean<ConstraintF<C>>> = Vec::new();
        // for byte in verifier_challenge {
        //     let byte_bits = byte.to_bits_le()?;
        //     bits.extend(byte_bits);
        // }

        // let verifier_challenge_fe = FpVar::<ConstraintF<C>>::new_variable(
        //     cs.clone(),
        //     || Ok(ConstraintF::<C>::from_le_bits(&bits)),
        //     AllocationMode::Witness,
        // ).unwrap();

        // Convert the bits back into an FpVar
        // let verifier_challenge_fe = FpVar::<ConstraintF<C>>::from(&bits);
        // let verifier_challenge_fe = verifier_challenge.to_bigint().to_bytes_le()?;
        let bits = obtained_verifier_challenge.to_bits_le()?;
        let mut bytes = Vec::new();
        for chunk in bits.chunks(8) {
            // Convert each 8-bit chunk to a UInt8<ConstraintF<C>>
            let byte = UInt8::<ConstraintF<C>>::from_bits_le(chunk);
            bytes.push(byte);
        }

        bytes.is_eq(&verifier_challenge)
    }
}
