use std::{borrow::Borrow, marker::PhantomData};

use ark_bn254::Fr;
// use ark_crypto_primitives::encryption::elgamal::constraints::ConstraintF;
use ark_ec::{CurveGroup, Group};
use ark_ff::{BigInteger, Field, MontBackend, PrimeField};
// use ark_ff::to_bytes;
use ark_r1cs_std::{
    fields::fp::FpVar, prelude::{AllocVar, AllocationMode, CurveVar, GroupOpsBounds}, uint8::UInt8, ToBytesGadget
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use derivative::Derivative;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
type C = JubJub;
type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

use super::schnorr::Signature;

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct SignatureVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    pub prover_response: Vec<UInt8<ConstraintF<C>>>,
    pub verifier_challenge: Vec<UInt8<ConstraintF<C>>>,      // TODO: ADD (crate) back in for both
    #[doc(hidden)]
    _group: PhantomData<GC>,
}

impl<C, GC> AllocVar<Signature<C>, ConstraintF<C>> for SignatureVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    // <C as Group>::ScalarField: Borrow<ark_ff::Fp<MontBackend<ark_ed_on_bn254::FqConfig, 4>, 4>>,
    // Namespace<ark_ff::Fp<MontBackend<ark_ed_on_bn254::FqConfig, 4>, 4>>: From<Namespace<<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField>>,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let response_bytes = val.borrow().prover_response.into_bigint().to_bytes_le();
            let challenge_bytes = &val.borrow().verifier_challenge;
            let mut prover_response = Vec::<UInt8<ConstraintF<C>>>::new();
            let mut verifier_challenge = Vec::<UInt8<ConstraintF<C>>>::new();
            for byte in &response_bytes {
                prover_response.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }
            for byte in challenge_bytes {
                verifier_challenge.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }
            Ok(SignatureVar {
                prover_response,
                verifier_challenge,
                _group: PhantomData,
            })
        })
    }
}

// DO NOT USE!!!!!
impl<C, GC> ToBytesGadget<ConstraintF<C>> for SignatureVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    // <C as Group>::ScalarField: Borrow<ark_ff::Fp<MontBackend<ark_ed_on_bn254::FrConfig, 4>, 4>>,
    // Namespace<ark_ff::Fp<MontBackend<ark_ed_on_bn254::FrConfig, 4>, 4>>: From<Namespace<<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField>>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        let prover_response_bytes = self.prover_response.to_bytes()?;
        let verifier_challenge_bytes = self.verifier_challenge.to_bytes()?;
        let mut bytes = Vec::<UInt8<ConstraintF<C>>>::new();
        bytes.extend(prover_response_bytes);
        bytes.extend(verifier_challenge_bytes);
        Ok(bytes)
    }
}
