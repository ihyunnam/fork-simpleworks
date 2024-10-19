use std::{borrow::Borrow, marker::PhantomData};

// use ark_crypto_primitives::encryption::elgamal::constraints::ConstraintF;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode, CurveVar, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use super::schnorr::Parameters;

use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
type C = JubJub;
// type ConstraintF = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
type ConstraintF = ark_ed_on_bn254::Fr;

#[derive(Clone)]
pub struct ParametersVar<C: CurveGroup, GC: CurveVar<C, ConstraintF>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    pub(crate) generator: GC,
    pub(crate) salt: Option<Vec<UInt8<ConstraintF>>>,
    _curve: PhantomData<C>,
}

impl<C, GC> AllocVar<Parameters<C>, ConstraintF> for ParametersVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let generator = GC::new_variable(cs.clone(), || Ok(val.borrow().generator), mode)?;
            let native_salt = val.borrow().salt;
            let mut constraint_salt = Vec::<UInt8<ConstraintF>>::new();
            if let Some(native_salt_value) = native_salt {
                for i in 0..32 {
                    if let Some(native_salt_element) = native_salt_value.get(i) {
                        constraint_salt.push(UInt8::<ConstraintF>::new_variable(
                            cs.clone(),
                            || Ok(native_salt_element),
                            mode,
                        )?);
                    }
                }

                return Ok(Self {
                    generator,
                    salt: Some(constraint_salt),
                    _curve: PhantomData,
                });
            }
            Ok(Self {
                generator,
                salt: None,
                _curve: PhantomData,
            })
        })
    }
}
