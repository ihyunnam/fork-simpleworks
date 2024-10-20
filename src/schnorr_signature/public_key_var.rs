use super::schnorr::PublicKey;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_r1cs_std::{bits::uint8::UInt8, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::vec::Vec;
use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;

// type ConstraintF = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
type ConstraintF = ark_bn254::Fr;

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF>"),
    Clone(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF>")
)]
pub struct PublicKeyVar<C: CurveGroup, GC: CurveVar<C, ConstraintF>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    pub(crate) pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

impl<C, GC> AllocVar<PublicKey<C>, ConstraintF> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<ConstraintF> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C, GC> ToBytesGadget<ConstraintF> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        self.pub_key.to_bytes()
    }
}
