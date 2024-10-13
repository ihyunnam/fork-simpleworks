use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_r1cs_std::{
    fields::fp::FpVar, uint128::UInt128, uint16::UInt16, uint32::UInt32, uint64::UInt64,
    uint8::UInt8,
};

mod address;
pub use address::Address;

mod boolean;

mod field;

mod helpers;

mod poseidon;
pub use poseidon::poseidon2_hash;

use self::int8::Int8;

mod int8;
mod uint128;
mod uint16;
mod uint32;
mod uint64;
mod uint8;

pub mod traits;

use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsConfig, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
pub type C = JubJub;
pub type ConstraintF = <<ark_ec::twisted_edwards::Projective<EdwardsConfig> as CurveGroup>::BaseField as Field>::BasePrimeField;
pub type Comparison = helpers::Comparison;

pub type UInt8Gadget = UInt8<ConstraintF>;
pub type UInt16Gadget = UInt16<ConstraintF>;
pub type UInt32Gadget = UInt32<ConstraintF>;
pub type UInt64Gadget = UInt64<ConstraintF>;
pub type UInt128Gadget = UInt128<ConstraintF>;
pub type Int8Gadget = Int8<ConstraintF>;
pub type AddressGadget = Address<ConstraintF>;
pub type FieldGadget = FpVar<ConstraintF>;
