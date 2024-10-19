use crate::hash::POSEIDON_PARAMS;
use crate::hash;
use anyhow::{anyhow, Result};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
use ark_sponge::{
    constraints::{AbsorbGadget, CryptographicSpongeVar},
    poseidon::constraints::PoseidonSpongeVar,
};

use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
type C = JubJub;
// type ConstraintF = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
use ark_bn254::Fr;
type ConstraintF = Fr;

type PoseidonGadget = PoseidonSpongeVar<ConstraintF>;

pub fn poseidon2_hash(input: &impl AbsorbGadget<ConstraintF>) -> Result<FpVar<ConstraintF>> {
    let input_bytes = input.to_sponge_bytes().unwrap();

    let cs = input_bytes
        .first()
        .ok_or_else(|| anyhow!("Error getting the first element of the input"))?
        .cs();

    // let sponge_params = hash::helpers::poseidon_parameters_for_test()?;

    let mut constraint_sponge = PoseidonGadget::new(cs, &*POSEIDON_PARAMS);

    constraint_sponge.absorb(&input).unwrap();
    constraint_sponge
        .squeeze_field_elements(1)
        .map_err(|e| anyhow!(e.to_string()))?
        .first()
        .ok_or_else(|| anyhow!("Error getting the first element of the input"))
        .cloned()
}

// #[cfg(test)]
// mod tests {
//     use crate::{
//         gadgets::{self, UInt8Gadget},
//         hash,
//     };
//     use ark_crypto_primitives::sponge::{constraints::AbsorbGadget, Absorb};
//     use ark_r1cs_std::R1CSVar;
//     use ark_relations::{ns, r1cs::ConstraintSystem};

//     #[test]
//     fn test_poseidon2_hash_primitive_and_gadget_implementations_comparison() {
//         let cs = ConstraintSystem::new_ref();

//         let message = b"Hello World";
//         let message_var = UInt8Gadget::new_input_vec(ns!(cs, "input"), message).unwrap();

//         let primitive_squeeze = hash::poseidon2_hash(message).unwrap();
//         let squeeze_var = gadgets::poseidon2_hash(&message_var).unwrap();

//         assert!(cs.is_satisfied().unwrap());
//         assert_eq!(squeeze_var.value().unwrap(), primitive_squeeze);
//     }

//     // use crate::constraints::AbsorbGadget;
//     // use crate::test::Fr;
//     use ark_bn254::Fr;
//     // use crate::Absorb;
//     use ark_r1cs_std::alloc::AllocVar;
//     use ark_r1cs_std::fields::fp::FpVar;
//     use ark_r1cs_std::uint8::UInt8;
//     // use ark_r1cs_std::R1CSVar;
//     // use ark_relations::r1cs::ConstraintSystem;
//     use ark_relations::*;
//     use ark_std::{test_rng, UniformRand};

//     #[test]
//     fn consistency_check() {
//         // test constraint is consistent with native
//         let cs = ConstraintSystem::<Fr>::new_ref();
//         let mut rng = test_rng();
//         // uint8
//         let data = vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8];
//         let data_var = UInt8::new_input_vec(ns!(cs, "u8data"), &data).unwrap();

//         let native_bytes = data.to_sponge_bytes_as_vec();
//         let constraint_bytes = data_var.to_sponge_bytes().unwrap();

//         assert_eq!(constraint_bytes.value().unwrap(), native_bytes);

//         // field

//         let data: Vec<_> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
//         let data_var: Vec<_> = data
//             .iter()
//             .map(|item| FpVar::new_input(ns!(cs, "fpdata"), || Ok(*item)).unwrap())
//             .collect();

//         let native_bytes = data.to_sponge_bytes_as_vec();
//         let constraint_bytes = data_var.to_sponge_bytes().unwrap();
//         assert_eq!(constraint_bytes.value().unwrap(), native_bytes);

//         assert!(cs.is_satisfied().unwrap())
//     }
    
// }
