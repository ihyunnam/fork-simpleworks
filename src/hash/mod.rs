use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_sponge::poseidon::PoseidonConfig;
use lazy_static::lazy_static;
use anyhow::{anyhow, Result};
use ark_crypto_primitives::crh::pedersen;
use ark_crypto_primitives::{
    crh::{injective_map::{PedersenCRHCompressor, TECompressor},
    poseidon::CRH},
};
// use ark_ed_on_bls12_377::{EdwardsProjective, Fq};
use ark_sponge::poseidon::PoseidonSponge;
use ark_sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ed_on_bn254::Fr;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
type C = JubJub;
type ConstraintF = Fr;

// pub mod helpers;

// #[derive(Clone, PartialEq, Eq, Hash)]
// struct LeafWindow;

// impl pedersen::Window for LeafWindow {
//     const WINDOW_SIZE: usize = 4;
//     const NUM_WINDOWS: usize = 144;
// }

// type PedersenHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;

// pub fn pedersen_hash(input: &[u8]) -> Result<Fq> {
//     let mut rng = ark_std::test_rng();
//     let params = PedersenHash::setup(&mut rng).map_err(|e| anyhow!("{:?}", e))?;

//     PedersenHash::evaluate(&params, input).map_err(|e| anyhow!("{:?}", e))
// }

type PoseidonHash = PoseidonSponge<ConstraintF>;

lazy_static! {
    pub static ref POSEIDON_PARAMS: PoseidonConfig<ConstraintF> = {
        let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF>(254, 2, 8, 24, 0);
        PoseidonConfig::<ConstraintF>::new(8, 24, 31, mds, ark, 2, 1)
    };
}

pub fn poseidon2_hash(input: &[u8]) -> Result<ConstraintF> {
    // let sponge_params = helpers::poseidon_parameters_for_test()?;
    
    // pass in our hardcoded default params
    let mut native_sponge = PoseidonHash::new(&*POSEIDON_PARAMS);

    native_sponge.absorb(&input);
    native_sponge
        .squeeze_native_field_elements(1)
        .first()
        .ok_or_else(|| anyhow!("Error getting the first element of the input"))
        .copied()
}
