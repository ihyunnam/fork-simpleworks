use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_ec::Group;
// use ark_crypto_primitives::signature::{schnorr::Schnorr, constraints::SigVerifyGadget};
use ark_ff::{BigInteger, BigInteger256};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
// use ark_ec::twisted_edwards::GroupProjective;
use ark_r1cs_std::fields::fp::FpVar;
use ark_sponge::poseidon::find_poseidon_ark_and_mds;
use bitvec::view::AsBits;
use simpleworks::schnorr_signature::SimpleSchnorrSignature;
// use digest::Digest;
// use sha2::digest::DynDigest as H;
// use ark_r1cs_std::UInt128::UInt128;
use std::time::Duration;
// use ark_ec::bls12::Bls12;
// use ark_bn254::{FrConfig};
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar as TEAffineVar;
use ark_crypto_primitives::crh::poseidon::CRH;
use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget};
use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem, Namespace, SynthesisMode};
use ark_std::{Zero, borrow::Borrow};
use ark_ec::{twisted_edwards::Affine, AffineRepr, CurveGroup};
use ark_ff::{BigInt, BitIteratorLE, Fp, Fp256, MontBackend, One, PrimeField};
use ark_ff::{
    // bytes::ToBytes,
    fields::{Field},
    UniformRand,
};
use ark_bn254::{Bn254 as E, FrConfig};
// use ark_bn254::{Bn254 as E};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, EmptyFlags, Validate};
use ark_ed_on_bn254::{Fr, constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group

// mod schnorr;
// use schnorr::constraints::*;

use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    prelude::*
};
use std::{time::Instant, result::Result};
use ark_std::vec::Vec;
// use ark_snark::SNARK;
use rand::rngs::OsRng;
use ark_crypto_primitives::{
    // commitment::{pedersen::{
    // Commitment, Randomness as PedersenRandomness, Parameters as PedersenParameters},
    //     CommitmentScheme},
    signature::SignatureScheme
        // schnorr::{Parameters as SchnorrParameters, PublicKey as SchnorrPubKey, SecretKey as SchnorrSecKey, Signature},
    // constraints::{SchnorrSignatureVerifyGadget as VerifyGadget, SignatureVar as SchnorrSignatureVar, ParametersVar as SchnorrParametersVar, PublicKeyVar as SchnorrPublicKeyVar}}},
};
// use crate::schnorr::{{Parameters as SchnorrParameters, PublicKey as SchnorrPubKey, SecretKey as SchnorrSecKey, Signature},
// constraints::{SchnorrSignatureVerifyGadget as VerifyGadget, SignatureVar as SchnorrSignatureVar, ParametersVar as SchnorrParametersVar, PublicKeyVar as SchnorrPublicKeyVar}};
use simpleworks::schnorr_signature::
    {schnorr::{Schnorr, Parameters as SchnorrParameters, PublicKey as SchnorrPubKey, Signature},
    parameters_var::ParametersVar as SchnorrParametersVar,
    signature_var::SignatureVar as SchnorrSignatureVar,
    schnorr_signature_verify_gadget::{SchnorrSignatureVerifyGadget, },
    public_key_var::PublicKeyVar,
    parameters_var::ParametersVar,
    signature_var::SignatureVar,
};
use arkworks_mimc::{utils::to_field_elements, MiMC, MiMCParameters, MiMCNonFeistelCRH};
use ark_relations::r1cs::{SynthesisError, ConstraintSynthesizer, ConstraintSystemRef, };
use ark_std::marker::PhantomData;
use ark_groth16::Groth16;

// type E = <EdwardsConfig as Pairing>;
// type Fr = Fp<MontBackend<FrConfig, 4>, 4>;
type C = JubJub;
// type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
// type ConstraintF = JubJub::ScalarField;
type ConstraintF = Fr;
// type P = MiMCParameters;
type W = Window;
// type GG = TEAffineVar<C, ConstraintF>;

// type GG = EdwardsVar;
// type GG = CurveVar<JubJub, Fr>;
type GG = ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar<ark_bn254::G1Projective, ark_bn254::Fr>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Window;
impl ark_crypto_primitives::crh::pedersen::Window for Window {
    const WINDOW_SIZE: usize = 16;
    const NUM_WINDOWS: usize = 16;
}

#[derive(Clone, Default)]
pub struct MiMCMock;

impl MiMCParameters for MiMCMock {
    const ROUNDS: usize = 5;
    const EXPONENT: usize = 5;
}

/* Circuit definitions */

pub struct InsertCircuit<W, C: CurveGroup, GG: CurveVar<C, ConstraintF>> {
    pub first_login: Option<bool>,
    pub schnorr_params: Option<SchnorrParameters<C>>,
    pub schnorr_sig: Option<Signature<C>>,
    pub schnorr_pk: Option<SchnorrPubKey<C>>,
    pub schnorr_msg: Option<Vec<u8>>,
    pub poseidon_params: Option<PoseidonConfig<ConstraintF>>,    // constant
    pub mimc_params: Option<MiMC<ConstraintF, MiMCMock>>,
    pub record: Option<Vec<u8>>,        // record = c||RP name||account ID
    pub h_prev: Option<ConstraintF>,           /* Record info */
    pub v_prev: Option<ConstraintF>,
    pub h_cur: Option<ConstraintF>,
    pub v_cur: Option<ConstraintF>,
    pub i: Option<u8>,
    pub _window_var: PhantomData<W>,
    pub _curvevar: PhantomData<GG>,
}

// pub struct LoggingCircuit<W, C: CurveGroup> {
//     // pub schnorr_params: Option<SchnorrParameters>,
//     // pub schnorr_apk: Option<Affine<EdwardsConfig>>,
//     // pub schnorr_apk: Option<PublicKey>,
//     pub apk_commit_x: Option<ConstraintF>,
//     pub apk_commit_y: Option<ConstraintF>,
//     pub pedersen_rand: Option<PedersenRandomness<C>>,
//     pub pedersen_params: Option<PedersenParameters<C>>,
//     pub poseidon_params: Option<PoseidonConfig<ConstraintF>>,    // constant
//     pub hmac: Option<[u8;32]>,
//     pub record_x: Option<ConstraintF>,
//     pub record_y: Option<ConstraintF>,
//     // pub elgamal_rand: Option<EncRand<C>>,
//     // pub elgamal_params: Option<EncParams<C>>,
//     pub pedersen_rand_elgamal: Option<PedersenRandomness<C>>,
//     // pub elgamal_key_commit_x: Option<ConstraintF>,
//     // pub elgamal_key_commit_y: Option<ConstraintF>,
//     pub v_cur: Option<ConstraintF>,
//     // pub elgamal_key: Option<EncPubKey<C>>,
//     pub h_cur: Option<ConstraintF>,
//     pub i: Option<u8>,
//     // pub _curve_var: PhantomData<GG>,
//     pub _window_var: PhantomData<W>,
// }

/* Functions for circuit generation */

fn generate_insert_circuit() -> InsertCircuit<W,C,GG> {
    println!("Generating InsertCircuit");
    let rng = &mut OsRng;
        
    let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF> (254, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255
    let poseidon_params = PoseidonConfig::<ConstraintF>::new(8, 24, 31, mds, ark, 2, 1);

    /* Generate user MiMC key */
    let mut mimc = <MiMCNonFeistelCRH<ConstraintF, MiMCMock> as CRHScheme>::setup(rng).unwrap();
    mimc.k = ConstraintF::rand(rng);

    /* Hash MiMC key */
    let mimc_k_hash = CRH::<ConstraintF>::evaluate(&poseidon_params, [mimc.k]).unwrap();

    /* Assume this is previous record */
    let i_prev: u8 = 9;
    let mut h_prev_bytes = vec![];
    let i_prev_fr = ConstraintF::from_be_bytes_mod_order(&[i_prev]);
    let h_prev = CRH::<ConstraintF>::evaluate(&poseidon_params, [i_prev_fr, mimc_k_hash]).unwrap();
    h_prev.serialize_with_mode(&mut h_prev_bytes, Compress::Yes);

    let record = "challenge1RPnameaccountID".as_bytes();
    // let v_prev = MyEnc::encrypt(&elgamal_param, &elgamal_key, &plaintext, &elgamal_rand).unwrap();
    let v_prev = <MiMCNonFeistelCRH<ConstraintF, MiMCMock> as CRHScheme>::evaluate(&mimc, record).unwrap();
    let mut v_prev_bytes = vec![];    // TODO: unify length to check partition later
    v_prev.serialize_with_mode(&mut v_prev_bytes, Compress::Yes).unwrap();

    let mut sign_msg = vec![];
    
    // NOTE: msg ends up being 224 bytes.
    sign_msg.extend_from_slice(&h_prev_bytes);
    sign_msg.extend_from_slice(&v_prev_bytes);        // TODO: check partitions too
    
    let schnorr_params = Schnorr::setup(rng).unwrap();
    let (pk,sk) = Schnorr::keygen(&schnorr_params, rng).unwrap();
    let schnorr_sig = Schnorr::sign(&schnorr_params, &sk, &sign_msg, rng).unwrap();
    /* Make current record */
    let i: u8 = 10;
    let i_fr = ConstraintF::from_be_bytes_mod_order(&[i]);
    let h_cur = CRH::<ConstraintF>::evaluate(&poseidon_params, [i_fr, mimc_k_hash]).unwrap();

    let record = "challenge2RPnameaccountname".as_bytes();
    let v_cur = <MiMCNonFeistelCRH<ConstraintF, MiMCMock> as CRHScheme>::evaluate(&mimc, record).unwrap();
    let insert_circuit = InsertCircuit::<W,C,GG> {
        first_login: None,
        schnorr_params: Some(schnorr_params),
        schnorr_pk: Some(pk),
        schnorr_sig: Some(schnorr_sig),
        schnorr_msg: Some(sign_msg),        // TODO: ERASE TO RECONSTRUCT WITH H, V LATER
        poseidon_params: Some(poseidon_params),
        h_prev: Some(h_prev),
        v_prev:  Some(v_prev),
        record: Some(record.to_vec()),
        mimc_params: Some(mimc),
        h_cur: Some(h_cur),
        v_cur: Some(v_cur),
        i: Some(i),
        _window_var: PhantomData::<W>,
        _curvevar: PhantomData::<GG>,
    };

    insert_circuit
}


// fn generate_logging_circuit() -> LoggingCircuit<W,C> {
//     // println!("Entering main.");
//     let rng = &mut OsRng;
        
//     // let start = Instant::now();
//     let elgamal_rand = EncRand::<JubJub>::rand(rng);
//     let elgamal_param = MyEnc::setup(rng).unwrap();
//     let (elgamal_key, _) = MyEnc::keygen(&elgamal_param, rng).unwrap();

//     /* Generate Poseidon hash parameters for both Schnorr signature (Musig2) and v_i */      // 6, 5, 8, 57, 0
    
//     let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF> (255, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255

//     let poseidon_params = PoseidonConfig::<ConstraintF>::new(8, 24, 31, mds, ark, 2, 1);
//     /* Assume this is previous record */
//     // let mut i_prev_vec = vec![i_prev];
//     // Step 1: Serialize the ElGamal key into a byte vector.
//     let mut elgamal_key_bytes = vec![];
//     elgamal_key.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes).unwrap(); // Ensure serialization succeeds.

//     // Step 2: Prepare a new vector to hold the serialized data.
//     let mut cur_input = Vec::with_capacity(elgamal_key_bytes.len() + 1); // Preallocate with the expected size.

//     // Step 3: Extend the vector with the serialized key bytes.
//     cur_input.extend_from_slice(&elgamal_key_bytes);

//     // Step 4: Append the additional `u8` value.
//     let i: u8 = 10;
//     cur_input.push(i); // Append `i` directly as a byte.

//     // Step 5: Convert to the scalar field element directly.
//     let fr_element = ConstraintF::from_be_bytes_mod_order(&cur_input);
//     // let h_cur = <CRH<ConstraintF, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &cur_input).unwrap();
//     let h_cur = CRH::<ConstraintF>::evaluate(&poseidon_params, [fr_element]).unwrap();
//     let mut h_cur_bytes = vec![];
//     h_cur.serialize_with_mode(&mut h_cur_bytes, Compress::Yes);
//     let plaintext = JubJub::rand(rng).into_affine();
//     let v_cur = MyEnc::encrypt(&elgamal_param, &elgamal_key, &plaintext, &elgamal_rand).unwrap();

//     // println!("vcur.0 {:?}", v_cur.0);
//     // println!("vcur.1 {:?}", v_cur.1);
//     // println!("v_cur {:?}", v_cur);
//     let mut v_0_bytes = vec![];    // TODO: unify length to check partition later
//     // let mut v_1_bytes = vec![];

//     v_cur.0.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
    
//     let mut msg = vec![];
    
//     // NOTE: msg ends up being 224 bytes.
//     msg.extend_from_slice(&h_cur_bytes);
//     msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
//     v_0_bytes.clear();
//     v_cur.1.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
//     // msg.extend_from_slice(&v_0_y_bytes);
//     msg.extend_from_slice(&v_0_bytes);
//     // msg.extend_from_slice(&v_1_y_bytes);
//     // println!("schnorr msg from outside: {:?}", msg);

//     let msg2 = msg.clone();
//     // let msg3 = msg.clone();
//     let key = b"log-secret-key";

//     // Compute HMAC-SHA256
//     let hmac_result = HMAC::mac(msg2, key);

//     /* Commit to aggregated_pubkey and give it to RP. */
//     let pedersen_randomness = PedersenRandomness(ConstraintF::rand(rng));
//     let pedersen_params = Commitment::<JubJub, Window>::setup(rng).unwrap();
//     let apk_commit = Commitment::<JubJub, Window>::commit(&pedersen_params, key, &pedersen_randomness).unwrap();
    
//     let pedersen_rand_elgamal = PedersenRandomness(ConstraintF::rand(rng));
//     let elgamal_commit = Commitment::<JubJub, Window>::commit(&pedersen_params, &elgamal_key_bytes, &pedersen_rand_elgamal).unwrap();

//     // let end = start.elapsed();
//     // println!("User and log generate variables: {:?}", end);
//     // let mut result = [0u128; 4]; // Array to hold the 8 resulting i32 values

//     let new_circuit = LoggingCircuit::<W,C,GG> {
//         // schnorr_params: Some(schnorr_param),
//         // schnorr_apk: Some(aggregated_pubkey),
//         apk_commit_x: Some(apk_commit.x),
//         apk_commit_y: Some(apk_commit.y),
//         pedersen_rand: Some(pedersen_randomness),
//         pedersen_params: Some(pedersen_params),
//         poseidon_params: Some(poseidon_params),
//         hmac: Some(last_sig),
//         record_x: Some(plaintext.x),
//         record_y: Some(plaintext.y),
//         elgamal_rand: Some(elgamal_rand),
//         elgamal_params: Some(elgamal_param),
//         pedersen_rand_elgamal: Some(pedersen_rand_elgamal),
//         elgamal_key_commit_x: Some(elgamal_commit.x),
//         elgamal_key_commit_y: Some(elgamal_commit.y),
//         v_cur: Some(v_cur),
//         elgamal_key: Some(elgamal_key),
//         h_cur: Some(h_cur),
//         i: Some(i),
//         _curve_var: PhantomData::<GG>,
//         _window_var: PhantomData::<W>, 
//     };
//     new_circuit
// }

/* Empty circuits for Groth16 setup */

fn generate_insert_circuit_for_setup() -> InsertCircuit<W,C,GG> {
    InsertCircuit::<W,C,GG> {
        first_login: None,
        schnorr_params: None,
        schnorr_sig: None,
        schnorr_msg: None,
        schnorr_pk: None,
        poseidon_params: None,
        mimc_params: None,
        record: None,
        h_prev: None,
        v_prev: None,
        h_cur: None,
        v_cur: None,
        i: Some(0),     // value doesn't mater but needs to be populated 
        _window_var: PhantomData::<W>,
        _curvevar: PhantomData::<GG>,
    }
}

// fn generate_logging_circuit_for_setup() -> LoggingCircuit::<W, C, GG> {
//     LoggingCircuit::<W,C,GG> {
//         schnorr_params: None,
//         schnorr_apk: None,
//         apk_commit_x: None,
//         apk_commit_y: None,
//         pedersen_rand: None,
//         pedersen_params: None,
//         poseidon_params: None,
//         schnorr_sig: None,
//         record_x: None,
//         record_y: None,
//         elgamal_rand: None,
//         elgamal_params: None,
//         pedersen_rand_elgamal: None,
//         elgamal_key_commit_x: None,
//         elgamal_key_commit_y: None,
//         v_cur: None,
//         elgamal_key: None,
//         h_cur: None,
//         i: None,
//         _curve_var: PhantomData::<GG>,
//         _window_var: PhantomData::<W>,
//     }
// }

/* zkSNARK proof generation */

impl<W, C, GG> ConstraintSynthesizer<ConstraintF> for InsertCircuit<W,C,GG> where 
    W: ark_crypto_primitives::crh::pedersen::Window,
    // ConstraintF: PrimeField,
    C: CurveGroup<BaseField = ark_ff::Fp<MontBackend<ark_ed_on_bn254::FrConfig, 4>, 4>>,
    GG: CurveVar<C, ConstraintF>,
        // + GroupOpsBounds<'_, ark_ec::twisted_edwards::TECurveConfig, GG>,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    // Namespace<<<C as CurveGroup>::BaseField as Field>::BasePrimeField>: From<ConstraintSystemRef<ConstraintF>>,
    // C: CurveGroup<Affine = ark_ec::twisted_edwards::Affine<ark_ed_on_bn254::EdwardsConfig>>,
    <C as CurveGroup>::BaseField: PrimeField,
    <C as CurveGroup>::BaseField: ark_crypto_primitives::sponge::Absorb,
    Namespace<Fp<MontBackend<ark_ed_on_bn254::FrConfig, 4>, 4>>: From<ConstraintSystemRef<<C as CurveGroup>::BaseField>>,
    // <C as Group>::ScalarField: Borrow<ark_ff::Fp<MontBackend<ark_bn254::FrConfig, 4>, 4>>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF>) -> Result<(), SynthesisError> {
        println!("inside generate constraints");

        let h_default = ConstraintF::default();      // This is ConstraintF

        let first_login_wtns = Boolean::<ConstraintF>::new_witness(
            cs.clone(), 
            || {Ok(self.first_login.as_ref().unwrap_or(&false))
        }).unwrap();

        /* If first login, i=0 must be true. */

        let i_wtns = UInt8::<ConstraintF>::new_witness (
            cs.clone(),
            || {
                let i = self.i.as_ref().unwrap_or(&0);
                Ok(*i)
            }
        ).unwrap();
        
        let zero_wtns = UInt8::<ConstraintF>::new_witness (
            cs.clone(),
            || { Ok(u8::zero()) }
        ).unwrap();

        let supposed_to_be = first_login_wtns.select(&zero_wtns, &i_wtns).unwrap();

        let supposed_to_be_wtns = UInt8::<ConstraintF>::new_witness (
            cs.clone(),
            || {
                Ok(supposed_to_be.value().unwrap_or(u8::one()))
            }
        ).unwrap();

        println!("here1");
        i_wtns.enforce_equal(&supposed_to_be_wtns);

        /* Verify (i-1)th signature, unless it's first login. */
        // let h_prev_wtns = UInt8::<ConstraintF>::new_witness_vec(
        //     cs.clone(),
        //     &{
        //         let h_prev = self.h_prev.unwrap_or(h_default);            // TODO: consider serializing outside circuit and passing u8 as input
        //         let mut h_prev_vec = vec![];
        //         h_prev.serialize_with_mode(&mut h_prev_vec, Compress::Yes);
        //         h_prev_vec
        //     },
        // ).unwrap();

        let rng = &mut OsRng;
        let default_sig = Signature::<C>{
            prover_response: C::ScalarField::rand(rng),
            verifier_challenge: vec![0u8;32],
        };
        let schnorr_sig_wtns = SchnorrSignatureVar::<C,GG>::new_variable(
            cs.clone(),
            || {
                Ok(self.schnorr_sig.as_ref().unwrap_or(&default_sig))
            },
            AllocationMode::Witness,
        ).unwrap();

        let default_schnorr_params = SchnorrParameters::<C> {
            generator: C::Affine::default(),
            salt: None,
        };
        let schnorr_param_wtns = SchnorrParametersVar::<C,GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_params.as_ref().unwrap_or(&default_schnorr_params)),
            AllocationMode::Witness,
        ).unwrap();

        let affine_default = C::Affine::default();
        let schnorr_pk_wtns = PublicKeyVar::<C,GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_pk.as_ref().unwrap_or(&affine_default)),
            AllocationMode::Witness,
        ).unwrap();

        let schnorr_msg_wtns = UInt8::<ConstraintF>::new_witness_vec(
            cs.clone(),
            self.schnorr_msg.as_ref().unwrap_or(&vec![0u8;32])
        ).unwrap();

        println!("here2");
        let verified: Boolean<ConstraintF> = <SchnorrSignatureVerifyGadget::<C, GG> as SigVerifyGadget::<Schnorr<C>, ConstraintF>>::verify(&schnorr_param_wtns, &schnorr_pk_wtns, &schnorr_msg_wtns, &schnorr_sig_wtns).unwrap();
        println!("verified inside gadget {:?}", verified.value());
        println!("here3");
        let verified_select = first_login_wtns.select(&Boolean::<ConstraintF>::Constant(true), &verified).unwrap();
        println!("here4");
        verified_select.enforce_equal(&Boolean::Constant(true));
        
        // // println!("enforce equal 3 {:?}", computed_hash_wtns.is_eq(&h_cur_wtns).unwrap().value());
        // let end = start.elapsed();
        // println!("end2 {:?}", end);
        // let start = Instant::now();
        // let computed_prev_hash_wtns = UInt8::<ConstraintF>::new_witness_vec(
        //     cs.clone(),
        //     &{
        //         let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&poseidon_params_default);
        //         // let mut prev_input = vec![];
        //         let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&default_affine);
        //         // let mut elgamal_key_bytes = vec![];
        //         elgamal_key.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes);

        //         let i_value = self.i.as_ref().unwrap_or(&0);
        //         let selected_i_prev = UInt8::<ConstraintF>::conditionally_select(
        //             &Boolean::<ConstraintF>::constant(*i_value == 0),
        //             &UInt8::<ConstraintF>::constant(0),
        //             &UInt8::<ConstraintF>::constant(i_value.checked_sub(1).unwrap_or(0)),   // both branches run
        //         )?;

        //         cur_input.extend_from_slice(&elgamal_key_bytes);
        //         cur_input.extend_from_slice(&[selected_i_prev.value().unwrap()]);
        //         elgamal_key_bytes.clear();
        //         let cur_input_fr = ConstraintF::from_be_bytes_mod_order(&cur_input);
        //         let result = CRH::<ConstraintF>::evaluate(&poseidon_params, [cur_input_fr]).unwrap();
        //         result.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes);

        //         // let output = first_login_wtns.select(&elgamal_key_bytes, &elgamal_key_bytes);
        //         elgamal_key_bytes
        //     },
        // ).unwrap();

        // let mut output = vec![];
        // for i in 0..computed_prev_hash_wtns.len() {
        //     let elem = first_login_wtns.select(&h_prev_wtns[i], &computed_prev_hash_wtns[i]).unwrap_or(UInt8::<ConstraintF>::constant(0));
        //     output.push(elem);
        // };
        
        // output.enforce_equal(&h_prev_wtns);

        // // let hmac_key = self.hmac_key.as_ref().unwrap_or(&[0u8;32]);
        // // let key = ConstraintF::deserialize_with_mode(&hmac_key[..], Compress::Yes, Validate::Yes).unwrap();
        // // FpVar::<ConstraintF>::new_variable (
        // //     cs.clone(),
        // //     || Ok(key),
        // //     AllocationMode::Input,
        // // ).unwrap();
        
        // // let reconstructed_hmac_wtns = UInt8::<ConstraintF>::new_witness_vec(
        // //     cs.clone(),
        // //     &{
        // //         /* reconstructed msg */
        // //         let mut h_bytes = vec![];
        // //         let h = self.h_prev.as_ref().unwrap_or(&h_default);
        // //         h.serialize_with_mode(&mut h_bytes, Compress::Yes);
        // //         let default_coords = (C::Affine::default(), C::Affine::default());
        // //         let mut v_0_bytes = vec![];
        // //         let mut v_1_bytes = vec![];
        // //         let v: &(C::Affine, C::Affine) = self.v_prev.as_ref().unwrap_or(&default_coords);
                
        // //         v.0.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
        // //         v.1.serialize_with_mode(&mut v_1_bytes, Compress::Yes).unwrap();

        // //         let mut msg: Vec<u8> = vec![];
        // //         msg.extend_from_slice(&h_bytes);
        // //         msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
        // //         msg.extend_from_slice(&v_1_bytes);

        // //         HMAC::mac(msg, hmac_key)
        // //     }
        // // ).unwrap();

        // // let hmac_wtns = UInt8::<ConstraintF>::new_witness_vec(
        // //     cs.clone(),
        // //     self.hmac.as_ref().unwrap_or(&[0u8;32]),
        // // ).unwrap();

        // // hmac_wtns.enforce_equal(&reconstructed_hmac_wtns);
        
        // let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF> (255, 2, 8, 24, 0);
        // let poseidon_params_default = PoseidonConfig::<ConstraintF>::new(8, 24, 31, mds, ark, 2, 1);

        // let end = start.elapsed();
        // println!("end2 {:?}", end);
        // let start = Instant::now();
        // let mut cur_input = vec![];
        // let mut elgamal_key_bytes = vec![];
        // let computed_hash_wtns = UInt8::<ConstraintF>::new_witness_vec(
        //     cs.clone(),
        //     &{
        //         let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&poseidon_params_default);
        //         // let mut cur_input = vec![];
        //         let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&default_affine);
        //         // let mut elgamal_key_bytes = vec![];
        //         elgamal_key.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes);
        //         cur_input.extend_from_slice(&elgamal_key_bytes);
        //         cur_input.extend_from_slice(&[*self.i.as_ref().unwrap_or(&0)]);
        //         let cur_input_fr = ConstraintF::from_be_bytes_mod_order(&cur_input);
        //         let result = CRH::<ConstraintF>::evaluate(&poseidon_params, [cur_input_fr]).unwrap();
        //         let mut result_vec = vec![];
        //         // result.clear();
        //         result.serialize_with_mode(&mut result_vec, Compress::Yes);
        //         result_vec
        //     },
        // ).unwrap();

        // cur_input.clear();
        // elgamal_key_bytes.clear();
        

        // let h_cur_wtns = UInt8::<ConstraintF>::new_witness_vec(
        //     cs.clone(),
        //     &{
        //         let h_cur = self.h_cur.unwrap_or(h_default);            // TODO: consider serializing outside circuit and passing u8 as input
        //         let mut h_cur_vec = vec![];
        //         h_cur.serialize_with_mode(&mut h_cur_vec, Compress::Yes);
        //         h_cur_vec
        //     },
        // ).unwrap();
        // computed_hash_wtns.enforce_equal(&h_cur_wtns);

        // let end = start.elapsed();
        // println!("end2 {:?}", end);
        
        Ok(())
    }
}

// impl<W, C> ConstraintSynthesizer<ConstraintF> for LoggingCircuit<W, C> where 
//     W: ark_crypto_primitives::crh::pedersen::Window,
//     ConstraintF: PrimeField,
//     C: CurveGroup,
//     // GG: CurveVar<C, ConstraintF>,
//     // for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
//     Namespace<<<C as CurveGroup>::BaseField as Field>::BasePrimeField>: From<ConstraintSystemRef<ConstraintF>>,
//     // C: CurveGroup<Affine = ark_ec::twisted_edwards::Affine<ark_ed25519::EdwardsConfig>>,
//     <<C as CurveGroup>::BaseField as Field>::BasePrimeField: ark_crypto_primitives::sponge::Absorb,
// {
//     fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF>) -> Result<(), SynthesisError> { 
//         let affine_default = C::Affine::default();
//         // let sig_default = Signature::<C>::default();
//         // let schnorr_param_default = SchnorrParameters {
//         //     generator: EdwardsAffine::default(),
//         //     salt: Some([0u8; 32]),
//         // };
//         let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF> (255, 2, 8, 24, 0);
//         let poseidon_params_default = PoseidonConfig::<ConstraintF>::new(8, 24, 31, mds, ark, 2, 1);
//         let pedersen_rand_default = PedersenRandomness::<C>::default();
//         let pedersen_param_default = PedersenParameters::<C> {
//             randomness_generator: vec![],
//             generators: vec![vec![];16],        // NUM_WINDOWS=16 hardcoded
//         };

//         let mut cur_input = vec![];
//         let mut elgamal_key_bytes = vec![];

//         println!("logging1");
//         /* Check h_i hashes correct Elgamal key. */
//         let computed_hash_wtns = UInt8::<ConstraintF>::new_witness_vec(
//             cs.clone(),
//             &{
//                 let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&poseidon_params_default);
//                 let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&affine_default);
//                 elgamal_key.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes);
//                 cur_input.extend_from_slice(&elgamal_key_bytes);
//                 cur_input.extend_from_slice(&[*self.i.as_ref().unwrap_or(&0)]);
//                 let cur_input_fr = ConstraintF::from_be_bytes_mod_order(&cur_input);
                // let result = CRH::<ConstraintF>::evaluate(&poseidon_params, [cur_input_fr]).unwrap();
//                 let mut result_vec = vec![];
//                 result.serialize_with_mode(&mut result_vec, Compress::Yes);
//                 result_vec
//             },
//         ).unwrap();

//         let h_cur_wtns = UInt8::<ConstraintF>::new_witness_vec(
//             cs.clone(),
//             &{
//                 let h_cur = self.h_cur.unwrap_or(ConstraintF::default());            // TODO: consider serializing outside circuit and passing u8 as input
//                 let mut h_cur_vec = vec![];
//                 h_cur.serialize_with_mode(&mut h_cur_vec, Compress::Yes);
//                 h_cur_vec
//             },
//         ).unwrap();

//         computed_hash_wtns.enforce_equal(&h_cur_wtns);

//         println!("logging2");
//         /* Check elgamal key commitment */
//         let elgamal_commit_x = self.elgamal_key_commit_x.unwrap_or(ConstraintF::one());
//         let elgamal_commit_y = self.elgamal_key_commit_y.unwrap_or(ConstraintF::one());
        
//         let elgamal_commit_proj = C::from(C::Affine::new_unchecked(elgamal_commit_x, elgamal_commit_y));       // THIS IS TWISTED EDWARDS

//         let reconstructed_commit_var = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
//             cs.clone(),
//             || Ok(elgamal_commit_proj),
//             AllocationMode::Input,
//         ).unwrap();

//         let default_elgamal_key = EncPubKey::<C>::default();
//         // let start = Instant::now();
//         let commit_input = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
//             cs.clone(),
//             || {
//                 let parameters = self.pedersen_params.as_ref().unwrap_or(&pedersen_param_default);
//                 let randomness = self.pedersen_rand_elgamal.as_ref().unwrap_or(&pedersen_rand_default);

//                 let mut h_vec = vec![0u8; 32];  // Vec<u8> avoids lifetime issues
//                 let pubkey = self.elgamal_key.as_ref().unwrap_or(&default_elgamal_key);
//                 pubkey.serialize_with_mode(&mut h_vec[..], Compress::Yes).unwrap();
            
//                 let input = h_vec;
                
//                 // If the input is too long, return an error.
//                 if input.len() > W::WINDOW_SIZE * W::NUM_WINDOWS {
//                     panic!("incorrect input length: {:?}", input.len());
//                 }
//                 // Pad the input to the necessary length.
//                 let mut padded_input = Vec::with_capacity(input.len());
//                 let mut input = input;
//                 if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
//                     padded_input.extend_from_slice(&input);
//                     let padded_length = (W::WINDOW_SIZE * W::NUM_WINDOWS) / 8;
//                     padded_input.resize(padded_length, 0u8);
//                     input = padded_input;
//                 }
//                 assert_eq!(parameters.generators.len(), W::NUM_WINDOWS);

//                 // Invoke Pedersen CRH here, to prevent code duplication.

//                 let crh_parameters = ark_crypto_primitives::crh::pedersen::Parameters {
//                     generators: parameters.generators.clone(),
//                 };
//                 let mut result: C = ark_crypto_primitives::crh::pedersen::CRH::<C,W>::evaluate(&crh_parameters, input).unwrap().into();

//                 // Compute h^r.
//                 for (bit, power) in BitIteratorLE::new(randomness.0.into_bigint())
//                     .into_iter()
//                     .zip(&parameters.randomness_generator)
//                 {
//                     if bit {
//                         result += power
//                     }
//                 }
//                 Ok(result)
//             },
//             AllocationMode::Witness,
//         ).unwrap();

//         println!("logging3");
//         commit_input.enforce_equal(&reconstructed_commit_var);
        
//         // println!("time commit {:?}", end);

//         let default_coords = (C::Affine::default(), C::Affine::default());
//         // println!("C::Affine::default() {:?}", C::Affine::default());
//         let v_cur_wtns = ElgamalCiphertextVar::<C,GG>::new_variable (
//             cs.clone(),
//             || Ok(self.v_cur.as_ref().unwrap_or(&default_coords)),
//             AllocationMode::Witness,
//         ).unwrap();

//         /* Check encryption of correct context (using correct Elgamal key) */
//         // let default_rand = EncRand::<C>(C::ScalarField::one());
//         // let default_param = EncParams::<C>{generator: C::Affine::default()};
//         // let default_param = EncParams::<C>{ generator: C::Affine::default() };
//         let reconstructed_v_cur_wtns = ElgamalCiphertextVar::<C,GG>::new_variable (
//             cs.clone(),
//             || {
//                 let record_x = self.record_x.as_ref().unwrap();
//                 let record_y = self.record_y.as_ref().unwrap();
//                 // println!("record x {:?}", record_x);
//                 // println!("record y {:?}", record_y);
//                 // println!("GroupAffine::<ark_ed_on_bn254::EdwardsParameters>::new(*record_x, *record_y).into() {:?}", GroupAffine::<ark_ed_on_bn254::EdwardsParameters>::new(*record_x, *record_y));
//                 // let test: GroupProjective::<ark_ed_on_bn254::EdwardsParameters> = GroupAffine::<ark_ed_on_bn254::EdwardsParameters>::new(*record_x, *record_y).into();
//                 // println!("test {:?}", test);
//                 let record_input: C::Affine = ark_ec::twisted_edwards::Affine::<EdwardsConfig>::new_unchecked(*record_x, *record_y);

//                 let elgamal_param_input = self.elgamal_params.as_ref().unwrap();
//                 let pubkey = self.elgamal_key.as_ref().unwrap();
//                 let elgamal_rand = self.elgamal_rand.as_ref().unwrap();
//                 println!("logging3-1");
                
//                 let ciphertext: (C::Affine, C::Affine) = ElGamal::<C>::encrypt(elgamal_param_input, pubkey, &record_input, elgamal_rand).unwrap();
//                 // let test1: (GroupAffine::<EdwardsParameters>, GroupAffine::<EdwardsParameters>) = ciphertext.into();
//                 // println!("default affine {:?}", C::Affine::default());
//                 println!("logging3-2");
//                 // println!("ciphertext.0 {:?}", ciphertext.0);
//                 // println!("ciphertext.1 {:?}", ciphertext.1);
//                 // let test: GroupProjective::<ark_ed_on_bn254::EdwardsParameters> = GroupAffine::<ark_ed_on_bn254::EdwardsParameters>::new(ciphertext.0, ciphertext.0).into();
//                 // println!("test {:?}", test);
//                 Ok((ciphertext.0, ciphertext.1))
//             },
//             AllocationMode::Witness,
//         ).unwrap();

//         println!("logging4");
//         v_cur_wtns.enforce_equal(&reconstructed_v_cur_wtns);

//         /* Check aggregated signature */

//         let reconstructed_msg_wtns = UInt8::<ConstraintF>::new_witness_vec(
//             cs.clone(),
//             &{
//                 let mut h_bytes = vec![];
//                 let default = ConstraintF::default();
//                 let h = self.h_cur.as_ref().unwrap_or(&default);
//                 h.serialize_with_mode(&mut h_bytes, Compress::Yes);
//                 let default_coords = (C::Affine::default(), C::Affine::default());
//                 let mut v_0_bytes = vec![];
//                 let mut v_1_bytes = vec![];
//                 let v: &(C::Affine, C::Affine) = self.v_cur.as_ref().unwrap_or(&default_coords);
                
//                 v.0.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
//                 v.1.serialize_with_mode(&mut v_1_bytes, Compress::Yes).unwrap();

//                 let mut msg: Vec<u8> = vec![];
//                 msg.extend_from_slice(&h_bytes);
//                 msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
//                 msg.extend_from_slice(&v_1_bytes);

//                 // println!("reconstructed msg {:?}", msg);
//                 msg
//             }
//         ).unwrap();

//         // let start = Instant::now();
        
//         println!("logging5");
//         let schnorr_param_const = ParametersVar::<C>::new_variable(
//             cs.clone(),
//             || Ok(self.schnorr_params.as_ref().unwrap_or(&schnorr_param_default)),
//             AllocationMode::Constant,
//         ).unwrap();

//         /* SCHNORR SIG VERIFY GADGET */
//         let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF> (255, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255
//         let poseidon_params = PoseidonConfig::<ConstraintF>::new(8, 24, 31, mds, ark, 2, 1);
        
//         let mut poseidon_params_wtns = CRHParametersVar::<ConstraintF>::new_variable(
//             cs.clone(),
//             || Ok(self.poseidon_params.as_ref().unwrap_or(&poseidon_params_default)),
//             AllocationMode::Witness,
//         )?;

//         let schnorr_apk_input = SchnorrPublicKeyVar::<C>::new_variable(
//             cs.clone(),
//             || Ok(self.schnorr_apk.as_ref().unwrap_or(&affine_default)),
//             AllocationMode::Input,          // NOTE: this should be witness when RP is verifying circuit
//         ).unwrap();

//         let schnorr_sig_wtns = SchnorrSignatureVar::<C>::new_variable(
//             cs.clone(),
//             || Ok(self.schnorr_sig.as_ref().unwrap_or(&sig_default)),
//             AllocationMode::Witness,
//         ).unwrap();

//         let schnorr_verified = SchnorrSignatureVerifyGadget::<C>::verify(
//             cs.clone(),
//             &schnorr_param_const,
//             &schnorr_apk_input,
//             &reconstructed_msg_wtns,
//             &schnorr_sig_wtns,
//             &mut poseidon_params_wtns,
//         ).unwrap();
//         println!("logging6");

//         schnorr_verified.enforce_equal(&Boolean::TRUE)?;
        
//         /* Check that the schnorr_apk provided is the apk committed to at registration and given to RP. */

//         let apk_commit_x = self.apk_commit_x.unwrap_or(ConstraintF::one());
//         let apk_commit_y = self.apk_commit_y.unwrap_or(ConstraintF::one());
        
//         // println!("here2");
//         let apk_commit_proj = C::from(EdwardsAffine::new_unchecked(apk_commit_x, apk_commit_y).into());       // THIS IS TWISTED EDWARDS
//         // println!("APK COMMIT PROJ {:?}", apk_commit_proj);
//         let reconstructed_commit_var = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
//             cs.clone(),
//             || Ok(apk_commit_proj),
//             AllocationMode::Input,
//         ).unwrap();

//         // println!("reconstructed_commit_var {:?}", reconstructed_commit_var.value());

//         // let end = start.elapsed();
//         // println!("time 3 {:?}", end);

//         // let start = Instant::now();
//         let commit_wtns = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
//             cs.clone(),
//             || {
//                 let parameters = self.pedersen_params.as_ref().unwrap_or(&pedersen_param_default);
//                 let randomness = self.pedersen_rand.as_ref().unwrap_or(&pedersen_rand_default);

//                 let mut h_vec = vec![0u8; 32];  // Vec<u8> avoids lifetime issues
//                 let apk = self.schnorr_apk.as_ref().unwrap_or(&affine_default);
//                 apk.serialize_with_mode(&mut h_vec[..], Compress::Yes).unwrap();

//                 let input = h_vec;
                
//                 // If the input is too long, return an error.
//                 if input.len() > W::WINDOW_SIZE * W::NUM_WINDOWS {
//                     panic!("incorrect input length: {:?}", input.len());
//                 }
//                 // Pad the input to the necessary length.
//                 let mut padded_input = Vec::with_capacity(input.len());
//                 let mut input = input;
//                 if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
//                     padded_input.extend_from_slice(&input);
//                     let padded_length = (W::WINDOW_SIZE * W::NUM_WINDOWS) / 8;
//                     padded_input.resize(padded_length, 0u8);
//                     input = padded_input;
//                 }
//                 assert_eq!(parameters.generators.len(), W::NUM_WINDOWS);

//                 // Invoke Pedersen CRH here, to prevent code duplication.

//                 let crh_parameters = ark_crypto_primitives::crh::pedersen::Parameters {
//                     // randomness_generator: parameters.randomness_generator.clone(),
//                     generators: parameters.generators.clone(),
//                 };
//                 let mut result: C = ark_crypto_primitives::crh::pedersen::CRH::<C,W>::evaluate(&crh_parameters, input).unwrap().into();

//                 // Compute h^r.
//                 for (bit, power) in BitIteratorLE::new(randomness.0.into_bigint())
//                     .into_iter()
//                     .zip(&parameters.randomness_generator)
//                 {
//                     if bit {
//                         result += power
//                     }
//                 }
//                 Ok(result)
//             },
//             AllocationMode::Witness,
//         ).unwrap();
//         commit_wtns.enforce_equal(&reconstructed_commit_var);
//         println!("logging7");
//         // println!("time 5 {:?}", end);
    
//         // println!("last in generate constraints");
//         Ok(())
//     }
// }

/* Benchmarking */

fn main() {
    /* Prove and verify Groth16 circuits 10 times to compute average times. */
    let mut logistics_total: Duration = Duration::default();
    let mut setup_total: Duration = Duration::default();
    let mut proof_time_total = Duration::default();
    let mut verify_time_total = Duration::default();
    for i in 0..10 {
        println!("InsertCircuit iteration {:?}", i);
        let rng = &mut OsRng;
        let new_circuit = generate_insert_circuit_for_setup();
        
        let start = Instant::now();
        // let new_circuit_for_setup = generate_logging_circuit_for_setup();
        logistics_total += start.elapsed();
        
        let start = Instant::now();
        let (pk, vk) = Groth16::<E>::circuit_specific_setup(new_circuit, rng).unwrap();
        let pvk: ark_groth16::PreparedVerifyingKey<E> = Groth16::<E>::process_vk(&vk).unwrap();
        println!("LENGTH: {:?}", pvk.vk.gamma_abc_g1.len());
        setup_total += start.elapsed();

        let new_circuit = generate_insert_circuit();
    
        let start = Instant::now();
        let proof = Groth16::<E>::prove(
            &pk,
            new_circuit,
            rng
        ).unwrap();
        proof_time_total += start.elapsed();

        let start = Instant::now();
        let verified = Groth16::<E>::verify_with_processed_vk(
            &pvk,
            &[],        // NOTE: No public inputs for new users (because they weren't supplied for prove phase)
            &proof,
        );
        verify_time_total += start.elapsed();
        println!("{:?}", verified);
    }

    println!("InsertCircuit Logistics time: {:?}", logistics_total/10);
    println!("InsertCircuit Setup time total: {:?}", setup_total/10);
    println!("InsertCircuit Prove time: {:?}", proof_time_total.as_millis()/10);
    println!("InsertCircuit Verify time: {:?}", verify_time_total.as_millis()/10);

    // let mut logistics_total: Duration = Duration::default();
    // let mut setup_total: Duration = Duration::default();
    // let mut proof_time_total = Duration::default();
    // let mut verify_time_total = Duration::default();
    // for i in 0..10 {
    //     println!("LoggingCircuit iteration {:?}", i);
    //     let rng = &mut OsRng;
    //     let (new_circuit, aggregated_pubkey, elgamal_commit, apk_commit) = generate_logging_circuit();
        
    //     let start = Instant::now();
    //     // let new_circuit_for_setup = generate_logging_circuit_for_setup();
    //     logistics_total += start.elapsed();

        
    //     let start = Instant::now();
    //     let (pk, vk) = Groth16::<E>::circuit_specific_setup(new_circuit, rng).unwrap();
    //     let pvk: ark_groth16::PreparedVerifyingKey<E> = Groth16::<E>::process_vk(&vk).unwrap();
    //     setup_total += start.elapsed();

    //     let (new_circuit, aggregated_pubkey, elgamal_commit, apk_commit) = generate_logging_circuit();
    //     let public_inputs = [
    //         elgamal_commit.x,
    //         elgamal_commit.y,
    //         aggregated_pubkey.x,
    //         aggregated_pubkey.y,
    //         apk_commit.x,
    //         apk_commit.y, 
    //     ];
    //     let start = Instant::now();
    //     let proof = Groth16::<E>::prove(
    //         &pk,
    //         new_circuit,
    //         rng
    //     ).unwrap();
    //     proof_time_total += start.elapsed();

    //     let start = Instant::now();
    //     let verified = Groth16::<E>::verify_with_processed_vk(
    //         &pvk,
    //         &public_inputs,        // NOTE: No public inputs for new users (because they weren't supplied for prove phase)
    //         &proof,
    //     );
    //     verify_time_total += start.elapsed();
    //     println!("{:?}", verified);
    // }
    // println!("LoggingCircuit Logistics time: {:?}", logistics_total/10);
    // println!("LoggingCircuit Setup time: {:?}", setup_total/10);
    // println!("LoggingCircuit Prove time: {:?}", proof_time_total.as_millis()/10);
    // println!("LoggingCircuit Verify time: {:?}", verify_time_total.as_millis()/10);
}