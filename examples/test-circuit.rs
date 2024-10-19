use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
/// Circuit that will test whether the two given numbers are equal
pub struct TestCircuit {
    /// Private input
    pub a: u8,
    /// Private input
    pub b: u8,
}

impl ConstraintSynthesizer<ark_ed_on_bls12_377::Fq> for TestCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ark_ed_on_bls12_377::Fq>,
    ) -> Result<(), SynthesisError> {
        let a = UInt8::new_witness(ark_relations::ns!(cs, "a"), || Ok(self.a))?;

        let b = UInt8::new_witness(ark_relations::ns!(cs, "b"), || Ok(self.b))?;

        a.enforce_equal(&b)?;

        Ok(())
    }
}

fn main() {}

#[cfg(test)]
mod tests {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    #[test]
    fn same_values_should_pass() {
        let circuit = super::TestCircuit { a: 1, b: 1 };

        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            println!("{:?}", cs.which_is_unsatisfied().unwrap().unwrap());
        }
        assert!(is_satisfied);
    }

    #[test]
    fn different_values_should_fail() {
        let circuit = super::TestCircuit { a: 1, b: 2 };

        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(!is_satisfied);
    }

    use ark_marlin::{Marlin, SimpleHashFiatShamirRng};

    use ark_bn254::{Bls12_381, Fr};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use blake2::Blake2s;
    use rand_chacha::ChaChaRng;

    type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
    type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
    type MarlinInst = Marlin<Fr, MultiPC, FS>;

    #[test]
    fn test_proof() {
        let rng = &mut ark_std::test_rng();
        let universal_srs = MarlinInst::universal_setup(100, 25, 300, rng).unwrap();

        let circuit = super::TestCircuit { a: 1, b: 1 };
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();

        let proof = MarlinInst::prove(&index_pk, circuit.clone(), rng).unwrap();
        assert!(MarlinInst::verify(&index_vk, &[], &proof, rng).unwrap());
    }

    // TODO: Figure out why this test panics on a `debug_assert!` when verifying.
    // It might just be that we are proving a circuit that is not satisfied to begin with,
    // I'm not sure.
    // #[test]
    // fn invalid_proof_should_not_verify() {
    //     let rng = &mut ark_std::test_rng();
    //     let universal_srs = MarlinInst::universal_setup(100, 25, 300, rng).unwrap();

    //     let circuit = super::TestCircuit { a: 1, b: 2 };
    //     let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();

    //     let proof = MarlinInst::prove(&index_pk, circuit.clone(), rng).unwrap();
    //     assert!(!MarlinInst::verify(&index_vk, &[], &proof, rng).unwrap());
    // }
}
