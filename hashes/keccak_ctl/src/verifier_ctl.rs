use anyhow::Result;
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;
use plonky2::util::timing::TimingTree;
use starky_ctl::table::Table;

use crate::keccak_ctl_stark::KeccakCtl;
use crate::keccak_permutation::keccak_permutation_stark::KeccakPermutationStark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::proof_ctl::{KeccakCtlProof, KeccakCtlProofChallenges};
use starky_ctl::config::StarkConfig;
use starky_ctl::cross_table_lookup::{verify_cross_table_lookups, CtlCheckVars};
use starky_ctl::stark::Stark;
use starky_ctl::verifier::verify_stark_proof_with_challenges;
use crate::keccak_xor::xor_stark::KeccakXORStark;

pub fn keccak256verify_stark<F, C, const D: usize>(
    stark: KeccakCtl<F, D>,
    proof: KeccakCtlProof<F, C, D>,
) -> Result<()>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
    [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
    [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakXORStark::<F, D>::COLUMNS]:,
{
    let config = StarkConfig::standard_fast_config();

    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));

    let timing = TimingTree::new("verify", log::Level::Debug);

    let res = verify_proof(&stark, proof, &config);

    timing.print();

    res
}

pub fn verify_proof<F, C, const D: usize>(
    all_stark: &KeccakCtl<F, D>,
    all_proof: KeccakCtlProof<F, C, D>,
    config: &StarkConfig,
) -> Result<()>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
    [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
    [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakXORStark::<F, D>::COLUMNS]:,
{
    let KeccakCtlProofChallenges {
        stark_challenges,
        ctl_challenges,
    } = all_proof.get_challenges(all_stark, config);

    let nums_permutation_zs = all_stark.nums_permutation_zs(config);

    let KeccakCtl {
        keccak_permutation_stark,
        keccak_sponge_stark,
        keccak_xor_stark,
        cross_table_lookups,
    } = all_stark;

    let ctl_vars_per_table = CtlCheckVars::from_proofs(
        &all_proof.stark_proofs,
        cross_table_lookups,
        &ctl_challenges,
        &nums_permutation_zs,
    );

    verify_stark_proof_with_challenges(
        keccak_permutation_stark,
        all_proof.stark_proofs[Table::KeccakPermutation as usize].clone(),
        stark_challenges[Table::KeccakPermutation as usize].clone(),
        &ctl_vars_per_table[Table::KeccakPermutation as usize],
        config,
    )?;
    verify_stark_proof_with_challenges(
        keccak_sponge_stark,
        all_proof.stark_proofs[Table::KeccakSponge as usize].clone(),
        stark_challenges[Table::KeccakSponge as usize].clone(),
        &ctl_vars_per_table[Table::KeccakSponge as usize],
        config,
    )?;
    verify_stark_proof_with_challenges(
        keccak_xor_stark,
        all_proof.stark_proofs[Table::KeccakXor as usize].clone(),
        stark_challenges[Table::KeccakXor as usize].clone(),
        &ctl_vars_per_table[Table::KeccakXor as usize],
        config,
    )?;
    verify_cross_table_lookups::<F, D>(
        cross_table_lookups,
        all_proof.stark_proofs.map(|p| p.proof.openings.ctl_zs_last),
        config,
    )
}
