use nockvm::interpreter::Context;
use nockvm::jets::util::slot;
use nockvm::jets::JetErr;
use nockvm::noun::{Cell, IndirectAtom, Noun};
use tracing::debug;

use crate::form::math::fext::*;
use crate::form::poly::Poly;
use crate::form::{Belt, FPolySlice, Felt};
use crate::hand::handle::new_handle_mut_felt;
use crate::hand::structs::HoonList;
use crate::jets::utils::jet_err;
use crate::noun::noun_ext::NounExt;

pub fn evaluate_deep_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let sam = slot(subject, 6)?;
    let mut sam_cur: Cell = sam.as_cell()?;

    // Extract all parameters from the subject
    let trace_evaluations = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let comp_evaluations = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let trace_elems = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let comp_elems = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let num_comp_pieces = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let weights = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let heights = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let full_widths = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let omega = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let index = sam_cur.head();
    sam_cur = sam_cur.tail().as_cell()?;
    let deep_challenge = sam_cur.head();
    let new_comp_eval = sam_cur.tail();

    // Convert nouns to appropriate types
    let Ok(trace_evaluations) = FPolySlice::try_from(trace_evaluations) else {
        debug!("trace_evaluations is not a valid FPolySlice");
        return jet_err();
    };
    let Ok(comp_evaluations) = FPolySlice::try_from(comp_evaluations) else {
        debug!("comp_evaluations is not a valid FPolySlice");
        return jet_err();
    };
    let trace_elems: Vec<Belt> = HoonList::try_from(trace_elems)?
        .into_iter()
        .map(|x| x.as_atom().unwrap().as_u64().unwrap())
        .map(|x| Belt(x))
        .collect();
    let comp_elems: Vec<Belt> = HoonList::try_from(comp_elems)?
        .into_iter()
        .map(|x| x.as_atom().unwrap().as_u64().unwrap())
        .map(|x| Belt(x))
        .collect();
    let num_comp_pieces = num_comp_pieces.as_atom()?.as_u64()?;
    let Ok(weights) = FPolySlice::try_from(weights) else {
        debug!("weights is not a valid FPolySlice");
        return jet_err();
    };
    let heights: Vec<u64> = HoonList::try_from(heights)?
        .into_iter()
        .map(|x| x.as_atom().unwrap().as_u64().unwrap())
        .collect();
    let full_widths: Vec<u64> = HoonList::try_from(full_widths)?
        .into_iter()
        .map(|x| x.as_atom().unwrap().as_u64().unwrap())
        .collect();
    let omega = omega.as_felt()?;
    let index = index.as_atom()?.as_u64()?;
    let deep_challenge = deep_challenge.as_felt()?;
    let new_comp_eval = new_comp_eval.as_felt()?;

    //  TODO use g defined wherever it is
    let g = Felt::lift(Belt(7));
    let omega_pow = fmul_(&fpow_(&omega, index as u64), &g);

    let mut acc = Felt::zero();
    let mut num = 0usize;
    let mut total_full_width = 0usize;

    for (i, &height) in heights.iter().enumerate() {
        let full_width = full_widths[i] as usize;
        let omicron = Felt::lift(Belt(height).ordered_root()?);

        let current_trace_elems = &trace_elems[total_full_width..(total_full_width + full_width)];

        // Process first row trace columns
        let denom = fsub_(&omega_pow, &deep_challenge);
        (acc, num) = process_belt(
            current_trace_elems, &trace_evaluations.0, &weights.0, full_width, num, &denom, &acc,
        );

        // Process second row trace columns (shifted by omicron)
        let denom = fsub_(&omega_pow, &fmul_(&deep_challenge, &omicron));
        (acc, num) = process_belt(
            current_trace_elems, &trace_evaluations.0, &weights.0, full_width, num, &denom, &acc,
        );

        total_full_width += full_width;
    }

    total_full_width = 0;
    for (i, &height) in heights.iter().enumerate() {
        let full_width = full_widths[i] as usize;
        let omicron = Felt::lift(Belt(height).ordered_root()?);

        let current_trace_elems = &trace_elems[total_full_width..(total_full_width + full_width)];

        // Process first row trace columns with new_comp_eval
        let denom = fsub_(&omega_pow, &new_comp_eval);
        (acc, num) = process_belt(
            current_trace_elems, &trace_evaluations.0, &weights.0, full_width, num, &denom, &acc,
        );

        // Process second row trace columns with new_comp_eval (shifted by omicron)
        let denom = fsub_(&omega_pow, &fmul_(&new_comp_eval, &omicron));
        (acc, num) = process_belt(
            current_trace_elems, &trace_evaluations.0, &weights.0, full_width, num, &denom, &acc,
        );

        total_full_width += full_width;
    }

    // Process composition elements
    let denom = fsub_(&omega_pow, &fpow_(&deep_challenge, num_comp_pieces as u64));

    (acc, _) = process_belt(
        &comp_elems,
        &comp_evaluations.0,
        &weights.0[num..],
        num_comp_pieces as usize,
        0,
        &denom,
        &acc,
    );

    // Return the result as a Noun
    let (res_atom, res_felt): (IndirectAtom, &mut Felt) = new_handle_mut_felt(&mut context.stack);
    *res_felt = acc;

    Ok(res_atom.as_noun())
}

// Helper function for processing belts
fn process_belt(
    elems: &[Belt],
    evals: &[Felt],
    weights: &[Felt],
    width: usize,
    start_num: usize,
    denom: &Felt,
    acc_start: &Felt,
) -> (Felt, usize) {
    let mut acc = *acc_start;
    let mut num = start_num;

    for i in 0..width {
        let elem_val = Felt::lift(elems[i]);
        let eval_val = evals[num];
        let weight_val = weights[num];

        // (elem_val - eval_val) / denom * weight_val + acc
        let diff = fsub_(&elem_val, &eval_val);
        let term = fmul_(&fdiv_(&diff, denom), &weight_val);
        acc = fadd_(&acc, &term);

        num += 1;
    }

    (acc, num)
}
