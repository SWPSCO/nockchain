use nockvm::interpreter::Context;
use nockvm::jets::util::slot;
use nockvm::jets::JetErr;
use nockvm::noun::{IndirectAtom, Noun};
use tracing::debug;

use crate::form::fext::*;
use crate::form::poly::*;
use crate::hand::handle::new_handle_mut_felt;
use crate::jets::utils::jet_err;
use crate::noun::noun_ext::NounExt;
use crate::utils::*;

pub fn fadd_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let sam = slot(subject, 6)?;
    let a = slot(sam, 2)?;
    let b = slot(sam, 3)?;

    let (Ok(a_felt), Ok(b_felt)) = (a.as_felt(), b.as_felt()) else {
        debug!("a or b not a felt");
        return jet_err();
    };
    let (res_atom, res_felt): (IndirectAtom, &mut Felt) = new_handle_mut_felt(&mut context.stack);
    fadd(a_felt, b_felt, res_felt);

    assert!(felt_atom_is_valid(res_atom));
    Ok(res_atom.as_noun())
}

pub fn fsub_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let sam = slot(subject, 6)?;
    let a = slot(sam, 2)?;
    let b = slot(sam, 3)?;

    let (Ok(a_felt), Ok(b_felt)) = (a.as_felt(), b.as_felt()) else {
        debug!("a or b not a felt");
        return jet_err();
    };
    let (res_atom, res_felt): (IndirectAtom, &mut Felt) = new_handle_mut_felt(&mut context.stack);
    fsub(a_felt, b_felt, res_felt);

    assert!(felt_atom_is_valid(res_atom));
    Ok(res_atom.as_noun())
}

pub fn fneg_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let a = slot(subject, 6)?;

    let Ok(a_felt) = a.as_felt() else {
        debug!("a not a felt");
        return jet_err();
    };
    let (res_atom, res_felt): (IndirectAtom, &mut Felt) = new_handle_mut_felt(&mut context.stack);
    fneg(a_felt, res_felt);

    assert!(felt_atom_is_valid(res_atom));
    Ok(res_atom.as_noun())
}

pub fn fmul_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let sam = slot(subject, 6)?;
    let a = slot(sam, 2)?;
    let b = slot(sam, 3)?;

    let (Ok(a_felt), Ok(b_felt)) = (a.as_felt(), b.as_felt()) else {
        debug!("a or b not a felt");
        return jet_err();
    };
    let (res_atom, res_felt): (IndirectAtom, &mut Felt) = new_handle_mut_felt(&mut context.stack);
    fmul(a_felt, b_felt, res_felt);

    assert!(felt_atom_is_valid(res_atom));
    Ok(res_atom.as_noun())
}

pub fn finv_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let a = slot(subject, 6)?;

    let Ok(a_felt) = a.as_felt() else {
        debug!("a is not a felt");
        return jet_err();
    };
    let (res_atom, res_felt): (IndirectAtom, &mut Felt) = new_handle_mut_felt(&mut context.stack);
    finv(a_felt, res_felt);

    assert!(felt_atom_is_valid(res_atom));
    Ok(res_atom.as_noun())
}

pub fn fdiv_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let sam = slot(subject, 6)?;
    let a = slot(sam, 2)?;
    let b = slot(sam, 3)?;

    let (Ok(a_felt), Ok(b_felt)) = (a.as_felt(), b.as_felt()) else {
        debug!("a or b not felts");
        return jet_err();
    };
    let (res_atom, res_felt): (IndirectAtom, &mut Felt) = new_handle_mut_felt(&mut context.stack);
    fdiv(a_felt, b_felt, res_felt);

    assert!(felt_atom_is_valid(res_atom));
    Ok(res_atom.as_noun())
}

pub fn fpow_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let sam = slot(subject, 6)?;
    let x = slot(sam, 2)?;
    let n = slot(sam, 3)?;

    let (Ok(x_felt), Ok(n_atom)) = (x.as_felt(), n.as_atom()) else {
        debug!("x not a felt or n not an atom");
        return jet_err();
    };
    let n_64 = n_atom.as_u64()?;
    let (res_atom, res_felt): (IndirectAtom, &mut Felt) = new_handle_mut_felt(&mut context.stack);
    fpow(x_felt, n_64, res_felt);

    assert!(felt_atom_is_valid(res_atom));
    Ok(res_atom.as_noun())
}
