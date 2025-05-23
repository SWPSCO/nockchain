use nockvm::interpreter::Context;
use nockvm::jets::util::slot;
use nockvm::jets::JetErr;
use nockvm::noun::{IndirectAtom, Noun};
use tracing::debug;

use crate::form::mary::*;
use crate::form::math::mary::*;
use crate::hand::handle::{finalize_mary, new_handle_mut_mary};
use crate::jets::utils::jet_err;

pub fn mary_swag_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let door = slot(subject, 7)?;
    let ma = slot(door, 6)?;
    let sam = slot(subject, 6)?;
    let i = sam.as_cell()?.head().as_direct()?.data() as usize;
    let j = sam.as_cell()?.tail().as_direct()?.data() as usize;

    let Ok(mary) = MarySlice::try_from(ma) else {
        debug!("cannot convert mary arg to mary");
        return jet_err();
    };

    let (res, res_poly): (IndirectAtom, MarySliceMut) =
        new_handle_mut_mary(&mut context.stack, mary.step as usize, j);
    let step = mary.step as usize;

    res_poly
        .dat
        .copy_from_slice(&mary.dat[(i * step)..(i + j) * step]);

    let res_cell = finalize_mary(&mut context.stack, step, j, res);
    Ok(res_cell)
}

pub fn mary_weld_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let door = slot(subject, 7)?;
    let ma = slot(door, 6)?;
    let ma2 = slot(subject, 6)?;

    let step = ma.as_cell()?.head().as_direct()?.data() as u32;
    let step2 = ma2.as_cell()?.head().as_direct()?.data() as u32;
    if step != step2 {
        debug!("can only weld marys of same step");
        return jet_err();
    }

    let (Ok(mary1), Ok(mary2)) = (MarySlice::try_from(ma), MarySlice::try_from(ma2)) else {
        debug!("mary1 or mary2 is not an fpoly");
        return jet_err();
    };
    let res_len = mary1.len + mary2.len;
    let (res, res_poly): (IndirectAtom, MarySliceMut) =
        new_handle_mut_mary(&mut context.stack, step as usize, res_len as usize);

    mary_weld(mary1, mary2, res_poly);
    let res_cell = finalize_mary(&mut context.stack, step as usize, res_len as usize, res);
    Ok(res_cell)
}

pub fn mary_transpose_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let door = slot(subject, 7)?;
    let ma = slot(door, 6)?;
    let offset = slot(subject, 6)?;

    let (Ok(mary), Ok(offset)) = (MarySlice::try_from(ma), offset.as_atom()?.as_u64()) else {
        debug!("fp is not an fpoly or n is not an atom");
        return jet_err();
    };

    let offset = offset as usize;

    let (res, mut res_poly): (IndirectAtom, MarySliceMut) = new_handle_mut_mary(
        &mut context.stack,
        mary.len as usize * offset,
        mary.step as usize / offset,
    );

    mary_transpose(mary, offset, &mut res_poly);

    let res_cell = finalize_mary(
        &mut context.stack, res_poly.step as usize, res_poly.len as usize, res,
    );

    Ok(res_cell)
}
