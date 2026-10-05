//! Hoon 135 primitive jets registered at the kernel's versioned paths.

use either::Either::{self, Left, Right};
use nockvm::jets::bits::*;
use nockvm::jets::hash::*;
use nockvm::jets::hot::HotEntry;
use nockvm::jets::list::*;
use nockvm::jets::math::*;
use nockvm::jets::serial::*;
use nockvm::jets::sort::*;

const K_135: Either<&[u8], (u64, u64)> = Right((b'k' as u64, 135));

pub const HOT_STATE: &[HotEntry] = &[
    (&[K_135, Left(b"one"), Left(b"add")], 1, jet_add),
    (&[K_135, Left(b"one"), Left(b"dec")], 1, jet_dec),
    (&[K_135, Left(b"one"), Left(b"div")], 1, jet_div),
    (&[K_135, Left(b"one"), Left(b"dvr")], 1, jet_dvr),
    (&[K_135, Left(b"one"), Left(b"gte")], 1, jet_gte),
    (&[K_135, Left(b"one"), Left(b"gth")], 1, jet_gth),
    (&[K_135, Left(b"one"), Left(b"lte")], 1, jet_lte),
    (&[K_135, Left(b"one"), Left(b"lth")], 1, jet_lth),
    (&[K_135, Left(b"one"), Left(b"max")], 1, jet_max),
    (&[K_135, Left(b"one"), Left(b"min")], 1, jet_min),
    (&[K_135, Left(b"one"), Left(b"mod")], 1, jet_mod),
    (&[K_135, Left(b"one"), Left(b"mul")], 1, jet_mul),
    (&[K_135, Left(b"one"), Left(b"sub")], 1, jet_sub),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"flop")],
        1,
        jet_flop,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"lent")],
        1,
        jet_lent,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"roll")],
        1,
        jet_roll,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"snag")],
        1,
        jet_snag,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"snip")],
        1,
        jet_snip,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"turn")],
        1,
        jet_turn,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"weld")],
        1,
        jet_weld,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"zing")],
        1,
        jet_zing,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"find")],
        1,
        jet_find,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"scag")],
        1,
        jet_scag,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"bex")],
        1,
        jet_bex,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"can")],
        1,
        jet_can,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"cat")],
        1,
        jet_cat,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"cut")],
        1,
        jet_cut,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"end")],
        1,
        jet_end,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"lsh")],
        1,
        jet_lsh,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"met")],
        1,
        jet_met,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"rap")],
        1,
        jet_rap,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"rep")],
        1,
        jet_rep,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"rev")],
        1,
        jet_rev,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"rip")],
        1,
        jet_rip,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"rsh")],
        1,
        jet_rsh,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"sew")],
        1,
        jet_sew,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"xeb")],
        1,
        jet_xeb,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"con")],
        1,
        jet_con,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"dis")],
        1,
        jet_dis,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"mix")],
        1,
        jet_mix,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"mug")],
        1,
        jet_mug,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"dor")],
        1,
        jet_dor,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"gor")],
        1,
        jet_gor,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"mor")],
        1,
        jet_mor,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"cue")],
        1,
        jet_cue,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"jam")],
        1,
        jet_jam,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"levy")],
        1,
        jet_levy,
    ),
    (
        &[K_135, Left(b"one"), Left(b"two"), Left(b"reap")],
        1,
        jet_reap,
    ),
];
