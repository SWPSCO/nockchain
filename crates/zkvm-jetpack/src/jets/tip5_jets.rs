use bitvec::prelude::{BitSlice, Lsb0};
use bitvec::view::BitView;
use nockvm::interpreter::Context;
use nockvm::jets::list::util::lent;
use nockvm::jets::util::slot;
use nockvm::jets::JetErr;
use nockvm::noun::Noun;

use crate::based;
use crate::form::math::tip5::*;
use crate::form::{Belt, Poly};
use crate::jets::utils::jet_err;
use crate::utils::{
    belt_as_noun, bitslice_to_u128, fits_in_u128, hoon_list_to_vecbelt, vec_to_hoon_list,
};

pub fn hoon_list_to_sponge(list: Noun) -> Result<[u64; STATE_SIZE], JetErr> {
    if list.is_atom() {
        return jet_err();
    }

    let mut sponge = [0; STATE_SIZE];
    let mut current = list;
    let mut i = 0;

    while current.is_cell() {
        let cell = current.as_cell()?;
        sponge[i] = cell.head().as_atom()?.as_u64()?;
        current = cell.tail();
        i = i + 1;
    }

    if i != STATE_SIZE {
        return jet_err();
    }

    Ok(sponge)
}

pub fn permutation_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let sample = slot(subject, 6)?;
    let mut sponge = hoon_list_to_sponge(sample)?;
    permute(&mut sponge);

    let new_sponge = vec_to_hoon_list(context, &sponge);

    Ok(new_sponge)
}

pub fn hash_varlen_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let input = slot(subject, 6)?;
    let mut input_vec = hoon_list_to_vecbelt(input)?;
    let mut sponge = [0u64; STATE_SIZE];

    // assert that input is made of base field elements
    input_vec.iter().for_each(|b| based!(b.0));

    // pad input with ~[1 0 ... 0] to be a multiple of rate
    let lent_input = lent(input)?;
    let (q, r) = (lent_input / RATE, lent_input % RATE);
    input_vec.push(Belt(1));
    for _i in 0..(RATE - r) - 1 {
        input_vec.push(Belt(0));
    }

    // bring input into montgomery space
    let mut input_montiplied: Vec<Belt> = vec![Belt(0); input_vec.len()];
    for i in 0..input_vec.len() {
        input_montiplied[i] = montify(input_vec[i]);
    }

    // process input in batches of size RATE
    let mut cnt_q = q;
    let mut input_to_absorb = input_montiplied.as_slice();
    loop {
        let (scag_input, slag_input) = input_to_absorb.split_at(RATE);
        absorb_rate(&mut sponge, scag_input);

        if cnt_q == 0 {
            break;
        }
        cnt_q = cnt_q - 1;
        input_to_absorb = slag_input;
    }

    // calc digest
    let mut digest = [0u64; DIGEST_LENGTH];
    for i in 0..DIGEST_LENGTH {
        digest[i] = mont_reduction(sponge[i] as u128).0;
    }

    Ok(vec_to_hoon_list(context, &digest))
}

fn absorb_rate(sponge: &mut [u64; 16], input: &[Belt]) {
    assert_eq!(input.len(), RATE);

    for copy_pos in 0..RATE {
        sponge[copy_pos] = input[copy_pos].0;
    }

    permute(sponge);
}

pub fn montify_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let stack = &mut context.stack;
    let sam = slot(subject, 6)?;
    let x = Belt(sam.as_atom()?.as_u64()?);

    let res = montify(x);

    Ok(belt_as_noun(stack, res))
}

fn montify(x: Belt) -> Belt {
    // transform to Montgomery space, i.e. compute x•r = xr mod p
    montiply(x, Belt(R2))
}

pub fn montiply_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let sam = slot(subject, 6)?;
    let a = Belt(sam.as_cell()?.head().as_atom()?.as_u64()?);
    let b = Belt(sam.as_cell()?.tail().as_atom()?.as_u64()?);
    Ok(belt_as_noun(&mut context.stack, montiply(a, b)))
}

fn montiply(a: Belt, b: Belt) -> Belt {
    // computes a*b = (abr^{-1} mod p)
    based!(a.0);
    based!(b.0);
    mont_reduction((a.0 as u128) * (b.0 as u128))
}

pub fn mont_reduction_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let sam = slot(subject, 6)?;
    let x_atom = sam.as_atom()?;

    let x_u128: u128 = if x_atom.is_indirect() {
        if x_atom.as_indirect()?.size() > 2 {
            // mont_reduction asserts that x < RP, so u128 should be sufficient anyway??!!
            let x_bitslice = x_atom.as_bitslice();
            assert!(fits_in_u128(x_bitslice));
            bitslice_to_u128(x_bitslice)
        } else if x_atom.as_indirect()?.size() == 2 {
            let x = unsafe { x_atom.as_u64_pair()? };
            ((x[1] as u128) << 64u128) + (x[0] as u128)
        } else {
            x_atom.as_u64()? as u128
        }
    } else {
        x_atom.as_u64()? as u128
    };

    Ok(belt_as_noun(&mut context.stack, mont_reduction(x_u128)))
}

fn mont_reduction(x: u128) -> Belt {
    // mont-reduction: computes x•r^{-1} = (xr^{-1} mod p).
    assert!(x < RP);

    const R_MOD_P1: u128 = (R_MOD_P + 1) as u128; // 4.294.967.296
    const RX: u128 = R; // 18.446.744.073.709.551.616
    const PX: u128 = P as u128; // 0xffffffff00000001

    let parts: [u64; 2] = [
        (x & 0xFFFFFFFFFFFFFFFF) as u64, // lower 64 bits
        (x >> 64) as u64,                // upper 64 bits
    ];
    let x_bitslice: &BitSlice<u64, Lsb0> = parts.view_bits::<Lsb0>();
    let x_u128 = bitslice_to_u128(x_bitslice);

    let x1_u128_div = x_u128 / R_MOD_P1;
    let x1_u128 = x1_u128_div % R_MOD_P1;
    let x2_u128 = x_u128 / RX;
    let x0_u128 = x_u128 % R_MOD_P1;
    let c_u128 = (x0_u128 + x1_u128) * R_MOD_P1;
    let f_u128 = c_u128 / RX;
    let d_u128 = c_u128 - (x1_u128 + (f_u128 * PX));

    let res = if x2_u128 >= d_u128 {
        x2_u128 - d_u128
    } else {
        (x2_u128 + PX) - d_u128
    };

    Belt(res as u64)
}

#[cfg(test)]
mod tests {
    use nockvm::jets::util::test::*;
    use nockvm::noun::{D, T};

    use super::*;
    use crate::utils::u128_as_noun;

    #[test]
    fn test_mont_reduction_jet() {
        let c = &mut init_context();

        // [%mont-reduction-x 18.446.744.065.119.617.025]
        // [%mont-reduction-res 4.294.967.295]
        let sam = belt_as_noun(&mut c.stack, Belt(18446744065119617025));
        let res = D(4294967295);
        assert_jet(c, mont_reduction_jet, sam, res);

        // [%mont-reduction-x 45.157.629.471.412.822.477.200]
        // [%mont-reduction-res 10.514.079.938.160]
        let sam = u128_as_noun(&mut c.stack, 45157629471412822477200u128);
        let res = D(10514079938160);
        assert_jet(c, mont_reduction_jet, sam, res);

        // [%mont-reduction-x 0]
        // [%mont-reduction-res 0]
        let sam = D(0);
        let res = D(0);
        assert_jet(c, mont_reduction_jet, sam, res);

        // [%mont-reduction-x 24.583.549.534.147.014.201.149.663.878.358.805.000]
        // [%mont-reduction-res 6.813.007.285.744.613.222]
        let sam = u128_as_noun(&mut c.stack, 24583549534147014201149663878358805000u128);
        let res = u128_as_noun(&mut c.stack, 6813007285744613222);
        assert_jet(c, mont_reduction_jet, sam, res);
    }

    #[test]
    fn test_montify_jet() {
        let c = &mut init_context();

        let sam = D(1);
        let res = D(4294967295);
        assert_jet(c, montify_jet, sam, res);

        let sam = D(122);
        let res = D(523986009990);
        assert_jet(c, montify_jet, sam, res);

        let sam = D(127128);
        let res = D(546010602278760);
        assert_jet(c, montify_jet, sam, res);

        let sam = D(127128129);
        let res = D(546011156329541055);
        assert_jet(c, montify_jet, sam, res);

        let sam = D(127128129130);
        let res = belt_as_noun(&mut c.stack, Belt(11055578874863858041));
        assert_jet(c, montify_jet, sam, res);

        let sam = D(127128129130131);
        let res = belt_as_noun(&mut c.stack, Belt(5979177847162748366));
        assert_jet(c, montify_jet, sam, res);
    }

    #[test]
    fn test_hash_varlen_jet() {
        let c = &mut init_context();

        // [%test-hash-varlen-tv ~]
        let b11048995573592393898 = belt_as_noun(&mut c.stack, Belt(11048995573592393898));
        let sam = D(0);
        let res = T(
            &mut c.stack,
            &[
                b11048995573592393898,
                D(6655187932135147625),
                D(8573492257662932655),
                D(4379820112787053727),
                D(3881663824627898703),
                D(0),
            ],
        );
        assert_jet(c, hash_varlen_jet, sam, res);

        // [%test-hash-varlen-tv [i=2 t=~]]
        let b12061287490523852513 = belt_as_noun(&mut c.stack, Belt(12061287490523852513));
        let sam = T(&mut c.stack, &[D(2), D(0)]);
        let res = T(
            &mut c.stack,
            &[
                D(8342164316692288712),
                b12061287490523852513,
                D(4038969618836824144),
                D(5830796451787599265),
                D(468390350313364562),
                D(0),
            ],
        );
        assert_jet(c, hash_varlen_jet, sam, res);

        // [%test-hash-varlen-tv [i=5 t=[i=26 t=~]]]
        let b13674194094340317530 = belt_as_noun(&mut c.stack, Belt(13674194094340317530));
        let b13743008867885290460 = belt_as_noun(&mut c.stack, Belt(13743008867885290460));
        let sam = T(&mut c.stack, &[D(5), D(26), D(0)]);
        let res = T(
            &mut c.stack,
            &[
                D(4045697570544439560),
                b13674194094340317530,
                b13743008867885290460,
                D(6020910684025273897),
                D(3362765570390427021),
                D(0),
            ],
        );
        assert_jet(c, hash_varlen_jet, sam, res);

        let c = &mut init_context();
        // (hash-varlen:tip5.zeke ~[1 2.448 1 0 0 0 0 0 0 0])
        // [ i=12.811.986.333.282.368.874
        //   t=[i=13.601.598.673.786.067.780 t=~[3.807.788.325.936.413.287 5.511.165.615.113.400.862 11.490.077.061.305.916.457]]
        // ]
        let b12811986333282368874 = belt_as_noun(&mut c.stack, Belt(12811986333282368874));
        let b13601598673786067780 = belt_as_noun(&mut c.stack, Belt(13601598673786067780));
        let b11490077061305916457 = belt_as_noun(&mut c.stack, Belt(11490077061305916457));
        let sam = T(
            &mut c.stack,
            &[D(1), D(2448), D(1), D(0), D(0), D(0), D(0), D(0), D(0), D(0), D(0)],
        );
        let res = T(
            &mut c.stack,
            &[
                b12811986333282368874,
                b13601598673786067780,
                D(3807788325936413287),
                D(5511165615113400862),
                b11490077061305916457,
                D(0),
            ],
        );
        assert_jet(c, hash_varlen_jet, sam, res);
    }
}
