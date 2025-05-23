use crate::form::bpoly::*;
use crate::form::poly::*;

//==============================================================================
// field extension methods
//==============================================================================

pub fn fadd(a: &Felt, b: &Felt, res: &mut Felt) {
    for i in 0..3 {
        res[i] = a[i] + b[i];
    }
}

pub fn fadd_(a: &Felt, b: &Felt) -> Felt {
    let mut res: Felt = Felt::zero();
    fadd(a, b, &mut res);
    res
}

pub fn fadd_self(a: &Felt, res: &mut Felt) {
    for i in 0..3 {
        res[i] = a[i] + res[i];
    }
}

#[inline(always)]
pub fn fsub(a: &Felt, b: &Felt, res: &mut Felt) {
    for i in 0..3 {
        res[i] = a[i] - b[i];
    }
}

pub fn fsub_(a: &Felt, b: &Felt) -> Felt {
    let mut res: Felt = Felt::zero();
    fsub(a, b, &mut res);
    res
}

#[inline(always)]
pub fn fneg(a: &Felt, res: &mut Felt) {
    for i in 0..3 {
        res[i] = -a[i];
    }
}

pub fn fneg_(a: &Felt) -> Felt {
    let mut res: Felt = Felt::zero();
    fneg(a, &mut res);
    res
}

#[inline(always)]
pub fn felt_to_bpoly(dat: &Felt) -> BPolyVec {
    PolyVec(vec![dat.0[0], dat.0[1], dat.0[2]])
}

pub const IRD: [Belt; 4] = [Belt(1), Belt(18446744069414584320), Belt(0), Belt(1)];

// See hoon comments for full explanation
#[inline(always)]
pub fn fmul(a: &Felt, b: &Felt, res: &mut Felt) {
    let poly_a: &[Belt] = &a.0;
    let poly_b: &[Belt] = &b.0;

    let a0: Belt = poly_a[0];
    let a1: Belt = poly_a[1];
    let a2: Belt = poly_a[2];
    let b0: Belt = poly_b[0];
    let b1: Belt = poly_b[1];
    let b2: Belt = poly_b[2];

    let a0b0: Belt = a0 * b0;
    let a1b1: Belt = a1 * b1;
    let a2b2: Belt = a2 * b2;
    let a0b1_a1b0: Belt = ((a0 + a1) * (b0 + b1) - a0b0) - a1b1;
    let a1b2_a2b1: Belt = ((a1 + a2) * (b1 + b2) - a1b1) - a2b2;
    let a0b2_a2b0: Belt = ((a0 + a2) * (b0 + b2) - a0b0) - a2b2;

    res.0[0] = a0b0 - a1b2_a2b1;
    res.0[1] = (a0b1_a1b0 + a1b2_a2b1) - a2b2;
    res.0[2] = a0b2_a2b0 + a1b1 + a2b2;
}

pub fn fmul_(a: &Felt, b: &Felt) -> Felt {
    let mut res = Felt::zero();
    fmul(a, b, &mut res);
    res
}

pub fn fscal_(a: &Belt, b: &Felt) -> Felt {
    Felt([b.0[0] * *a, b.0[1] * *a, b.0[2] * *a])
}

pub fn fscal_self(a: &Belt, b: &mut Felt) {
    b.0[0] = b.0[0] * *a;
    b.0[1] = b.0[1] * *a;
    b.0[2] = b.0[2] * *a;
}

const POLY: [Belt; 4] = [Belt(1), Belt(18446744069414584320), Belt(0), Belt(1)];

pub const DUV_LEN: usize = 4;

#[inline(always)]
pub fn finv(a: &Felt, res: &mut Felt) {
    let poly_a: &[Belt] = a.into();

    let mut poly_d = [Belt(0); DUV_LEN];
    let mut poly_u = [Belt(0); DUV_LEN];
    let mut poly_v = [Belt(0); DUV_LEN];
    let poly_bpoly = POLY.as_slice();

    bpegcd(
        poly_bpoly,
        poly_a,
        poly_d.as_mut_slice(),
        poly_u.as_mut_slice(),
        poly_v.as_mut_slice(),
    );

    bpscal(poly_d[0].inv(), poly_v.as_slice(), &mut res.0);
}

pub fn finv_(a: &Felt) -> Felt {
    let mut res: Felt = Felt::zero();
    finv(a, &mut res);
    res
}

#[inline(always)]
pub fn fpow_(term: &Felt, exponent: u64) -> Felt {
    let mut res: Felt = Felt::zero();
    fpow(term, exponent, &mut res);
    res
}

#[inline(always)]
pub fn fpow(term: &Felt, exponent: u64, c: &mut Felt) {
    let a: &mut Felt = &mut term.clone();
    let mut b: u64 = exponent;
    *c = Felt::from([Belt(1), Belt(0), Belt(0)]);
    if b == 0 {
        return;
    }

    while b > 1 {
        let a_clone = *a;

        if b & 1 == 0 {
            fmul(&a_clone, &a_clone, a);
            b /= 2;
        } else {
            fmul(&c.clone(), a, c);
            fmul(&a_clone, &a_clone, a);
            b = (b - 1) / 2;
        }
    }
    fmul(&c.clone(), a, c);
}

#[inline(always)]
pub fn fdiv(a: &Felt, b: &Felt, res: &mut Felt) {
    let binv = &mut Felt::zero();
    finv(b, binv);
    fmul(a, binv, res);
}

#[inline(always)]
pub fn fdiv_(a: &Felt, b: &Felt) -> Felt {
    let mut res: Felt = Felt::zero();
    fdiv(a, b, &mut res);
    res
}
