use std::ops::{Add, Div, Mul, Neg, Sub};

use nockvm::noun::Noun;
use num_traits::Pow;
use tracing::debug;

use crate::based;
use crate::form::math::base::*;
use crate::form::poly::Belt;

const ROOTS: &[u64] = &[
    0x0000000000000001, 0xffffffff00000000, 0x0001000000000000, 0xfffffffeff000001,
    0xefffffff00000001, 0x00003fffffffc000, 0x0000008000000000, 0xf80007ff08000001,
    0xbf79143ce60ca966, 0x1905d02a5c411f4e, 0x9d8f2ad78bfed972, 0x0653b4801da1c8cf,
    0xf2c35199959dfcb6, 0x1544ef2335d17997, 0xe0ee099310bba1e2, 0xf6b2cffe2306baac,
    0x54df9630bf79450e, 0xabd0a6e8aa3d8a0e, 0x81281a7b05f9beac, 0xfbd41c6b8caa3302,
    0x30ba2ecd5e93e76d, 0xf502aef532322654, 0x4b2a18ade67246b5, 0xea9d5a1336fbc98b,
    0x86cdcc31c307e171, 0x4bbaf5976ecfefd8, 0xed41d05b78d6e286, 0x10d78dd8915a171d,
    0x59049500004a4485, 0xdfa8c93ba46d2666, 0x7e9bd009b86a0845, 0x400a7f755588e659,
    0x185629dcda58878c,
];

impl Belt {
    #[inline(always)]
    pub fn zero() -> Self {
        Belt(Default::default())
    }

    #[inline(always)]
    pub fn one() -> Self {
        Belt(1)
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub fn is_one(&self) -> bool {
        self.0 == 1
    }

    #[inline(always)]
    pub fn ordered_root(&self) -> Result<Self, FieldError> {
        // Belt(bpow(H, ORDER / self.0))
        let log_of_self = self.0.ilog2();
        if (log_of_self as usize) >= ROOTS.len() {
            debug!("ordered_root: out of bounds");
            return Err(FieldError::OrderedRootError);
        }
        // assert that it was an even power of two
        if self.0 != 1 << log_of_self {
            debug!("ordered_root: not power of two");
            return Err(FieldError::OrderedRootError);
        }
        Ok(ROOTS[log_of_self as usize].into())
    }

    #[inline(always)]
    pub fn inv(&self) -> Self {
        Belt(binv(self.0))
    }
}

impl Add for Belt {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        Belt(badd(a, b))
    }
}

impl Sub for Belt {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        Belt(bsub(a, b))
    }
}

impl Neg for Belt {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        let a = self.0;
        Belt(bneg(a))
    }
}

impl Mul for Belt {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        Belt(bmul(a, b))
    }
}

impl Pow<usize> for Belt {
    type Output = Self;

    #[inline(always)]
    fn pow(self, rhs: usize) -> Self::Output {
        Belt(bpow(self.0, rhs as u64))
    }
}

impl Div for Belt {
    type Output = Self;

    #[inline(always)]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inv()
    }
}

impl PartialEq<u64> for Belt {
    #[inline(always)]
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Belt> for u64 {
    #[inline(always)]
    fn eq(&self, other: &Belt) -> bool {
        *self == other.0
    }
}

impl AsRef<u64> for Belt {
    #[inline(always)]
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl TryFrom<&u64> for Belt {
    type Error = ();

    #[inline(always)]
    fn try_from(f: &u64) -> Result<Self, Self::Error> {
        based!(*f);
        Ok(Belt(*f))
    }
}

impl TryFrom<Noun> for Belt {
    type Error = ();

    #[inline(always)]
    fn try_from(n: Noun) -> std::result::Result<Self, Self::Error> {
        if !n.is_atom() {
            Err(())
        } else {
            Belt::try_from(&n.as_atom()?.as_u64()?)
        }
    }
}

impl From<u64> for Belt {
    #[inline(always)]
    fn from(f: u64) -> Self {
        Belt(f)
    }
}

impl From<Belt> for u64 {
    #[inline(always)]
    fn from(b: Belt) -> Self {
        b.0
    }
}

impl From<u32> for Belt {
    #[inline(always)]
    fn from(f: u32) -> Self {
        Belt(f as u64)
    }
}

impl From<Belt> for u32 {
    #[inline(always)]
    fn from(b: Belt) -> Self {
        b.0 as u32
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for Belt {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        Belt(u64::arbitrary(g) % PRIME)
    }
}
